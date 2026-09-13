#!/usr/bin/env python3
"""Exercise real HTTP accounts and publishing on Wasmd or the native server.

All state is isolated under target/. Test credentials never appear in the report.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wasmd', type=Path)
    parser.add_argument('--native', type=Path)
    parser.add_argument('--component', type=Path, default=ROOT/'artifacts/registry.wasm')
    args = parser.parse_args()
    if bool(args.wasmd) == bool(args.native):
        parser.error('Choose exactly one of --wasmd or --native')
    out = ROOT/'target'/('application-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3))
    out.mkdir(parents=True)
    data = out/'data'
    data.mkdir()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    env = dict(os.environ)
    # Do not inherit a real administrator credential into disposable tests.
    env.pop('WASMD_REGISTRY_ADMIN_TOKEN',None)
    env.update(WASMD_REGISTRY_PUBLIC_URL=base, WASMD_REGISTRY_LISTEN=f'127.0.0.1:{port}',
               WASMD_REGISTRY_DATABASE=str(data/'registry.db'), WASMD_REGISTRY_BLOB_DIR=str(data/'blobs'),
               WASMD_REGISTRY_TEMP_DIR=str(data/'tmp'))
    command = [str(args.native.resolve())] if args.native else [str(args.wasmd.resolve()),'serve',str(args.component.resolve()),
        '--listen',f'127.0.0.1:{port}','--data',str(data),'--workers','2','--queue-capacity','32',
        '--env',f'WASMD_REGISTRY_PUBLIC_URL={base}','--fuel','100000000000','--timeout-ms','180000','--max-body-bytes','33554432']
    report={'status':'running','profile':'native' if args.native else 'wasmd-wasi-http','command':command,'checks':[]}
    if args.wasmd:
        report['component_sha256']=hashlib.sha256(args.component.read_bytes()).hexdigest()
        report['runtime_sha256']=hashlib.sha256(args.wasmd.read_bytes()).hexdigest()
    flags=getattr(subprocess,'CREATE_NO_WINDOW',0)

    def request(method,path,value=None,cookie=None,csrf=None,token=None,origin=base,raw=None):
        headers={'Origin':origin}
        if cookie: headers['Cookie']=cookie
        if csrf: headers['X-CSRF-Token']=csrf
        if token: headers['Authorization']='Bearer '+token
        payload=raw if raw is not None else (json.dumps(value).encode() if value is not None else None)
        if payload is not None: headers['Content-Type']='application/wasm' if raw is not None else 'application/json'
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=190)
        try:
            conn.request(method,path,body=payload,headers=headers)
            res=conn.getresponse(); body=res.read(); result=(res.status,dict(res.getheaders()),body)
            return result
        finally: conn.close()
    def checked(name,method,path,expected,**kwargs):
        start=time.monotonic(); result=request(method,path,**kwargs)
        assert result[0]==expected,(name, 'expected', expected, 'received', result[0])
        report['checks'].append({'name':name,'status':result[0],'seconds':round(time.monotonic()-start,3)})
        print(name,'passed',flush=True)
        return result
    def json_body(result): return json.loads(result[2])
    def session(result):
        headers={k.lower():v for k,v in result[1].items()}
        cookie=headers['set-cookie']; assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
        return cookie.split(';')[0],json_body(result)['csrf_token']
    def start_server():
        log=(out/f'server-{time.time_ns()}.log').open('wb')
        process=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=log,creationflags=flags)
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if process.poll() is not None: raise RuntimeError(f'Server exited: {process.returncode}; see {out}')
            try:
                if request('GET','/healthz')[0]==200: return process,log
            except (OSError,http.client.HTTPException): time.sleep(.2)
        process.terminate();process.wait(timeout=10);log.close();raise TimeoutError('Server readiness')
    process=None;log=None
    try:
        process,log=start_server()
        for path,marker in [('/','home'),('/explore','explore'),('/register','register'),('/login','login'),('/account','account'),('/publish','publish'),('/docs','docs'),('/packages/demo/hello','package'),('/packages/demo/hello/1.0.0','release')]:
            result=checked('page '+path,'GET',path,200)
            assert f'data-page="{marker}"'.encode() in result[2]
            assert b'href="#/' not in result[2]
        password='test-only-'+secrets.token_urlsafe(24)
        checked('cross-origin registration','POST','/v1/auth/register',403,value={'email':'alice@example.com','password':password},origin='https://attacker.invalid')
        alice=checked('register alice','POST','/v1/auth/register',201,value={'email':'alice@example.com','password':password})
        cookie,csrf=session(alice)
        bob=checked('register bob','POST','/v1/auth/register',201,value={'email':'bob@example.com','password':password})
        other,other_csrf=session(bob)
        checked('duplicate email','POST','/v1/auth/register',409,value={'email':'alice@example.com','password':password})
        checked('CSRF rejection','POST','/v1/namespaces',403,value={'name':'demo'},cookie=cookie)
        checked('claim namespace','POST','/v1/namespaces',201,value={'name':'demo','description':'Test components'},cookie=cookie,csrf=csrf)
        checked('another owner cannot claim namespace','POST','/v1/namespaces',409,value={'name':'demo'},cookie=other,csrf=other_csrf)
        wasm=b'\x00asm\x01\x00\x00\x00'; digest='sha256:'+hashlib.sha256(wasm).hexdigest()
        checked('anonymous upload denied','PUT','/v1/blobs/'+digest,401,raw=wasm)
        checked('artifact upload','PUT','/v1/blobs/'+digest,201,raw=wasm,cookie=cookie,csrf=csrf)
        manifest={'schema':'wasmd.package/v0','namespace':'demo','name':'hello','version':'1.0.0','description':'Verified test module',
                  'artifacts':[{'name':'module','digest':digest,'size':len(wasm),'media_type':'application/wasm','kind':'core-module'}]}
        path='/v1/packages/demo/hello/versions'
        checked('cross-namespace publication denied','POST',path,403,value=manifest,cookie=other,csrf=other_csrf)
        checked('publish','POST',path,201,value=manifest,cookie=cookie,csrf=csrf)
        checked('immutable release','POST',path,409,value=manifest,cookie=cookie,csrf=csrf)
        downloaded=checked('download','GET','/v1/blobs/'+digest,200);assert downloaded[2]==wasm
        download_headers={k.lower():v for k,v in downloaded[1].items()}
        assert download_headers['content-disposition']=='attachment'
        assert download_headers['x-content-type-options']=='nosniff'
        assert 'sandbox' in download_headers['content-security-policy']
        checked('resolve','GET','/v1/packages/demo/hello/resolve?requirement=%5E1.0',200)
        if args.component.exists():
            component=args.component.read_bytes()
            component_digest='sha256:'+hashlib.sha256(component).hexdigest()
            checked('component upload','PUT','/v1/blobs/'+component_digest,201,raw=component,cookie=cookie,csrf=csrf)
            analysis=json_body(checked('component WIT inspection','GET','/v1/blobs/'+component_digest+'/component',200))
            assert 'wasi:http/incoming-handler@0.2.4' in analysis['wit']
            assert any('incoming-handler' in item['name'] for item in analysis['exports'])

        checked('yank','POST','/v1/packages/demo/hello/1.0.0/yank',200,value={},cookie=cookie,csrf=csrf)
        checked('yanked release excluded','GET','/v1/packages/demo/hello/resolve?requirement=%5E1.0',404)
        checked('exact yanked release retained','GET','/v1/packages/demo/hello/1.0.0',200)
        checked('unyank','DELETE','/v1/packages/demo/hello/1.0.0/yank',200,value={},cookie=cookie,csrf=csrf)
        token=json_body(checked('create personal token','POST','/v1/account/tokens',201,value={'name':'Smoke test'},cookie=cookie,csrf=csrf))
        checked('CLI token authentication','GET','/v1/auth/check',200,token=token['token'])
        if args.wasmd:
            cli_env=dict(env, WASMD_CONFIG=str(out/'cli-config'))
            cli_env.pop('WASMD_REGISTRY_TOKEN',None)
            cli_env.pop('WASMD_REGISTRY',None)
            def cli(name, arguments, stdin=None):
                result=subprocess.run([str(args.wasmd.resolve()),*arguments], input=stdin,
                    text=True, encoding='utf-8', capture_output=True, env=cli_env,
                    cwd=out, creationflags=flags, timeout=190)
                assert result.returncode==0,(name,'exit code',result.returncode)
                report['checks'].append({'name':name,'status':'passed'})
                print(name,'passed',flush=True)
            cli('Wasmd CLI login',['login',base,'--token-stdin'],token['token']+'\n')
            cli('Wasmd CLI namespace',['namespace','create','cli-demo'])
            module=out/'hello.wasm';module.write_bytes(wasm)
            cli('Wasmd CLI push',['push',str(module),'cli-demo/hello:1.0.0'])
            pulled=out/'downloaded.wasm'
            cli('Wasmd CLI pull',['pull','cli-demo/hello:1.0.0','-o',str(pulled)])
            assert pulled.read_bytes()==wasm

        checked('token namespace isolation','POST',path,403,value=manifest,token=json_body(checked('bob token','POST','/v1/account/tokens',201,value={'name':'Other owner'},cookie=other,csrf=other_csrf))['token'])
        def concurrent_namespace(index):
            for _ in range(30):
                result=request('POST','/v1/namespaces',value={'name':f'parallel-{index}'},cookie=cookie,csrf=csrf)
                if result[0]!=503: assert result[0]==201,result; return
                time.sleep(.1)
            raise RuntimeError('Concurrent mutation never completed')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(concurrent_namespace,range(4)))
        for i in range(4): checked(f'concurrent write persisted {i}','GET',f'/v1/namespaces/parallel-{i}',200)
        process.terminate();process.wait(timeout=10);log.close();process=None
        process,log=start_server()
        checked('session survives restart','GET','/v1/auth/me',200,cookie=cookie)
        checked('release survives restart','GET','/v1/packages/demo/hello/1.0.0',200)
        checked('revoke token','DELETE','/v1/account/tokens/'+token['id'],200,cookie=cookie,csrf=csrf)
        checked('revoked token rejected','GET','/v1/auth/check',401,token=token['token'])
        checked('logout','POST','/v1/auth/logout',200,value={},cookie=cookie,csrf=csrf)
        checked('logged-out session rejected','GET','/v1/auth/me',401,cookie=cookie)
        checked('wrong password','POST','/v1/auth/login',401,value={'email':'alice@example.com','password':'incorrect test password'})
        checked('login after restart','POST','/v1/auth/login',200,value={'email':'alice@example.com','password':password})
        account_file=data/('registry.accounts.json' if args.native else 'accounts.json')
        persisted=account_file.read_text(); assert password not in persisted and token['token'] not in persisted
        assert '$argon2id$v=19$m=19456,t=2,p=1$' in persisted
        report['status']='passed'
    except Exception as error:
        report.update(status='failed',error=str(error));raise
    finally:
        if process is not None and process.poll() is None: process.terminate();process.wait(timeout=10)
        if log: log.close()
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('Evidence:',out,flush=True)

if __name__=='__main__': main()
