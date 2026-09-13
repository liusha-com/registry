import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const origin = 'https://registry.test';
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');

test('Workers runtime: accounts, immutable publications, D1 transactions and private R2', async t => {
  const files = (await readdir('dist/worker')).filter(f => /\.(wasm|css|txt|svg|yaml)$/.test(f));
  const mf = new Miniflare(convertV4MiniflareOptions({
    workers: [{ name: 'registry',
    modules: [{ type: 'ESModule', path: 'dist/worker/index.js' }, ...files.map(f => ({
      type: f.endsWith('.wasm') ? 'CompiledWasm' : 'Text', path: `dist/worker/${f}`,
    }))], compatibilityDate: '2026-07-01',
    d1Databases: ['DB'], r2Buckets: ['BLOBS'],
    bindings: { PUBLIC_READ: 'true', REGISTRATION_ENABLED: 'true', MAX_BLOB_BYTES: '8388608', MAX_ANALYSIS_BYTES: '8388608' },
    }],
  }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database('DB');
  for (const file of (await readdir('worker/migrations')).filter(f => f.endsWith('.sql')).sort()) {
    const sql = await readFile(`worker/migrations/${file}`, 'utf8');
    await db.batch(sql.split(';').filter(s => s.trim()).map(s => db.prepare(s)));
  }
  async function request(path, { method = 'GET', data, bytes, cookie, csrf, token, headers = {} } = {}) {
    const res = await mf.dispatchFetch(origin + path, {
      method, duplex: 'half', headers: { ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(data ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: data ? JSON.stringify(data) : bytes,
    });
    return res;
  }
  const expect = async (res, status) => {
    const text = await res.text();
    assert.equal(res.status, status, text);
    return text ? JSON.parse(text) : null;
  };
  let alice, bob, token, tokenId;
  const wasm = new Uint8Array([0,97,115,109,1,0,0,0]);
  const key = digest(wasm);
  const manifest = { schema: 'wasmd.package/v0', namespace: 'demo', name: 'hello', version: '1.0.0', description: 'Hello worker',
    artifacts: [{ name: 'module', digest: key, size: wasm.length, kind: 'core-module', media_type: 'application/wasm' }], dependencies: {}, annotations: {} };
  await t.test('renders every shared page, assets, health and readiness', async () => {
    for (const path of ['/', '/explore', '/login', '/register', '/account', '/publish', '/docs', '/packages/demo/hello', '/packages/demo/hello/1.0.0']) {
      const r = await request(path); assert.equal(r.status, 200); assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
      assert.doesNotMatch(await r.text(), /\{\{(?:title|body|page)\}\}/);
    }
    for (const path of ['/assets/app.css', '/assets/app.js', '/favicon.svg', '/openapi.yaml', '/healthz', '/readyz', '/v1/info'])
      assert.equal((await request(path)).status, 200, path);
    await expect(await request('/missing'), 404);
    await expect(await request('/v1/search?limit=0'), 400);
    await expect(await request('/v1/blobs/%ZZ'), 400);
  });
  await t.test('registers Argon2id accounts with secure sessions and CSRF', async () => {
    for (const username of ['alice', 'bobby']) {
      const r = await request('/v1/auth/register', { method: 'POST', data: { email: `${username}@example.com`, password: 'correct-horse-1234' } });
      const cookie = r.headers.get('set-cookie');
      assert.match(cookie, /HttpOnly; SameSite=Strict/); assert.match(cookie, /Secure/);
      const data = await expect(r, 201);
      const credentials = { username: data.user.username, cookie: cookie.split(';')[0], csrf: data.csrf_token };
      if (username === 'alice') alice = credentials; else bob = credentials;
    }
    const stored = await db.prepare('SELECT password FROM users WHERE username=?').bind(alice.username).first();
    assert.match(stored.password, /^\$argon2id\$/);
    await expect(await request('/v1/namespaces', { method: 'POST', cookie: alice.cookie, data: { name: 'demo' } }), 403);
    await expect(await request('/v1/namespaces', { method: 'POST', ...alice, headers: { Origin: 'https://evil.test' }, data: { name: 'demo' } }), 403);
    await expect(await request('/v1/auth/me', { token: alice.cookie.split('=')[1] }), 401);
    await expect(await request('/v1/auth/register', { method: 'POST', data: { email: 'alice@example.com', password: 'correct-horse-1234' } }), 409);
  });
  await t.test('claims namespaces and issues bearer-only, hashed personal tokens', async () => {
    const ns = await expect(await request('/v1/namespaces', { method: 'POST', ...alice, data: { name: 'demo' } }), 201);
    assert.equal(ns.owner_username, alice.username);
    await expect(await request('/v1/namespaces', { method: 'POST', ...bob, data: { name: 'demo' } }), 409);
    const data = await expect(await request('/v1/account/tokens', { method: 'POST', ...alice, data: { name: 'CLI' } }), 201);
    token = data.token; tokenId = data.id;
    assert.equal(data.expires_in, 90 * 86400);
    assert.ok(data.expires_at > Math.floor(Date.now() / 1000));
    assert.equal((await expect(await request('/v1/auth/check', { token }), 200)).authenticated, true);
    await expect(await request('/v1/auth/me', { cookie: `registry_session=${token}` }), 401);
    await expect(await request('/v1/account/tokens', { method: 'POST', token, data: { name: 'Nested' } }), 403);
    const rows = await db.prepare('SELECT hash FROM credentials WHERE id=?').bind(tokenId).first();
    assert.equal(rows.hash, createHash('sha256').update(token).digest('hex'));
  });
  await t.test('validates custom token lifetimes and rejects expired credentials', async () => {
    for (const expires_in of [0, -1, 1.5, '86400', true, {}, [], 315360001]) {
      const result = await expect(await request('/v1/account/tokens', { method: 'POST', ...alice, data: { name: 'Invalid', expires_in } }), 400);
      assert.equal(result.error.code, 'invalid_token_expiry');
    }
    for (const expires_in of [1, 17 * 86400, 315360000]) {
      const data = await expect(await request('/v1/account/tokens', { method: 'POST', ...alice, data: { name: 'Custom', expires_in } }), 201);
      const stored = await db.prepare('SELECT created_at,expires_at FROM credentials WHERE id=?').bind(data.id).first();
      assert.equal(data.expires_in, expires_in);
      assert.equal(data.expires_at, stored.expires_at);
      assert.equal(stored.expires_at - stored.created_at, expires_in);
      await db.prepare('UPDATE credentials SET expires_at=1 WHERE id=?').bind(data.id).run();
      await expect(await request('/v1/auth/check', { token: data.token }), 401);
      const listed = await expect(await request('/v1/account/tokens', alice), 200);
      assert.ok(!listed.tokens.some(t => t.id === data.id));
    }
  });
  await t.test('non-expiring tokens survive scheduled cleanup and remain revocable and owner-scoped', async () => {
    const data = await expect(await request('/v1/account/tokens', { method: 'POST', ...alice, data: { name: 'GitHub Actions', expires_in: null } }), 201);
    assert.equal(data.expires_in, null);
    assert.equal(data.expires_at, null);
    const worker = await mf.getWorker();
    assert.equal((await worker.scheduled({ cron: '17 * * * *' })).outcome, 'ok');
    await expect(await request('/v1/auth/check', { token: data.token }), 200);
    const listed = await expect(await request('/v1/account/tokens', alice), 200);
    assert.equal(listed.tokens.find(t => t.id === data.id).expires_at, null);
    assert.ok(listed.tokens.every(t => !('token' in t) && !('hash' in t)));
    const stored = await db.prepare('SELECT hash,expires_at FROM credentials WHERE id=?').bind(data.id).first();
    assert.equal(stored.hash, createHash('sha256').update(data.token).digest('hex'));
    assert.equal(stored.expires_at, 0);
    assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM credentials WHERE expires_at=1').first()).count, 0);
    await expect(await request('/v1/auth/me', { cookie: `registry_session=${data.token}` }), 401);
    await expect(await request('/v1/account/tokens', { method: 'POST', token: data.token, data: { name: 'Nested', expires_in: null } }), 403);
    await expect(await request(`/v1/account/tokens/${data.id}`, { method: 'DELETE', ...bob }), 404);
    await expect(await request(`/v1/account/tokens/${data.id}`, { method: 'DELETE', ...alice }), 200);
    await expect(await request('/v1/auth/check', { token: data.token }), 401);
    const session = await db.prepare('SELECT created_at,expires_at FROM credentials WHERE username=? AND session=1').bind(alice.username).first();
    assert.equal(session.expires_at - session.created_at, 86400);
  });
  await t.test('non-expiring tokens count toward the concurrent active credential limit', async () => {
    // Alice has one browser session and one default-duration CLI token.
    const results = await Promise.all(Array.from({ length: 30 }, (_, i) => request('/v1/account/tokens', {
      method: 'POST', ...alice, data: { name: `Automation ${i}`, expires_in: null },
    })));
    assert.equal(results.filter(r => r.status === 201).length, 28);
    assert.equal(results.filter(r => r.status === 429).length, 2);
    for (const response of results) {
      const data = await expect(response, response.status === 201 ? 201 : 429);
      if (data.id) await expect(await request(`/v1/account/tokens/${data.id}`, { method: 'DELETE', ...alice }), 200);
      else assert.equal(data.error.code, 'credential_limit');
    }
  });
  await t.test('only email credentials are accepted and addresses are normalized', async () => {
    const password = 'correct-horse-1234';
    const registered = await expect(await request('/v1/auth/register', { method: 'POST', data: { email: ' Test@Example.com ', password } }), 201);
    assert.match(registered.user.username, /^u-[a-f0-9]{24}$/);
    const result = await expect(await request('/v1/auth/login', { method: 'POST', data: { email: 'TEST@example.com', password } }), 200);
    assert.equal(result.user.username, registered.user.username);
    for (const path of ['/v1/auth/register','/v1/auth/login']) {
      for (const data of [{ username: registered.user.username, password }, { username: 'test@example.com', password }, { email: 'test@example.com', username: 'test', password }, { password }]) {
        await expect(await request(path, { method: 'POST', data }), 400);
      }
    }
    await expect(await request('/v1/auth/login', { method: 'POST', data: { email: 'test@example.com', password: 'incorrect-horse' } }), 401);
    await expect(await request('/v1/auth/register', { method: 'POST', data: { email: 'TEST@example.com', password } }), 409);
    await expect(await request('/v1/auth/register', { method: 'POST', data: { email: 'bad-email', password } }), 400);
    const providers = await expect(await request('/v1/auth/providers'), 200);
    assert.equal(providers.email_password, true); assert.equal(providers.github, false);
  });
  await t.test('validates streamed bodies, hashes, ownership and manifest integrity', async () => {
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', bytes: wasm }), 401);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes: new Uint8Array([1,2]) }), 400);
    const stream = new ReadableStream({ start(controller) {
      controller.enqueue(new Uint8Array(8 * 1024 * 1024)); controller.enqueue(new Uint8Array(1)); controller.close();
    } });
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes: stream }), 413);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes: wasm }), 201);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes: wasm }), 200);
    await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', ...bob, data: manifest }), 403);
    await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: { ...manifest, repository: 'javascript:alert(1)' } }), 400);
    await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: { ...manifest, artifacts: [{ ...manifest.artifacts[0], size: 99 }] } }), 409);
    await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: { ...manifest, dependencies: { 'demo/hello': 'nonsense' } } }), 400);
  });
  await t.test('concurrent duplicate publication has one winner and no partial updates', async () => {
    const responses = await Promise.all([1,2].map(() => request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: manifest })));
    assert.deepEqual(responses.map(r => r.status).sort(), [201,409]);
    const published = await expect(responses.find(r => r.status === 201), 201);
    assert.equal(published.record.manifest_digest, digest(JSON.stringify(published.manifest)));
    await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: { ...manifest, description: 'overwrite' } }), 409);
    const p = await expect(await request('/v1/packages/demo/hello'), 200);
    assert.equal(p.description, 'Hello worker'); assert.equal(p.versions.length, 1);
  });
  await t.test('downloads immutable bytes safely, including HEAD and conditional GET', async () => {
    const r = await request(`/v1/blobs/${key}`);
    assert.equal(r.headers.get('content-disposition'), 'attachment');
    assert.match(r.headers.get('content-security-policy'), /sandbox/);
    assert.deepEqual(new Uint8Array(await r.arrayBuffer()), wasm);
    const head = await request(`/v1/blobs/${key}`, { method: 'HEAD' });
    assert.equal(head.headers.get('content-length'), '8'); assert.equal(await head.text(), '');
    assert.equal((await request(`/v1/blobs/${key}`, { headers: { 'If-None-Match': `"${key}"` } })).status, 304);
  });
  await t.test('uses Rust SemVer ordering, excludes yanked and prerelease versions from wildcard resolution', async () => {
    for (const version of ['1.10.0', '1.2.0', '2.0.0-beta.1']) await expect(await request('/v1/packages/demo/hello/versions', { method: 'POST', token, data: { ...manifest, version } }), 201);
    assert.equal((await expect(await request('/v1/packages/demo/hello/resolve?requirement=%5E1'), 200)).record.version, '1.10.0');
    await expect(await request('/v1/packages/demo/hello/1.10.0/yank', { method: 'POST', ...bob, data: {} }), 403);
    await expect(await request('/v1/packages/demo/hello/1.10.0/yank', { method: 'POST', token, data: {} }), 200);
    assert.equal((await expect(await request('/v1/packages/demo/hello/resolve'), 200)).record.version, '1.2.0');
    assert.equal((await expect(await request('/v1/packages/demo/hello/1.10.0'), 200)).record.yanked, true);
    await expect(await request('/v1/packages/demo/hello/1.10.0/yank', { method: 'DELETE', token }), 200);
    assert.equal((await expect(await request('/v1/search?q=demo%2Fhello'), 200)).items.length, 1);
    assert.equal((await expect(await request('/v1/stats'), 200)).versions, 4);
  });
  await t.test('decodes Component Model WIT using the shared Rust analyzer', async () => {
    const component = new Uint8Array([0,97,115,109,13,0,1,0]);
    const key = digest(component);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes: component }), 201);
    const result = await expect(await request(`/v1/blobs/${key}/component`, { token }), 200);
    assert.equal(result.kind, 'component'); assert.equal(typeof result.wit, 'string');
    await expect(await request(`/v1/blobs/${digest(wasm)}/component`), 404);
  });
  await t.test('analyzes components above 1 MiB and backfills metadata for existing releases', async () => {
    // A valid large component: empty world plus a padded custom section.
    const leb = value => {
      const result = [];
      do { const byte = value & 127; value >>>= 7; result.push(byte | (value ? 128 : 0)); } while (value);
      return result;
    };
    const padding = 2 * 1024 * 1024;
    const bytes = Buffer.concat([Buffer.from([0,97,115,109,13,0,1,0,0, ...leb(padding + 2), 1, 120]), Buffer.alloc(padding)]);
    const key = digest(bytes);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes }), 201);
    assert.ok(await db.prepare('SELECT digest FROM component_analyses WHERE digest=?').bind(key).first());
    const original = await expect(await request(`/v1/blobs/${key}/component`, { token }), 200);
    // Simulate a release uploaded by the old deployment without metadata.
    await db.prepare('DELETE FROM component_analyses WHERE digest=?').bind(key).run();
    assert.deepEqual(await expect(await request(`/v1/blobs/${key}/component`, { token }), 200), original);
    assert.ok(await db.prepare('SELECT digest FROM component_analyses WHERE digest=?').bind(key).first());
    // Subsequent reads use persisted analysis, without needing to read R2 again.
    await (await mf.getR2Bucket('BLOBS')).delete(key);
    assert.deepEqual(await expect(await request(`/v1/blobs/${key}/component`, { token }), 200), original);
    await db.prepare('DELETE FROM component_analyses WHERE digest=?').bind(key).run();
    await expect(await request(`/v1/blobs/${key}/component`, { token }), 503);
    await expect(await request(`/v1/blobs/${digest(Buffer.from('missing'))}/component`), 404);
  });
  await t.test('inspects the locally built Registry WASI HTTP component', { skip: !process.env.REGISTRY_TEST_COMPONENT }, async () => {
    const bytes = await readFile(process.env.REGISTRY_TEST_COMPONENT);
    const key = digest(bytes);
    await expect(await request(`/v1/blobs/${key}`, { method: 'PUT', token, bytes }), 201);
    const result = await expect(await request(`/v1/blobs/${key}/component`, { token }), 200);
    assert.equal(result.kind, 'component');
    assert.ok(result.imports.length > 0);
    assert.match(result.wit, /export wasi:http\/incoming-handler@0\.2\.4/);
    await db.prepare('DELETE FROM component_analyses WHERE digest=?').bind(key).run();
    assert.deepEqual(await expect(await request(`/v1/blobs/${key}/component`, { token }), 200), result);
  });
  await t.test('account workspace shows owned namespaces, empty namespaces and their exact packages', async () => {
    await expect(await request('/v1/account/namespaces'), 401);
    assert.deepEqual((await expect(await request('/v1/account/namespaces', bob), 200)).namespaces, []);
    await expect(await request('/v1/namespaces', { method: 'POST', ...alice, data: { name: 'empty', description: 'Not published yet' } }), 201);
    await expect(await request('/v1/namespaces', { method: 'POST', ...bob, data: { name: 'demo-other' } }), 201);
    const response = await request('/v1/account/namespaces', alice);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const data = await expect(response, 200);
    assert.deepEqual(data.namespaces.map(n => n.name), ['demo', 'empty']);
    assert.equal(data.next_cursor, null);
    assert.equal(data.namespaces[0].package_count, 1);
    assert.deepEqual(data.namespaces[0].packages.map(p => [p.namespace, p.name]), [['demo', 'hello']]);
    assert.equal(data.namespaces[1].package_count, 0);
    assert.deepEqual(data.namespaces[1].packages, []);
    assert.equal(data.namespaces[1].next_package_cursor, null);
    assert.deepEqual(await expect(await request('/v1/account/namespaces', { token }), 200), data);
    await expect(await request('/v1/account/namespaces/demo/packages', bob), 404);
    await expect(await request('/v1/account/namespaces/demo-other/packages', alice), 404);
    await expect(await request('/v1/account/namespaces/missing/packages', alice), 404);
    await expect(await request('/v1/account/namespaces/demo/packages'), 401);
    await expect(await request('/v1/account/namespaces?after=%27', alice), 400);
    const head = await request('/v1/account/namespaces', { ...alice, method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
  });
  await t.test('account workspace paginates namespaces and packages without truncation or duplicates', async () => {
    const names = Array.from({ length: 21 }, (_, i) => `paged-${String(i).padStart(2, '0')}`);
    await db.batch(names.map(n => db.prepare('INSERT INTO namespaces(name,description,owner_username,created_at) VALUES (?,?,?,?)')
      .bind(n, 'Pagination fixture', alice.username, new Date().toISOString())));
    await db.batch(names.map(n => db.prepare('INSERT INTO packages(namespace,name,description,created_at,updated_at) VALUES (?,?,?,?,?)')
      .bind(names[0], n, 'Package fixture', new Date().toISOString(), new Date().toISOString())));
    const first = await expect(await request('/v1/account/namespaces', alice), 200);
    assert.equal(first.namespaces.length, 20);
    const second = await expect(await request(`/v1/account/namespaces?after=${first.next_cursor}`, alice), 200);
    assert.deepEqual([...first.namespaces, ...second.namespaces].map(n => n.name), ['demo', 'empty', ...names]);
    assert.equal(second.next_cursor, null);
    const preview = first.namespaces.find(n => n.name === names[0]);
    assert.equal(preview.package_count, 21);
    assert.equal(preview.packages.length, 20);
    const tail = await expect(await request(`/v1/account/namespaces/${names[0]}/packages?after=${preview.next_package_cursor}`, alice), 200);
    assert.deepEqual([...preview.packages, ...tail.packages].map(p => p.name), names);
    assert.equal(tail.next_cursor, null);
    await expect(await request(`/v1/account/namespaces/${names[0]}/packages?after=invalid!`, alice), 400);
    await expect(await request(`/v1/account/namespaces/${names[0]}/packages?after=${preview.next_package_cursor}`, bob), 404);
  });
  await t.test('private namespaces protect metadata, search, statistics, analysis and blob bytes', async () => {
    const baseline = await expect(await request('/v1/stats'), 200);
    await expect(await request('/v1/namespaces/demo', { cookie: 'registry_session=expired-session' }), 200);
    await expect(await request('/v1/namespaces', { method: 'POST', ...alice, data: { name: 'invalid-visibility', visibility: 'secret' } }), 400);
    const ns = await expect(await request('/v1/namespaces', { method: 'POST', ...alice, data: { name: 'private-team', visibility: 'private' } }), 201);
    assert.equal(ns.visibility, 'private');
    const bytes = new Uint8Array([0,97,115,109,13,0,1,0,0,2,1,112]);
    const privateKey = digest(bytes);
    await expect(await request(`/v1/blobs/${privateKey}`, { method: 'PUT', token, bytes }), 201);
    await expect(await request(`/v1/blobs/${privateKey}`), 404);
    await expect(await request(`/v1/blobs/${privateKey}`, bob), 404);
    assert.equal((await request(`/v1/blobs/${privateKey}`, { token })).status, 200);
    const secretManifest = { ...manifest, namespace: 'private-team', name: 'secret-package', description: 'private-only-marker',
      artifacts: [{ ...manifest.artifacts[0], digest: privateKey, size: bytes.length, kind: 'component' }] };
    await expect(await request('/v1/packages/private-team/secret-package/versions', { method: 'POST', token, data: secretManifest }), 201);
    const deniedPaths = ['/v1/namespaces/private-team', '/v1/packages/private-team/secret-package',
      '/v1/packages/private-team/secret-package/1.0.0', '/v1/packages/private-team/secret-package/resolve',
      `/v1/blobs/${privateKey}`, `/v1/blobs/${privateKey}/component`];
    for (const path of deniedPaths) {
      for (const credentials of [{}, bob]) {
        await expect(await request(path, credentials), 404);
        const head = await request(path, { ...credentials, method: 'HEAD', headers: { 'If-None-Match': `"${privateKey}"` } });
        assert.equal(head.status, 404, path);
      }
      assert.equal((await request(path, alice)).status, 200, path);
      assert.equal((await request(path, { token })).status, 200, path);
    }
    const download = await request(`/v1/blobs/${privateKey}`, alice);
    assert.equal(download.headers.get('cache-control'), 'private, no-store');
    assert.deepEqual(new Uint8Array(await download.arrayBuffer()), bytes);
    for (const credentials of [{}, bob])
      assert.deepEqual((await expect(await request('/v1/search?q=private-only-marker', credentials), 200)).items, []);
    assert.equal((await expect(await request('/v1/search?q=private-only-marker', alice), 200)).items.length, 1);
    assert.deepEqual(await expect(await request('/v1/stats'), 200), baseline);
    await expect(await request('/v1/packages/demo-other/stolen/versions', { method: 'POST', ...bob,
      data: { ...secretManifest, namespace: 'demo-other', name: 'stolen' } }), 404);
    // Cache hits and conditional requests must still enforce access.
    await expect(await request(`/v1/blobs/${privateKey}/component`, { token }), 200);
    await expect(await request(`/v1/blobs/${privateKey}/component`, bob), 404);
    await expect(await request('/v1/packages/private-team/secret-package/1.0.0/yank', { method: 'POST', ...bob, data: {} }), 403);
    await expect(await request('/v1/packages/private-team/secret-package/1.0.0/yank', { method: 'POST', token, data: {} }), 200);
    await expect(await request(`/v1/blobs/${privateKey}`, bob), 404);
    // Identical bytes intentionally published publicly are public by digest,
    // while the private namespace's metadata remains inaccessible.
    await expect(await request('/v1/packages/demo/shared-component/versions', { method: 'POST', token,
      data: { ...secretManifest, namespace: 'demo', name: 'shared-component', description: 'Public copy' } }), 201);
    assert.equal((await request(`/v1/blobs/${privateKey}`)).status, 200);
    await expect(await request('/v1/packages/private-team/secret-package'), 404);
    await expect(await request('/v1/packages/private-team/secret-package', { cookie: 'registry_session=expired-session' }), 404);
  });
  await t.test('package overviews are mutable, owned, revision checked and atomic with publication', async () => {
    const endpoint = '/v1/packages/demo/documented';
    const post = data => request(endpoint + '/versions', { method: 'POST', token, data: { ...manifest, name: 'documented', ...data } });
    await expect(await post({ overview: '# README\n\nHello **Wasm**.' }), 201);
    const original = await expect(await request(endpoint + '/1.0.0'), 200);
    let p = await expect(await request(endpoint), 200);
    assert.equal(p.overview_revision, 1); assert.equal(p.overview, original.manifest.overview);
    assert.equal(p.latest_release.manifest.version, '1.0.0'); assert.equal(p.visibility, 'public');
    const edit = { overview: '# Edited', revision: 1 };
    await expect(await request(endpoint + '/overview', { method: 'PUT', data: edit }), 401);
    await expect(await request(endpoint + '/overview', { method: 'PUT', ...bob, data: edit }), 403);
    await expect(await request(endpoint + '/overview', { method: 'PUT', cookie: alice.cookie, data: edit }), 403);
    const outcomes = await Promise.all([1,2].map(() => request(endpoint + '/overview', { method: 'PUT', ...alice, data: edit })));
    assert.deepEqual(outcomes.map(r => r.status).sort(), [200,409]);
    await expect(await post({ version: '1.0.1' }), 201);
    p = await expect(await request(endpoint), 200);
    assert.equal(p.overview, '# Edited'); assert.equal(p.overview_revision, 2);
    await expect(await post({ version: '1.0.1', overview: 'Duplicate must roll back' }), 409);
    await expect(await post({ version: '1.0.2', overview: '# CLI README' }), 201);
    p = await expect(await request(endpoint), 200);
    assert.equal(p.overview, '# CLI README'); assert.equal(p.overview_revision, 3);
    assert.deepEqual(await expect(await request(endpoint + '/1.0.0'), 200), original);
    for (const overview of [null, 42, {}, '界'.repeat(21846)]) {
      await expect(await post({ version: '1.0.3', overview }), 400);
      await expect(await request(endpoint + '/overview', { method: 'PUT', token, data: { overview, revision: 3 } }), 400);
    }
    await expect(await request(endpoint + '/overview', { method: 'PUT', token, data: { overview: '' } }), 400);
    await expect(await request('/v1/packages/demo/missing/overview', { method: 'PUT', token, data: { overview: '', revision: 0 } }), 404);
    await expect(await request(endpoint + '/overview', { method: 'PUT', token, data: { overview: '', revision: 3 } }), 200);
    p = await expect(await request(endpoint), 200);
    assert.equal(p.overview, ''); assert.equal(p.overview_revision, 4); assert.equal(p.versions.length, 3);
    const privateEndpoint = '/v1/packages/private-team/secret-package';
    p = await expect(await request(privateEndpoint, alice), 200);
    await expect(await request(privateEndpoint + '/overview', { method: 'PUT', token, data: { overview: 'Secret README', revision: p.overview_revision } }), 200);
    await expect(await request(privateEndpoint + '/overview', { method: 'PUT', ...bob, data: { overview: 'Stolen', revision: p.overview_revision } }), 403);
    for (const auth of [{}, bob]) await expect(await request(privateEndpoint, auth), 404);
    assert.equal((await expect(await request(privateEndpoint, alice), 200)).overview, 'Secret README');
  });
  await t.test('revokes tokens, expires sessions and persists login throttling', async () => {
    await expect(await request(`/v1/account/tokens/${tokenId}`, { method: 'DELETE', ...bob }), 404);
    await expect(await request(`/v1/account/tokens/${tokenId}`, { method: 'DELETE', ...alice }), 200);
    await expect(await request('/v1/auth/check', { token }), 401);
    await expect(await request('/v1/auth/logout', { method: 'POST', ...alice, data: {} }), 200);
    await expect(await request('/v1/auth/me', alice), 401);
    await expect(await request('/v1/auth/login', { method: 'POST', data: { email: 'alice@example.com', password: 'correct-horse-1234' } }), 200);
    for (let i = 0; i < 8; i++) await expect(await request('/v1/auth/login', { method: 'POST', data: { email: 'missing@example.com', password: 'incorrect-horse' } }), 401);
    await expect(await request('/v1/auth/login', { method: 'POST', data: { email: 'missing@example.com', password: 'incorrect-horse' } }), 429);
    await db.prepare('UPDATE credentials SET expires_at=0 WHERE username=?').bind(bob.username).run();
    await expect(await request('/v1/auth/me', bob), 401);
  });
  await t.test('private mode protects reads, closes registration, and disables public artifact caching', async () => {
    // Reconfigure the same runtime while retaining its local database and bucket.
    const options = convertV4MiniflareOptions({ workers: [{ name: 'registry',
      modules: [{ type: 'ESModule', path: 'dist/worker/index.js' }, ...files.map(f => ({
        type: f.endsWith('.wasm') ? 'CompiledWasm' : 'Text', path: `dist/worker/${f}`,
      }))], compatibilityDate: '2026-07-01', d1Databases: ['DB'], r2Buckets: ['BLOBS'],
      bindings: { PUBLIC_READ: 'false', REGISTRATION_ENABLED: 'false', MAX_BLOB_BYTES: '8388608', MAX_ANALYSIS_BYTES: '1048576' },
    }] });
    await mf.setOptions(options);
    for (const path of ['/v1/info', '/v1/stats', '/v1/search', '/v1/namespaces/demo', '/v1/packages/demo/hello', `/v1/blobs/${key}`]) {
      await expect(await request(path), 401);
      assert.equal((await request(path, { method: 'HEAD' })).status, 401);
    }
    await expect(await request('/v1/auth/register', { method: 'POST', data: { email: 'charlie@example.com', password: 'correct-horse-1234' } }), 403);
    const login = await request('/v1/auth/login', { method: 'POST', data: { email: 'alice@example.com', password: 'correct-horse-1234' } });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    await expect(await request('/v1/account/namespaces'), 401);
    assert.ok((await expect(await request('/v1/account/namespaces', { cookie }), 200)).namespaces.some(n => n.name === 'demo'));
    const r = await request(`/v1/blobs/${key}`, { cookie });
    assert.equal(r.status, 200); assert.equal(r.headers.get('cache-control'), 'private, no-store');
    assert.deepEqual(new Uint8Array(await r.arrayBuffer()), wasm);
  });
});
