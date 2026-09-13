import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('GitHub OAuth: browser binding, PKCE, replay protection and stable identities', async t => {
  const files = (await readdir('dist/worker')).filter(f => /\.(wasm|css|txt|svg|yaml)$/.test(f));
  let profile = { id: 12345, login: 'octocat' }, exchangeCount = 0, rejectExchange = false;
  const worker = {
    name: 'registry', modules: [{ type: 'ESModule', path: 'dist/worker/index.js' }, ...files.map(f => ({
      type: f.endsWith('.wasm') ? 'CompiledWasm' : 'Text', path: `dist/worker/${f}`,
    }))], compatibilityDate: '2026-07-01', d1Databases: ['DB'], r2Buckets: ['BLOBS'],
    bindings: { PUBLIC_READ: 'false', REGISTRATION_ENABLED: 'true', MAX_BLOB_BYTES: '8388608', MAX_ANALYSIS_BYTES: '8388608',
      GITHUB_CLIENT_ID: 'test-client', GITHUB_CLIENT_SECRET: 'test-secret' },
    outboundService: async request => {
      const url = new URL(request.url);
      if (url.origin === 'https://github.com' && url.pathname === '/login/oauth/access_token') {
        exchangeCount++;
        const values = new URLSearchParams(await request.text());
        assert.equal(values.get('client_secret'), 'test-secret');
        assert.equal(values.get('redirect_uri'), 'https://registry.test/v1/auth/github/callback');
        assert.match(values.get('code_verifier'), /^[a-f0-9]{64}$/);
        return Response.json(rejectExchange ? { error: 'bad_verification_code' } : { access_token: 'github-test-token', token_type: 'bearer' });
      }
      assert.equal(request.url, 'https://api.github.com/user');
      assert.equal(request.headers.get('authorization'), 'Bearer github-test-token');
      return Response.json(profile);
    },
  };
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [worker] }));
  t.after(() => mf.dispose());
  let db = await mf.getD1Database('DB');
  for (const file of (await readdir('worker/migrations')).filter(f => f.endsWith('.sql')).sort()) {
    const sql = await readFile(`worker/migrations/${file}`, 'utf8');
    await db.batch(sql.split(';').filter(s => s.trim()).map(s => db.prepare(s)));
  }
  const request = (path, cookie = '') => mf.dispatchFetch(`https://registry.test${path}`, { redirect: 'manual', headers: { Cookie: cookie } });
  const start = async () => {
    const response = await request('/v1/auth/github');
    assert.equal(response.status, 303);
    const target = new URL(response.headers.get('location'));
    assert.equal(target.origin, 'https://github.com');
    assert.equal(target.searchParams.get('scope'), 'read:user');
    assert.equal(target.searchParams.get('code_challenge_method'), 'S256');
    const cookie = response.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly; SameSite=Lax; Max-Age=600; Secure/);
    const state = target.searchParams.get('state');
    const stored = await db.prepare('SELECT verifier FROM oauth_states WHERE state_hash=?').bind(createHash('sha256').update(state).digest('hex')).first();
    assert.equal(createHash('sha256').update(stored.verifier).digest('base64url'), target.searchParams.get('code_challenge'));
    return { state, cookie: cookie.split(';')[0], path: `/v1/auth/github/callback?state=${state}&code=test-code` };
  };
  let username;
  await t.test('rejects missing/wrong browser cookies before exchanging a code', async () => {
    const flow = await start();
    for (const cookie of ['', `registry_oauth=${'0'.repeat(64)}`]) {
      const response = await request(flow.path, cookie);
      assert.equal(response.headers.get('location'), '/login?oauth_error=invalid_state');
    }
    assert.equal(exchangeCount, 0);
    const response = await request(flow.path, flow.cookie);
    assert.equal(response.headers.get('location'), '/account');
    const session = response.headers.getSetCookie().find(s => s.startsWith('registry_session='));
    assert.match(session, /HttpOnly; SameSite=Strict/);
    const me = await request('/v1/auth/me', session.split(';')[0]);
    assert.equal(me.status, 200);
    username = (await me.json()).user.username;
    assert.match(username, /^gh-octocat-/);
    assert.equal((await request(flow.path, flow.cookie)).headers.get('location'), '/login?oauth_error=invalid_state');
    assert.equal(exchangeCount, 1);
  });
  await t.test('keeps the same account when GitHub login changes', async () => {
    profile = { ...profile, login: 'renamed' };
    const flow = await start();
    assert.equal((await request(flow.path, flow.cookie)).headers.get('location'), '/account');
    const users = await db.prepare('SELECT username FROM users').all();
    assert.deepEqual(users.results, [{ username }]);
    assert.equal((await db.prepare('SELECT subject FROM oauth_identities').first()).subject, '12345');
  });
  await t.test('rejects cancelled, expired and failed exchanges without creating sessions', async () => {
    const count = (await db.prepare('SELECT COUNT(*) AS count FROM credentials').first()).count;
    const cancelled = await start();
    assert.equal((await request(`${cancelled.path}&error=access_denied`, cancelled.cookie)).headers.get('location'), '/login?oauth_error=denied');
    const expired = await start();
    await db.prepare('UPDATE oauth_states SET expires_at=0').run();
    assert.equal((await request(expired.path, expired.cookie)).headers.get('location'), '/login?oauth_error=invalid_state');
    rejectExchange = true;
    const failed = await start();
    assert.equal((await request(failed.path, failed.cookie)).headers.get('location'), '/login?oauth_error=github_unavailable');
    rejectExchange = false;
    assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM credentials').first()).count, count);
  });
  await t.test('does not merge an existing local username into a GitHub identity', async () => {
    await db.prepare('INSERT INTO users(username,password,created_at,email) VALUES (?,?,?,?)').bind('someone', 'local-hash', 0, 'someone@example.com').run();
    profile = { id: 54321, login: 'someone', email: 'someone@example.com' };
    const flow = await start();
    assert.equal((await request(flow.path, flow.cookie)).headers.get('location'), '/account');
    const identity = await db.prepare("SELECT username FROM oauth_identities WHERE subject='54321'").first();
    assert.notEqual(identity.username, 'someone');
  });
  await t.test('closed registration still permits existing GitHub accounts', async () => {
    worker.bindings.REGISTRATION_ENABLED = 'false';
    await mf.setOptions(convertV4MiniflareOptions({ workers: [worker] }));
    db = await mf.getD1Database('DB');
    const existing = await start();
    assert.equal((await request(existing.path, existing.cookie)).headers.get('location'), '/account');
    profile = { id: 67890, login: 'new-user' };
    const fresh = await start();
    assert.equal((await request(fresh.path, fresh.cookie)).headers.get('location'), '/login?oauth_error=registration_disabled');
    assert.equal(await db.prepare("SELECT subject FROM oauth_identities WHERE subject='67890'").first(), null);
  });
});
