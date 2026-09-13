import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('visibility migration preserves existing releases and backfills their artifact access', async t => {
  const mf = new Miniflare(convertV4MiniflareOptions({ workers: [{ name: 'migration', modules: true,
    script: 'export default { fetch() { return new Response("ok"); } }', d1Databases: ['DB'] }] }));
  t.after(() => mf.dispose());
  const db = await mf.getD1Database('DB');
  const migrate = async file => {
    const sql = await readFile(`worker/migrations/${file}`, 'utf8');
    await db.batch(sql.split(';').filter(s => s.trim()).map(s => db.prepare(s)));
  };
  await migrate('0001_registry.sql');
  await migrate('0002_email_github.sql');
  const digest = 'sha256:' + 'a'.repeat(64);
  const manifest = JSON.stringify({ artifacts: [{ digest }, { digest }] });
  await db.batch([
    db.prepare("INSERT INTO users(username,password,created_at) VALUES ('owner','hash',1)"),
    db.prepare("INSERT INTO namespaces(name,description,owner_username,created_at) VALUES ('legacy','Original namespace','owner','2026-01-01')"),
    db.prepare("INSERT INTO blobs(digest,size,media_type,created_at) VALUES (?,8,'application/wasm','2026-01-01')").bind(digest),
    db.prepare("INSERT INTO packages(namespace,name,description,created_at,updated_at) VALUES ('legacy','hello','Original package','2026-01-01','2026-01-01')"),
    db.prepare("INSERT INTO versions(namespace,package,version,manifest_json,manifest_digest,created_at,updated_at,publisher_username) VALUES ('legacy','hello','1.0.0',?,'original','2026-01-01','2026-01-01','owner')").bind(manifest),
  ]);
  await migrate('0003_namespace_visibility.sql');
  assert.deepEqual(await db.prepare("SELECT visibility,owner_username FROM namespaces WHERE name='legacy'").first(),
    { visibility: 'public', owner_username: 'owner' });
  assert.equal((await db.prepare('SELECT manifest_json FROM versions').first()).manifest_json, manifest);
  assert.deepEqual((await db.prepare('SELECT * FROM release_artifacts').all()).results,
    [{ namespace: 'legacy', package: 'hello', version: '1.0.0', digest }]);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM blob_uploads').first()).count, 0);
});
