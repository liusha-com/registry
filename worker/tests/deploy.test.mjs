import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { deployRegistry } from '../../tools/deploy-worker.mjs';
import { deployDashboard, dashboardConfig } from '../../tools/deploy-dashboard.mjs';

const uuid = '12345678-1234-4321-8765-123456789abc';
function fixture(t, database = {}, bucket = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'registry-deploy-'));
  const path = join(dir, 'wrangler.jsonc');
  const config = { name: 'custom-worker', main: 'worker/index.ts',
    d1_databases: [{ binding: 'DB', database_name: 'custom-database', migrations_dir: 'worker/migrations', ...database }],
    r2_buckets: [{ binding: 'BLOBS', bucket_name: 'custom-bucket', ...bucket }] };
  // The deployment entrypoint must accept actual JSONC, not just JSON.
  const source = '// deployment template\n' + JSON.stringify(config, null, 2).replace(/\n}$/, ',\n}');
  writeFileSync(path, source);
  t.after(() => {
    try {
      assert.equal(readFileSync(path, 'utf8'), source, 'source template must not be rewritten');
      assert.deepEqual(readdirSync(dir), ['wrangler.jsonc'], 'temporary config must be removed');
    } finally {
      assert.equal(dirname(resolve(dir)), resolve(tmpdir()));
      rmSync(dir, { recursive: true, force: true });
    }
  });
  return path;
}
function resolved(args) { return JSON.parse(readFileSync(args[args.indexOf('--config') + 1], 'utf8')); }

test('dashboard deploy publishes only code and preserves dashboard binding types', t => {
  const path = fixture(t), commands = [];
  deployDashboard(path, args => {
    commands.push(args[0]);
    const config = resolved(args);
    assert.equal(config.name, 'custom-worker');
    assert.equal(config.main, 'worker/index.ts');
    for (const key of ['d1_databases', 'r2_buckets', 'vars']) assert.equal(config[key], undefined);
    assert.deepEqual(config.unsafe.metadata.keep_bindings,
      ['d1', 'r2_bucket', 'plain_text', 'json', 'secret_text', 'secret_key']);
    assert.equal(config.keep_vars, true);
    assert.ok(!args.includes('--x-auto-create'));
  });
  assert.deepEqual(commands, ['deploy']);
});

test('dashboard config preserves code settings but never sends template environment values', () => {
  const source = { vars: { PUBLIC_READ: 'true' }, rules: [{ type: 'Text', globs: ['*.txt'] }],
    triggers: { crons: ['17 * * * *'] }, unsafe: { metadata: { custom: 1 } } };
  const copy = structuredClone(source), result = dashboardConfig(source);
  assert.deepEqual(source, copy);
  assert.deepEqual(result.rules, source.rules);
  assert.deepEqual(result.triggers, source.triggers);
  assert.equal(result.unsafe.metadata.custom, 1);
  assert.equal(result.vars, undefined);
});

test('failed dashboard deployment cleans up and dry-run remains non-deploying', t => {
  const path = fixture(t);
  assert.throws(() => deployDashboard(path, () => { throw new Error('upload failed'); }), /upload failed/);
  deployDashboard(path, args => assert.ok(args.includes('--dry-run')), { dryRun: true });
});

test('first deploy creates D1, migrates with its real UUID, then deploys with R2 provisioning', async t => {
  const path = fixture(t), commands = [];
  let created = false;
  await deployRegistry(path, async args => {
    commands.push(args.slice(0, 3).join(' '));
    if (args[1] === 'list') return JSON.stringify(created ? [{ name: 'custom-database', uuid }] : []);
    if (args[1] === 'create') { assert.ok(args.includes('--no-update-config')); created = true; return; }
    const config = resolved(args);
    assert.equal(config.d1_databases[0].database_id, uuid);
    assert.equal(config.d1_databases[0].migrations_dir, 'worker/migrations');
    assert.equal(config.r2_buckets[0].bucket_name, 'custom-bucket');
    if (args[0] === 'deploy') assert.ok(args.includes('--x-auto-create') && args.includes('--x-provision'));
  });
  assert.deepEqual(commands.map(c => c.split(' ').slice(0, 2).join(' ')),
    ['d1 list', 'd1 create', 'd1 list', 'd1 migrations', 'd1 execute', 'deploy --config']);
});

test('subsequent builds reuse an existing named database without creating another', async t => {
  const path = fixture(t);
  const calls = [];
  await deployRegistry(path, args => {
    calls.push(args[0] === 'deploy' ? 'deploy' : args[1]);
    if (args[1] === 'list') return JSON.stringify([{ name: 'unrelated', uuid: 'wrong' }, { name: 'custom-database', uuid }]);
    assert.equal(resolved(args).d1_databases[0].database_id, uuid);
  });
  assert.deepEqual(calls, ['list', 'migrations', 'execute', 'deploy']);
});

test('one-click supplied UUID is honored without listing or creating databases', async t => {
  const path = fixture(t, { database_id: uuid });
  const calls = [];
  await deployRegistry(path, args => { calls.push(args[0] === 'deploy' ? 'deploy' : args[1]); assert.equal(resolved(args).d1_databases[0].database_id, uuid); });
  assert.deepEqual(calls, ['migrations', 'execute', 'deploy']);
});

test('one-click existing D1 and R2 selections survive migrations and deployment', async t => {
  const bucket = { bucket_name: 'existing-registry-artifacts', jurisdiction: 'eu' };
  const path = fixture(t, { database_id: uuid, database_name: 'selected-registry' }, bucket);
  const calls = [];
  await deployRegistry(path, args => {
    calls.push(args[0] === 'deploy' ? 'deploy' : args[1]);
    const config = resolved(args);
    assert.equal(config.d1_databases[0].database_id, uuid);
    assert.equal(config.d1_databases[0].database_name, 'selected-registry');
    assert.deepEqual(config.r2_buckets, [{ binding: 'BLOBS', ...bucket }]);
  });
  assert.deepEqual(calls, ['migrations', 'execute', 'deploy']);
});

test('missing application tables prevent publication even when migrations succeed', async t => {
  const path = fixture(t, { database_id: uuid });
  const calls = [];
  await assert.rejects(deployRegistry(path, args => {
    calls.push(args[1]);
    if (args[1] === 'execute') {
      assert.match(args[args.indexOf('--command') + 1], /SELECT 1 FROM users LIMIT 0;/);
      assert.match(args[args.indexOf('--command') + 1], /SELECT 1 FROM versions LIMIT 0;/);
      throw new Error('no such table: users');
    }
  }), /no such table/);
  assert.deepEqual(calls, ['migrations', 'execute']);
});

test('repair mode migrates and checks the database without publishing a Worker', async t => {
  const path = fixture(t, { database_id: uuid });
  const calls = [];
  await deployRegistry(path, args => {
    assert.equal(resolved(args).d1_databases[0].database_id, uuid);
    calls.push(args[1]);
  }, { migrateOnly: true });
  assert.deepEqual(calls, ['migrations', 'execute']);
});

test('migration failure prevents Worker publication and removes temporary config', async t => {
  const path = fixture(t, { database_id: uuid });
  await assert.rejects(deployRegistry(path, args => {
    assert.equal(args[1], 'migrations'); throw new Error('migration failed');
  }), /migration failed/);
});

test('failed creation does not attempt migrations or deployment', async t => {
  const path = fixture(t);
  await assert.rejects(deployRegistry(path, args => {
    if (args[1] === 'list') return '[]';
    assert.equal(args[1], 'create'); throw new Error('permission denied');
  }), /permission denied/);
});

test('concurrent create recovers only after an exact-name database is found', async t => {
  const path = fixture(t); let lists = 0, migrated = false;
  await deployRegistry(path, args => {
    if (args[1] === 'list') return JSON.stringify(++lists === 1 ? [] : [{ name: 'custom-database', uuid }]);
    if (args[1] === 'create') throw new Error('already exists');
    if (args[1] === 'migrations') migrated = true;
    assert.equal(resolved(args).d1_databases[0].database_id, uuid);
  });
  assert.ok(migrated);
});
