// Provision D1 before migrations. Publish the application only after migrations succeed.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parse } from 'jsonc-parser';

const root = fileURLToPath(new URL('..', import.meta.url));
const zeroId = '00000000-0000-0000-0000-000000000000';
const validId = id => typeof id === 'string' && id !== zeroId &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);

function wrangler(args, { capture = false } = {}) {
  const result = spawnSync(process.execPath, [join(root, 'node_modules/wrangler/bin/wrangler.js'), ...args], {
    cwd: root,
    env: process.env,
    // No confirmation prompts in builds; credentials come from Wrangler/Workers Builds.
    stdio: ['ignore', capture ? 'pipe' : 'inherit', 'inherit'],
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`wrangler ${args.slice(0, 3).join(' ')} failed (exit ${result.status}).`);
  return result.stdout;
}

export async function deployRegistry(configPath = join(root, 'wrangler.jsonc'), run = wrangler, { migrateOnly = false } = {}) {
  configPath = resolve(configPath);
  const errors = [];
  const config = parse(readFileSync(configPath, 'utf8'), errors, { allowTrailingComma: true });
  if (errors.length || !config || typeof config !== 'object') throw new Error('Invalid Wrangler JSONC configuration.');
  const db = config.d1_databases?.find(binding => binding.binding === 'DB');
  if (!db) throw new Error('The DB binding is required in wrangler.jsonc.');

  if (!db.database_id || db.database_id === zeroId) {
    // Preserve resource names customized by Deploy to Cloudflare. The fallback
    // matches Wrangler's automatic name when only a binding has been declared.
    db.database_name ||= config.name ? `${config.name}-db` : undefined;
    if (!db.database_name) throw new Error('Set a database_name or Worker name before deploying.');
    const find = async () => {
      const databases = JSON.parse(await run(['d1', 'list', '--json', '--config', configPath], { capture: true }));
      if (!Array.isArray(databases)) throw new Error('Wrangler returned an invalid D1 database list.');
      return databases.find(item => item.name === db.database_name);
    };
    let database = await find();
    if (!database) {
      try {
        await run(['d1', 'create', db.database_name, '--no-update-config', '--config', configPath]);
      } catch (error) {
        // A concurrent first deployment may have won the create race. Reuse only
        // an exact name match; permission/network failures otherwise stop here.
        database = await find();
        if (!database) throw error;
      }
      database ||= await find();
    }
    if (!database || !validId(database.uuid)) throw new Error('D1 provisioning did not return a real database UUID. Deployment stopped.');
    db.database_id = database.uuid;
  }
  if (!validId(db.database_id)) throw new Error('DB.database_id is not a valid database UUID.');

  // Keep relative Worker/migration paths intact. Never commit an account-specific
  // ID into the reusable source template. Both commands use the same resolved ID.
  const deploymentConfig = join(dirname(configPath), `.wrangler.deploy.${randomUUID()}.jsonc`);
  writeFileSync(deploymentConfig, JSON.stringify(config, null, 2) + '\n', { flag: 'wx' });
  try {
    await run(['d1', 'migrations', 'apply', 'DB', '--remote', '--config', deploymentConfig]);
    // A successful migration command is not sufficient if the ledger and schema
    // have diverged. Read every required table before publishing, without rows.
    const schemaCheck = ['users', 'credentials', 'auth_attempts', 'namespaces',
      'blobs', 'component_analyses', 'packages', 'versions', 'oauth_identities', 'oauth_states', 'blob_uploads', 'release_artifacts']
      .map(table => `SELECT 1 FROM ${table} LIMIT 0;`).join('\n') + '\nSELECT visibility FROM namespaces LIMIT 0;\nSELECT overview,overview_revision FROM packages LIMIT 0;';
    await run(['d1', 'execute', 'DB', '--remote', '--config', deploymentConfig, '--command', schemaCheck]);
    if (!migrateOnly) await run(['deploy', '--config', deploymentConfig, '--x-provision', '--x-auto-create']);
  } finally {
    unlinkSync(deploymentConfig);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== '--migrate-only')) {
    console.error('Usage: node tools/deploy-worker.mjs [--migrate-only]');
    process.exitCode = 1;
  } else {
    deployRegistry(undefined, undefined, { migrateOnly: args.includes('--migrate-only') })
      .catch(error => { console.error(error.message); process.exitCode = 1; });
  }
}
