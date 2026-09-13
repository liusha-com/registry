// Deploy code while retaining resources and settings managed in the dashboard.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parse } from 'jsonc-parser';

const root = fileURLToPath(new URL('..', import.meta.url));
export function dashboardConfig(source) {
  const config = structuredClone(source);
  delete config.d1_databases;
  delete config.r2_buckets;
  delete config.vars;
  config.keep_vars = true;
  // Wrangler passes this upload metadata to Cloudflare. Preserve all binding
  // types used by Registry, including encrypted secrets, on subsequent uploads.
  config.unsafe = { ...config.unsafe, metadata: { ...config.unsafe?.metadata,
    keep_bindings: ['d1', 'r2_bucket', 'plain_text', 'json', 'secret_text', 'secret_key'],
  } };
  return config;
}

export function deployDashboard(configPath = join(root, 'wrangler.jsonc'), run = args => {
  const result = spawnSync(process.execPath, [join(root, 'node_modules/wrangler/bin/wrangler.js'), ...args],
    { cwd: root, env: process.env, stdio: ['ignore', 'inherit', 'inherit'] });
  if (result.error || result.status !== 0) throw result.error || new Error(`Dashboard deployment failed (${result.status}).`);
}, { dryRun = false } = {}) {
  const errors = [];
  const source = parse(readFileSync(configPath, 'utf8'), errors, { allowTrailingComma: true });
  if (errors.length || !source || typeof source !== 'object' || Array.isArray(source)) throw new Error('Invalid Wrangler configuration.');
  const temporary = join(dirname(configPath), `.wrangler.deploy.${randomUUID()}.jsonc`);
  writeFileSync(temporary, JSON.stringify(dashboardConfig(source), null, 2), { flag: 'wx' });
  try {
    run(['deploy', '--config', temporary, ...(dryRun ? ['--dry-run'] : [])]);
  } finally { unlinkSync(temporary); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== '--dry-run')) {
    console.error('Usage: node tools/deploy-dashboard.mjs [--dry-run]'); process.exitCode = 1;
  } else {
    try { deployDashboard(undefined, undefined, { dryRun: args.includes('--dry-run') }); }
    catch (error) { console.error(error.message); process.exitCode = 1; }
  }
}
