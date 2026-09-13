// Works in Workers Builds (Linux), local macOS, and Windows. No cloud credentials.
import { spawnSync } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';

process.chdir(fileURLToPath(new URL('..', import.meta.url)));
process.env.PATH = join(process.env.CARGO_HOME || join(homedir(), '.cargo'), 'bin') + delimiter + process.env.PATH;
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit', env: process.env });
  if (result.error || result.status !== 0) throw new Error(`${command} failed: ${result.error || result.status}`);
}
if (spawnSync('rustup', ['--version']).error) {
  if (process.platform === 'win32') throw new Error('Install Rust from https://rustup.rs and retry.');
  run('curl', ['--proto', '=https', '--tlsv1.2', '-sSf', 'https://sh.rustup.rs', '-o', '.rustup-init.sh']);
  run('sh', ['.rustup-init.sh', '-y', '--profile', 'minimal', '--default-toolchain', 'none']);
}
process.env.RUSTUP_TOOLCHAIN = process.env.REGISTRY_RUST_TOOLCHAIN || '1.98.0';
if (spawnSync('rustc', ['--version'], { env: process.env }).status !== 0)
  run('rustup', ['toolchain', 'install', process.env.RUSTUP_TOOLCHAIN, '--profile', 'minimal']);
run('rustup', ['target', 'add', 'wasm32-unknown-unknown']);
mkdirSync('worker/generated', { recursive: true });
await build({ entryPoints: ['ui/app.js'], outfile: 'worker/generated/app.txt', bundle: true, format: 'iife', target: 'es2022', minify: true });
// Native administrator tokens are not part of the namespace-owned Worker profile.
writeFileSync('worker/generated/openapi.yaml', readFileSync('openapi/registry.yaml', 'utf8')
  .replace('url: http://127.0.0.1:8080', 'url: /')
  .replace(/^  \/v1\/admin\/tokens[^\n]*\n[\s\S]*?(?=^  \/|^components:)/gm, ''));
// Avoid compiling twice when Workers Builds runs both build and deploy scripts.
const hash = createHash('sha256');
hash.update(process.env.RUSTUP_TOOLCHAIN);
const { readdirSync } = await import('node:fs');
function hashTree(path) {
  for (const entry of readdirSync(path, { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name))) {
    if (['target', 'pkg'].includes(entry.name)) continue;
    const p = join(path, entry.name);
    if (entry.isDirectory()) hashTree(p); else hash.update(p).update(readFileSync(p));
  }
}
for (const dir of ['worker/core', 'ui']) hashTree(dir);
for (const p of ['src/domain.rs', 'src/component.rs', 'src/pages.rs', 'tools/build-worker.mjs', 'package-lock.json']) hash.update(readFileSync(p));
const key = hash.digest('hex');
const stamp = 'worker/generated/build.sha256';
if (!existsSync(stamp) || readFileSync(stamp, 'utf8') !== key || !existsSync('worker/core/pkg/registry_worker_core_bg.wasm')) {
  run(process.execPath, ['node_modules/wasm-pack/run.js', 'build', 'worker/core', '--target', 'web', '--release', '--locked']);
  writeFileSync(stamp, key);
}
