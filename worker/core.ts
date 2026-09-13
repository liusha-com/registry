import { initSync, manifest, versions, analyze, password_hash, password_verify, page, content_security_policy } from './core/pkg/registry_worker_core.js';
import wasm from './core/pkg/registry_worker_core_bg.wasm';

let initialized = false;
export function core() {
  if (!initialized) { initSync({ module: wasm }); initialized = true; }
  return { manifest, versions, analyze, password_hash, password_verify, page, content_security_policy };
}
