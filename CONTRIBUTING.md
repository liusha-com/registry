# Contributing

Contributions, interoperability reports, documentation fixes, and protocol
reviews are welcome.

1. Discuss wire-breaking changes before implementation.
2. Add tests for behavior changes and migrations for persistent-schema changes.
3. Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
   and `cargo test --all-targets`.
4. Keep package versions immutable and preserve unknown manifest fields.
5. Do not add ambient host capabilities or runtime-private state to Registry Core; service guests may import only versioned WASI interfaces.

For the Cloudflare Workers profile, run `npm ci` and `npm test`. This builds the
shared Rust/Wasm helper, checks TypeScript, performs a Wrangler deployment dry
run, and tests local D1/R2 behavior in workerd without cloud credentials. Add
Workers schema changes under `worker/migrations/`; native SQLite migrations live
separately under `migrations/`. Keep shared UI and protocol behavior compatible
with both runtimes. See [Cloudflare development](README.md#local-development-and-manual-deployment).

Commits should be focused and explain compatibility and security impact. By
contributing, you agree that your contribution is licensed under Apache-2.0.
