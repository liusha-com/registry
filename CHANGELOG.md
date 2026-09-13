# Changelog

## 0.1.0 — unreleased

- Added shared native/WASI registration, login, Argon2id passwords, HttpOnly
  sessions, CSRF/origin checks, persistent login throttling, and personal token
  creation/revocation with hashed storage.
- Replaced the single-page hash router with separate English discovery,
  registration, login, account, publish, documentation, package, and release pages.
- Enforced account namespace ownership and added portable yank/unyank support.
- Serialized portable metadata mutations across Wasmd request instances and
  retained the previous snapshot until atomic replacement.
- Added real-HTTP application acceptance coverage for both execution profiles
  and a complete English Wasmd deployment tutorial.

- Migrated the complete `registry.wasm` service to a `wasm32-wasip2` component
  exporting standard `wasi:http/incoming-handler@0.2.4`, removing the Preview 1
  exchange-directory HTTP adapter.
- Added a Windows PowerShell-compatible end-to-end component smoke test covering
  UI, discovery, namespace creation, component upload/WIT analysis, publication
  and resolution through `wasmd serve`.
- Embedded the complete Registry UI and OpenAPI assets in `registry.wasm`, and
  added WASI-native search plus Component/WIT analysis for UI feature parity.
- Reworked the Registry catalog around a Docker Hub-inspired blue discovery
  layout with compact navigation, dense package rows, responsive categories,
  consistent light/dark themes and versioned embedded asset URLs.
- Increased small metadata, navigation, package, detail and mobile typography
  for comfortable reading without reducing catalog density.
- Fixed the Windows PowerShell WASI service build script default output path.
- Added authenticated `GET /v1/auth/check` discovery for Wasmd CLI login.
- Added Registry Protocol 0.1 and `wasmd.package/v0` envelope.
- Added SQLite metadata and filesystem SHA-256 blob storage.
- Added namespace-scoped bearer tokens, immutable publication, SemVer resolve,
  yank/unyank, exact retrieval, search, ETags, health, and readiness.
- Added `wasmd-registry` server, `wr` client, OpenAPI 3.1, containers,
  migrations, integration tests, and open-source governance documentation.
- Added optional Wasmd admission mode with a Rust/WASI policy guest, startup
  validation, fuel, timeout, concurrency limits, and fail-closed publication.
