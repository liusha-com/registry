# Security policy

## Supported versions

The latest `0.1.x` release receives security fixes while the protocol remains a
draft. Security fixes may tighten validation or limits without weakening the
immutable wire contract.

## Reporting a vulnerability

Do not file a public issue for a suspected vulnerability. Contact the project
maintainers through the private security-reporting channel configured on the
canonical source repository. Include affected revision, reproduction, impact,
and any suggested mitigation. Maintainers should acknowledge a report within
three business days and coordinate disclosure after a fix is available.

## Deployment assumptions

- TLS, DDoS protection, and per-principal rate limiting belong at the edge.
- The bootstrap admin token is a deployment secret and must be at least 32
  characters; generated API tokens contain 256 random bits.
- API token secrets are returned once and only SHA-256 hashes are stored.
- Namespace restrictions and scopes are enforced before package lookup or
  publication.
- Uploaded bytes, JSON, lengths, names, media types, and dependency constraints
  are untrusted and bounded.
- Digest verification provides integrity, not publisher identity. A future
  package-signature specification should bind signatures to canonical manifests
  without changing content addressing.

Never expose the service directly to the public internet without HTTPS and rate
limits. Backups contain token hashes and package metadata and must be protected.

## Browser accounts

Passwords use Argon2id with random salts. Browser session secrets are cookie-only
and use HttpOnly, SameSite=Strict, and Secure when the configured public origin
uses HTTPS. Cookie writes require a CSRF token; supplied origins must match.
Personal tokens are bearer-only, expire after 90 days, and cannot mint more tokens
or escalate to administrator. Owner checks protect account namespaces.

Uploads are untrusted. Artifact responses force attachment download, disable MIME
sniffing, and use a sandbox CSP so an uploaded HTML document cannot execute with
the Registry application's origin. Private native blob responses use no-store.

Account state and login throttling persist across restarts. Account endpoints
are not cached. Protect account files and backups, which include password hashes.
The current account system has no email verification, password reset, or MFA.
See the runbook for the measured hashing latency and single-host storage limits.
