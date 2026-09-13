-- Dedicated Workers schema. Native SQLite/account JSON files cannot be imported directly.
CREATE TABLE users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE credentials (
  hash TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL REFERENCES users(username),
  name TEXT NOT NULL,
  session INTEGER NOT NULL CHECK(session IN (0,1)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX credentials_user ON credentials(username, session);
CREATE INDEX credentials_expiry ON credentials(expires_at);
CREATE TABLE auth_attempts (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX attempts_expiry ON auth_attempts(expires_at);
CREATE TABLE namespaces (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  owner_username TEXT NOT NULL REFERENCES users(username),
  created_at TEXT NOT NULL
);
CREATE INDEX namespaces_owner ON namespaces(owner_username);
CREATE TABLE blobs (
  digest TEXT PRIMARY KEY,
  size INTEGER NOT NULL CHECK(size >= 0),
  media_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE component_analyses (
  digest TEXT PRIMARY KEY REFERENCES blobs(digest),
  analysis_json TEXT NOT NULL
);
CREATE TABLE packages (
  namespace TEXT NOT NULL REFERENCES namespaces(name),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(namespace, name)
);
CREATE INDEX packages_updated ON packages(updated_at DESC, namespace, name);
CREATE TABLE versions (
  namespace TEXT NOT NULL,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  yanked INTEGER NOT NULL DEFAULT 0 CHECK(yanked IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  publisher_username TEXT NOT NULL REFERENCES users(username),
  PRIMARY KEY(namespace, package, version),
  FOREIGN KEY(namespace, package) REFERENCES packages(namespace, name)
);
