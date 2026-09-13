ALTER TABLE namespaces ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public' CHECK(visibility IN ('public','private'));
CREATE TABLE blob_uploads (
  digest TEXT NOT NULL REFERENCES blobs(digest),
  username TEXT NOT NULL REFERENCES users(username),
  PRIMARY KEY(digest, username)
);
CREATE TABLE release_artifacts (
  namespace TEXT NOT NULL,
  package TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL REFERENCES blobs(digest),
  PRIMARY KEY(namespace, package, version, digest),
  FOREIGN KEY(namespace, package, version) REFERENCES versions(namespace, package, version)
);
CREATE INDEX release_artifacts_digest ON release_artifacts(digest, namespace);
INSERT OR IGNORE INTO release_artifacts(namespace,package,version,digest)
  SELECT v.namespace,v.package,v.version,json_extract(a.value,'$.digest')
  FROM versions v,json_each(v.manifest_json,'$.artifacts') a;
