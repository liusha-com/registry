import { core } from './core';
import { identify, owner, requireRead } from './auth';
import { namespaceAccess, blobAccess, visibleNamespace, visibleBlob } from './visibility';
import { type Env, ApiError, fail, json, name, digest, limit, body, object, hash, utf8, iso, unique, notFound } from './common';

interface VersionRow {
  version: string;
  manifest_json: string;
  manifest_digest: string;
  yanked: number;
  created_at: string;
}
interface Artifact { name: string; digest: string; size: number; media_type: string; }
interface Manifest { namespace: string; name: string; version: string; description: string; overview?: string; artifacts: Artifact[]; }
function overview(value: unknown): string {
  if (typeof value !== 'string' || utf8(value).length > 64 * 1024)
    return fail(400, 'invalid_overview', 'Overview must be Markdown text of at most 64 KiB (UTF-8).');
  return value;
}
const record = (v: VersionRow) => ({ version: v.version, manifest_digest: v.manifest_digest, yanked: Boolean(v.yanked), created_at: v.created_at });
const release = (v: VersionRow) => ({ manifest: JSON.parse(v.manifest_json), record: record(v) });
function sorted(values: string[], requirement?: string): string[] {
  try { return JSON.parse(core().versions(JSON.stringify(values), requirement)); }
  catch { return fail(400, 'invalid_requirement', 'Invalid semantic version requirement.'); }
}
async function releases(env: Env, ns: string, pkg: string): Promise<VersionRow[]> {
  const result = await env.DB.prepare('SELECT version,manifest_json,manifest_digest,yanked,created_at FROM versions WHERE namespace=? AND package=?')
    .bind(ns, pkg).all<VersionRow>();
  return result.results;
}
function pageNumber(url: URL, key: string, fallback: number, max: number, min = 0): number {
  const raw = url.searchParams.get(key);
  if (raw === null) return fallback;
  const n = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(n) || n < min || n > max) fail(400, `invalid_${key}`, `Invalid ${key}.`);
  return n;
}

export async function registry(request: Request, env: Env, path: string): Promise<Response> {
  const method = request.method, url = new URL(request.url);
  const read = method === 'GET' || method === 'HEAD';
  if (read) await requireRead(request, env);
  const hasCredential = request.headers.has('authorization') || /(?:^|;\s*)registry_session=/.test(request.headers.get('cookie') || '');
  let reader: string | null = null;
  if (read && hasCredential) {
    try { reader = (await identify(request, env)).username; }
    catch (error) { if (!(error instanceof ApiError && error.status === 401)) throw error; }
  }
  if (path === '/v1/info' && read) return json({
    registry_version: '0.1', package_schemas: ['wasmd.package/v0'], public_read: env.PUBLIC_READ === 'true',
    max_blob_bytes: limit(env.MAX_BLOB_BYTES, 8 * 1024 * 1024),
    component_analysis_max_bytes: limit(env.MAX_ANALYSIS_BYTES, 8 * 1024 * 1024), admission_engine: 'builtin',
    features: ['component-model', 'wit-analysis', 'dependency-graph', 'user-accounts', 'multi-page-ui', 'namespace-ownership', 'yanking', 'package-overview'],
  });
  if (path === '/v1/stats' && read) {
    return json(await env.DB.prepare(`WITH visible_namespaces AS (SELECT n.name FROM namespaces n WHERE ${visibleNamespace}),
      visible_blobs AS (SELECT b.digest FROM blobs b WHERE ${visibleBlob})
      SELECT (SELECT COUNT(*) FROM visible_namespaces) AS namespaces,
      (SELECT COUNT(*) FROM packages WHERE namespace IN visible_namespaces) AS packages,
      (SELECT COUNT(*) FROM versions WHERE namespace IN visible_namespaces) AS versions,
      (SELECT COUNT(*) FROM visible_blobs) AS blobs,
      (SELECT COUNT(*) FROM component_analyses WHERE digest IN visible_blobs) AS components`).bind(reader, reader, reader).first());
  }
  if (path === '/v1/namespaces' && method === 'POST') {
    const identity = await identify(request, env, true), input = await object(request);
    name(input.name);
    const description = input.description ?? '';
    if (typeof description !== 'string' || utf8(description).length > 4096) fail(400, 'description_too_long', 'Description must be at most 4096 UTF-8 bytes.');
    const visibility = input.visibility === undefined ? 'public' : input.visibility;
    if (visibility !== 'public' && visibility !== 'private') fail(400, 'invalid_visibility', 'Choose public or private.');
    const value = { name: input.name, description, visibility, owner_username: identity.username, created_at: iso() };
    try {
      await env.DB.prepare('INSERT INTO namespaces(name,description,visibility,owner_username,created_at) VALUES (?,?,?,?,?)')
        .bind(value.name, description, visibility, identity.username, value.created_at).run();
    } catch (error) {
      if (unique(error)) fail(409, 'namespace_exists', 'Namespace already exists.');
      throw error;
    }
    return json(value, 201);
  }
  const namespaceMatch = path.match(/^\/v1\/namespaces\/([^/]+)$/);
  if (namespaceMatch && read) {
    name(namespaceMatch[1]);
    return json(await namespaceAccess(env, namespaceMatch[1], reader));
  }
  const blobMatch = path.match(/^\/v1\/blobs\/([^/]+)(\/component)?$/);
  if (blobMatch) {
    const key = blobMatch[1];
    digest(key);
    const access = read ? await blobAccess(env, key, reader) : null;
    if (blobMatch[2] && read) {
      const row = await env.DB.prepare('SELECT analysis_json FROM component_analyses WHERE digest=?').bind(key).first<{analysis_json: string}>();
      if (row) return json(JSON.parse(row.analysis_json));
      // Older deployments skipped components above 1 MiB. Fill their metadata
      // from the immutable blob on first read; existing releases need no upload.
      const metadata = await env.DB.prepare('SELECT size FROM blobs WHERE digest=?').bind(key).first<{size: number}>();
      if (!metadata) return notFound();
      if (metadata.size > limit(env.MAX_ANALYSIS_BYTES, 8 * 1024 * 1024))
        return fail(422, 'analysis_limit_exceeded', 'This artifact exceeds the configured component analysis size limit.');
      const stored = await env.BLOBS.get(key);
      if (!stored) return fail(503, 'blob_unavailable', 'Artifact storage is temporarily unavailable.');
      const bytes = await body(new Request('https://registry.internal/blob', { method: 'POST', body: stored.body }),
        limit(env.MAX_ANALYSIS_BYTES, 8 * 1024 * 1024));
      const analysis = core().analyze(key, bytes);
      if (!analysis) return notFound();
      await env.DB.prepare('INSERT INTO component_analyses(digest,analysis_json) VALUES (?,?) ON CONFLICT(digest) DO NOTHING')
        .bind(key, analysis).run();
      return json(JSON.parse(analysis));
    }
    if (!blobMatch[2] && method === 'PUT') {
      const uploader = await identify(request, env, true);
      const media = request.headers.get('content-type') || 'application/octet-stream';
      if (media.length > 255) fail(400, 'invalid_media_type', 'Content-Type is too long.');
      const bytes = await body(request, limit(env.MAX_BLOB_BYTES, 8 * 1024 * 1024));
      if (`sha256:${await hash(bytes)}` !== key) fail(400, 'digest_mismatch', 'Uploaded bytes do not match the requested digest.');
      const existing = await env.DB.prepare('SELECT digest,size,media_type,created_at FROM blobs WHERE digest=?').bind(key).first();
      if (existing) {
        await env.DB.prepare('INSERT OR IGNORE INTO blob_uploads(digest,username) VALUES (?,?)').bind(key, uploader.username).run();
        return json(existing, 200);
      }
      // All writers of this key have verified identical bytes. R2 is private and keys are immutable.
      await env.BLOBS.put(key, bytes, { httpMetadata: { contentType: 'application/octet-stream' } });
      const created = iso();
      let analysis: string | undefined;
      if (bytes.length <= limit(env.MAX_ANALYSIS_BYTES, 8 * 1024 * 1024)) analysis = core().analyze(key, bytes);
      const statements = [env.DB.prepare('INSERT INTO blobs(digest,size,media_type,created_at) VALUES (?,?,?,?) ON CONFLICT(digest) DO NOTHING')
        .bind(key, bytes.length, media, created),
        env.DB.prepare('INSERT OR IGNORE INTO blob_uploads(digest,username) VALUES (?,?)').bind(key, uploader.username)];
      if (analysis) statements.push(env.DB.prepare('INSERT INTO component_analyses(digest,analysis_json) VALUES (?,?) ON CONFLICT(digest) DO NOTHING').bind(key, analysis));
      await env.DB.batch(statements);
      return json(await env.DB.prepare('SELECT digest,size,media_type,created_at FROM blobs WHERE digest=?').bind(key).first(), 201);
    }
    if (!blobMatch[2] && read) {
      const metadata = await env.DB.prepare('SELECT size FROM blobs WHERE digest=?').bind(key).first<{size: number}>();
      if (!metadata) notFound();
      const headers = new Headers({
        'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment',
        'Content-Security-Policy': "sandbox; default-src 'none'", 'X-Content-Type-Options': 'nosniff',
        'ETag': `"${key}"`, 'Content-Length': String(metadata.size),
        'Cache-Control': env.PUBLIC_READ === 'true' && access?.public ? 'public, max-age=31536000, immutable' : 'private, no-store',
        'Vary': 'Cookie, Authorization',
      });
      const stored = method === 'HEAD' ? await env.BLOBS.head(key) : await env.BLOBS.get(key);
      if (!stored) fail(503, 'blob_unavailable', 'Artifact storage is temporarily unavailable.');
      if (request.headers.get('if-none-match')?.split(',').some(t => ['*', `"${key}"`, `W/"${key}"`].includes(t.trim()))) {
        headers.delete('Content-Length');
        return new Response(null, { status: 304, headers });
      }
      return new Response('body' in stored ? stored.body as ReadableStream : null, { headers });
    }
  }
  const packageMatch = path.match(/^\/v1\/packages\/([^/]+)\/([^/]+)(?:\/([^/]+))?(\/yank)?$/);
  if (packageMatch) {
    const [, ns, pkg, version, yank] = packageMatch;
    name(ns); name(pkg);
    if (version === 'overview' && !yank && method === 'PUT') {
      await owner(request, env, ns);
      const input = await object(request, 512 * 1024), markdown = overview(input.overview);
      if (!Number.isSafeInteger(input.revision) || Number(input.revision) < 0)
        return fail(400, 'invalid_revision', 'Provide the current overview_revision as revision.');
      const result = await env.DB.prepare(`UPDATE packages SET overview=?,overview_revision=overview_revision+1
        WHERE namespace=? AND name=? AND overview_revision=? RETURNING overview,overview_revision`)
        .bind(markdown, ns, pkg, input.revision).first();
      if (!result) {
        if (!await env.DB.prepare('SELECT 1 FROM packages WHERE namespace=? AND name=?').bind(ns, pkg).first()) return notFound();
        return fail(409, 'overview_conflict', 'Overview changed since you opened it. Reload the package before saving again.');
      }
      return json(result);
    }
    if (version === 'versions' && !yank && method === 'POST') {
      const identity = await owner(request, env, ns);
      // Bound below D1's SQL/value limits; Rust performs the protocol validation.
      const input = await object(request, 512 * 1024);
      const markdown = input.overview === undefined ? null : overview(input.overview);
      let canonical: string;
      try { canonical = core().manifest(JSON.stringify(input)); }
      catch (error) { return fail(400, 'invalid_manifest', String(error)); }
      const m: Manifest = JSON.parse(canonical);
      if (m.namespace !== ns || m.name !== pkg) fail(400, 'path_manifest_mismatch', 'Path namespace/package differs from manifest.');
      if (m.artifacts.length > 32) fail(400, 'artifact_limit', 'Workers publications support at most 32 artifacts.');
      for (const artifact of m.artifacts) await blobAccess(env, artifact.digest, identity.username);
      const checks = await env.DB.batch<{size: number}>(m.artifacts.map(a => env.DB.prepare('SELECT size FROM blobs WHERE digest=?').bind(a.digest)));
      for (let i = 0; i < m.artifacts.length; i++) {
        if (!checks[i].results.length) fail(409, 'blob_missing', 'Upload every artifact before publishing.');
        if (checks[i].results[0].size !== m.artifacts[i].size) fail(409, 'blob_size_mismatch', 'Artifact size does not match its uploaded blob.');
      }
      const md = `sha256:${await hash(canonical)}`, created = iso();
      try {
        // D1 batches are transactional. A duplicate version rolls back the package upsert too.
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO packages(namespace,name,description,created_at,updated_at,overview,overview_revision) VALUES (?,?,?,?,?,COALESCE(?,''),?)
            ON CONFLICT(namespace,name) DO UPDATE SET description=excluded.description,updated_at=excluded.updated_at,
              overview=CASE WHEN ? IS NULL THEN packages.overview ELSE excluded.overview END,
              overview_revision=packages.overview_revision+excluded.overview_revision`)
            .bind(ns, pkg, m.description, created, created, markdown, markdown === null ? 0 : 1, markdown),
          env.DB.prepare(`INSERT INTO versions(namespace,package,version,manifest_json,manifest_digest,created_at,updated_at,publisher_username)
            VALUES (?,?,?,?,?,?,?,?)`).bind(ns, pkg, m.version, canonical, md, created, created, identity.username),
          ...m.artifacts.map(a => env.DB.prepare('INSERT OR IGNORE INTO release_artifacts(namespace,package,version,digest) VALUES (?,?,?,?)')
            .bind(ns, pkg, m.version, a.digest)),
        ]);
      } catch (error) {
        if (unique(error)) fail(409, 'version_exists', 'Package version is immutable and already exists.');
        throw error;
      }
      return json({ manifest: m, record: { version: m.version, manifest_digest: md, yanked: false, created_at: created } }, 201, { ETag: `"${md}"` });
    }
    if (version && yank && ['POST', 'DELETE'].includes(method)) {
      await owner(request, env, ns);
      const result = await env.DB.prepare('UPDATE versions SET yanked=?,updated_at=? WHERE namespace=? AND package=? AND version=?')
        .bind(Number(method === 'POST'), iso(), ns, pkg, version).run();
      if (!result.meta.changes) notFound();
      return json({ yanked: method === 'POST' });
    }
    if (read && !yank) {
      const namespace = await namespaceAccess(env, ns, reader);
      if (version && version !== 'resolve') {
        const row = await env.DB.prepare('SELECT version,manifest_json,manifest_digest,yanked,created_at FROM versions WHERE namespace=? AND package=? AND version=?')
          .bind(ns, pkg, version).first<VersionRow>();
        if (!row) notFound();
        return json(release(row), 200, { ETag: `"${row.manifest_digest}"` });
      }
      const rows = await releases(env, ns, pkg);
      if (version === 'resolve') {
        const selected = sorted(rows.filter(v => !v.yanked).map(v => v.version), url.searchParams.get('requirement') ?? '*')[0];
        const row = rows.find(v => v.version === selected);
        return json(row ? release(row) : notFound());
      }
      const p = await env.DB.prepare('SELECT namespace,name,description,updated_at,overview,overview_revision FROM packages WHERE namespace=? AND name=?').bind(ns, pkg).first();
      if (!p) notFound();
      const byVersion = new Map(rows.map(v => [v.version, v]));
      const ordered = sorted(rows.map(v => v.version)).map(v => byVersion.get(v)!);
      const latest = ordered.find(v => !v.yanked);
      return json({ ...p, visibility: namespace.visibility, owner_username: namespace.owner_username,
        latest_release: latest ? release(latest) : null, versions: ordered.map(record) });
    }
  }
  if (path === '/v1/search' && read) {
    const q = url.searchParams.get('q') || '';
    if (utf8(q).length > 200) fail(400, 'query_too_long', 'Search query exceeds 200 bytes.');
    const count = pageNumber(url, 'limit', 20, 100, 1), offset = pageNumber(url, 'offset', 0, 1_000_000);
    const result = await env.DB.prepare(`SELECT p.namespace,p.name,p.description,p.updated_at FROM packages p JOIN namespaces n ON n.name=p.namespace
      WHERE ${visibleNamespace} AND instr(lower(p.namespace || '/' || p.name || ' ' || p.description),lower(?))>0
      ORDER BY p.updated_at DESC,p.namespace,p.name LIMIT ? OFFSET ?`).bind(reader, q, count, offset)
      .all<{namespace: string; name: string; description: string; updated_at: string}>();
    // One batch avoids exhausting the per-request D1 query count for a 100-row page.
    const versionRows = result.results.length ? await env.DB.batch<{version: string}>(result.results.map(p =>
      env.DB.prepare('SELECT version FROM versions WHERE namespace=? AND package=? AND yanked=0').bind(p.namespace, p.name))) : [];
    return json({ items: result.results.map((p, i) => ({ ...p, latest_version: sorted(versionRows[i].results.map(v => v.version))[0] || null })), limit: count, offset });
  }
  return notFound();
}
