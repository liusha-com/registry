import { type Env, notFound } from './common';

export const visibleNamespace = "(n.visibility='public' OR n.owner_username=?)";
export const visibleBlob = `(EXISTS (SELECT 1 FROM release_artifacts a JOIN namespaces n ON n.name=a.namespace
  WHERE a.digest=b.digest AND ${visibleNamespace})
  OR EXISTS (SELECT 1 FROM blob_uploads u WHERE u.digest=b.digest AND u.username=?))`;

export async function namespaceAccess(env: Env, namespace: string, username: string | null) {
  const row = await env.DB.prepare(`SELECT n.name,n.description,n.owner_username,n.created_at,n.visibility
    FROM namespaces n WHERE n.name=? AND ${visibleNamespace}`).bind(namespace, username).first();
  return row || notFound();
}

export async function blobAccess(env: Env, digest: string, username: string | null) {
  const row = await env.DB.prepare(`SELECT EXISTS (SELECT 1 FROM release_artifacts a
    JOIN namespaces n ON n.name=a.namespace WHERE a.digest=b.digest AND n.visibility='public') AS public
    FROM blobs b WHERE b.digest=? AND ${visibleBlob}`).bind(digest, username, username).first<{public: number}>();
  return row || notFound();
}
