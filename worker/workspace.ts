import { type Env, json, name, notFound } from './common';

const PAGE_SIZE = 20;
interface PackageRow { namespace: string; name: string; description: string; updated_at: string; }
interface NamespaceRow { name: string; description: string; visibility: string; created_at: string; package_count: number; }
const page = <T extends { name: string }>(rows: T[]) => ({
  items: rows.slice(0, PAGE_SIZE),
  next_cursor: rows.length > PAGE_SIZE ? rows[PAGE_SIZE - 1].name : null,
});

// The caller supplies the authenticated identity, never a username from the URL.
export async function workspace(request: Request, env: Env, path: string, username: string): Promise<Response> {
  const after = new URL(request.url).searchParams.get('after') ?? '';
  if (after) name(after);
  const packageQuery = (namespace: string, cursor = '') => env.DB.prepare(`
    SELECT namespace,name,description,updated_at FROM packages
    WHERE namespace=? AND name>? ORDER BY name LIMIT ?`).bind(namespace, cursor, PAGE_SIZE + 1);
  if (path === '/v1/account/namespaces') {
    const rows = await env.DB.prepare(`SELECT n.name,n.description,n.visibility,n.created_at,
      (SELECT COUNT(*) FROM packages p WHERE p.namespace=n.name) AS package_count
      FROM namespaces n WHERE n.owner_username=? AND n.name>? ORDER BY n.name LIMIT ?`)
      .bind(username, after, PAGE_SIZE + 1).all<NamespaceRow>();
    const namespaces = page(rows.results);
    const packages = namespaces.items.length
      ? await env.DB.batch<PackageRow>(namespaces.items.map(n => packageQuery(n.name))) : [];
    return json({ namespaces: namespaces.items.map((n, i) => {
      const result = page(packages[i].results);
      return { ...n, packages: result.items, next_package_cursor: result.next_cursor };
    }), next_cursor: namespaces.next_cursor });
  }
  const match = path.match(/^\/v1\/account\/namespaces\/([^/]+)\/packages$/);
  if (!match) return notFound();
  name(match[1]);
  const owned = await env.DB.prepare('SELECT name FROM namespaces WHERE name=? AND owner_username=?')
    .bind(match[1], username).first();
  if (!owned) return notFound();
  const result = page((await packageQuery(match[1], after).all<PackageRow>()).results);
  return json({ packages: result.items, next_cursor: result.next_cursor });
}
