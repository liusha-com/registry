import { core } from './core';
import { accounts } from './auth';
import { registry } from './registry';
import { ApiError, type Env, json, now, notFound } from './common';
import css from '../ui/app.css';
import js from './generated/app.txt';
import favicon from '../ui/favicon.svg';
import openapi from './generated/openapi.yaml';

async function route(request: Request, env: Env): Promise<Response> {
  let path: string;
  try { path = decodeURIComponent(new URL(request.url).pathname); }
  catch { throw new ApiError(400, 'invalid_path', 'Invalid URL encoding.'); }
  const read = ['GET', 'HEAD'].includes(request.method);
  if (read) {
    if (path === '/healthz') return json({ status: 'ok' });
    if (path === '/readyz') {
      await env.DB.prepare('SELECT name FROM namespaces LIMIT 1').all();
      await env.BLOBS.head('readiness-probe');
      return json({ status: 'ready' });
    }
    const assets: Record<string, [string, string]> = {
      '/assets/app.css': [css, 'text/css; charset=utf-8'],
      '/assets/app.js': [js, 'text/javascript; charset=utf-8'],
      '/favicon.svg': [favicon, 'image/svg+xml'],
      '/openapi.yaml': [openapi, 'application/yaml; charset=utf-8'],
    };
    if (assets[path]) return new Response(assets[path][0], { headers: { 'Content-Type': assets[path][1], 'Cache-Control': 'public, max-age=3600' } });
    if (!path.startsWith('/v1/')) {
      const page = core().page(path);
      if (page !== undefined) return new Response(page, { headers: { 'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': core().content_security_policy(), 'Cache-Control': 'no-store' } });
      return notFound();
    }
  }
  // Treat HEAD as GET for routing/auth but suppress the response body at the boundary.
  // Blob HEAD retains its R2 metadata-only path.
  const effective = request.method === 'HEAD' && !/^\/v1\/blobs\/[^/]+$/.test(path)
    ? new Request(request, { method: 'GET' }) : request;
  if (path.startsWith('/v1/auth/') || path.startsWith('/v1/account/')) return accounts(effective, env, path);
  return registry(effective, env, path);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    let response: Response;
    try { response = await route(request, env); }
    catch (error) {
      const requestId = crypto.randomUUID();
      if (!(error instanceof ApiError)) console.error('Registry request failed', requestId, error);
      response = json({ error: { code: error instanceof ApiError ? error.code : 'internal',
        message: error instanceof ApiError ? error.message : 'Registry storage or processing is unavailable.',
        details: {}, request_id: requestId } }, error instanceof ApiError ? error.status : 500);
    }
    const headers = new Headers(response.headers);
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('Referrer-Policy', 'same-origin');
    return new Response(request.method === 'HEAD' ? null : response.body, { status: response.status, headers });
  },
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM credentials WHERE expires_at<=? AND NOT (session=0 AND expires_at=0)').bind(now()),
      env.DB.prepare('DELETE FROM auth_attempts WHERE expires_at<=?').bind(now()),
      env.DB.prepare('DELETE FROM oauth_states WHERE expires_at<=?').bind(now()),
    ]);
  },
} satisfies ExportedHandler<Env>;
