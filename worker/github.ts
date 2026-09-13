import { cookie, issue, throttle } from './auth';
import { type Env, ApiError, fail, hash, now, random, unique, notFound } from './common';

const stateCookie = (request: Request, value: string, age: number) =>
  `registry_oauth=${value}; Path=/v1/auth/github; HttpOnly; SameSite=Lax; Max-Age=${age}${new URL(request.url).protocol === 'https:' ? '; Secure' : ''}`;
const redirect = (location: string, cookies: string[] = []) => {
  const headers = new Headers({ Location: location, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  for (const value of cookies) headers.append('Set-Cookie', value);
  return new Response(null, { status: 303, headers });
};
async function githubJson(url: string, init: RequestInit): Promise<any> {
  try {
    const response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(10000) });
    if (!response.ok) return fail(502, 'github_unavailable', 'GitHub sign-in is temporarily unavailable.');
    return await response.json();
  } catch { return fail(502, 'github_unavailable', 'GitHub sign-in is temporarily unavailable.'); }
}

export async function githubAuth(request: Request, env: Env, path: string): Promise<Response> {
  if (request.method !== 'GET') return notFound();
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET)
    return redirect('/login?oauth_error=not_configured');
  const url = new URL(request.url);
  if (path === '/v1/auth/github') {
    await throttle(env, `github:${request.headers.get('cf-connecting-ip') || 'local'}`, 40);
    const state = random(), browser = random(), verifier = random();
    const redirectUri = `${url.origin}/v1/auth/github/callback`;
    await env.DB.prepare('INSERT INTO oauth_states(state_hash,browser_hash,verifier,redirect_uri,expires_at) VALUES (?,?,?,?,?)')
      .bind(await hash(state), await hash(browser), verifier, redirectUri, now() + 600).run();
    const challenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const target = new URL('https://github.com/login/oauth/authorize');
    target.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: redirectUri,
      scope: 'read:user', state, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
    return redirect(target.href, [stateCookie(request, browser, 600)]);
  }
  try {
    const state = url.searchParams.get('state') || '';
    const browser = request.headers.get('cookie')?.split(';').map(v => v.trim()).find(v => v.startsWith('registry_oauth='))?.slice(15) || '';
    if (!/^[a-f0-9]{64}$/.test(state) || !/^[a-f0-9]{64}$/.test(browser)) fail(400, 'invalid_state', 'Restart GitHub sign-in.');
    // Consume once, only for the browser that started this flow. Concurrent and
    // replayed callbacks cannot exchange the same authorization code twice.
    const flow = await env.DB.prepare(`DELETE FROM oauth_states WHERE state_hash=? AND browser_hash=? AND expires_at>? AND redirect_uri=?
      RETURNING verifier,redirect_uri`).bind(await hash(state), await hash(browser), now(), `${url.origin}/v1/auth/github/callback`)
      .first<{verifier: string; redirect_uri: string}>();
    if (!flow) fail(400, 'invalid_state', 'Restart GitHub sign-in.');
    if (url.searchParams.has('error')) fail(400, 'denied', 'GitHub sign-in was cancelled.');
    const code = url.searchParams.get('code');
    if (!code || code.length > 512) fail(400, 'invalid_state', 'Restart GitHub sign-in.');
    const token = await githubJson('https://github.com/login/oauth/access_token', { method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
        code, redirect_uri: flow.redirect_uri, code_verifier: flow.verifier }).toString() });
    if (typeof token.access_token !== 'string' || token.token_type?.toLowerCase() !== 'bearer')
      fail(502, 'github_unavailable', 'GitHub sign-in failed.');
    const profile = await githubJson('https://api.github.com/user', { headers: {
      Accept: 'application/vnd.github+json', Authorization: `Bearer ${token.access_token}`, 'User-Agent': 'Wasmd-Registry',
    } });
    if (!Number.isSafeInteger(profile.id) || profile.id <= 0 || typeof profile.login !== 'string')
      fail(502, 'github_unavailable', 'GitHub returned an invalid profile.');
    const subject = String(profile.id);
    const find = () => env.DB.prepare("SELECT username FROM oauth_identities WHERE provider='github' AND subject=?")
      .bind(subject).first<{username: string}>();
    let identity = await find();
    if (!identity) {
      if (env.REGISTRATION_ENABLED !== 'true') fail(403, 'registration_disabled', 'Registration is disabled.');
      // Never merge accounts by a mutable GitHub handle or an unverified email.
      const username = `gh-${profile.login.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 16)}-${random().slice(0, 8)}`;
      try {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users(username,password,created_at) VALUES (?,?,?)').bind(username, '!github-only', now()),
          env.DB.prepare("INSERT INTO oauth_identities(provider,subject,username) VALUES ('github',?,?)").bind(subject, username),
        ]);
        identity = { username };
      } catch (error) {
        if (!unique(error)) throw error;
        identity = await find();
        if (!identity) throw error;
      }
    }
    const session = await issue(env, identity.username, 'GitHub browser session', true);
    return redirect('/account', [cookie(request, session.secret, 86400), stateCookie(request, '', 0)]);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : 'unavailable';
    return redirect(`/login?oauth_error=${encodeURIComponent(code)}`, [stateCookie(request, '', 0)]);
  }
}
