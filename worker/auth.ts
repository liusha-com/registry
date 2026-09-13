import { core } from './core';
import { githubAuth } from './github';
import { workspace } from './workspace';
import { type Env, fail, hash, random, now, utf8, json, object, origin, unique, notFound } from './common';

interface Identity {
  hash: string;
  id: string;
  username: string;
  session: number;
  secret: string;
}
const DAY = 86400;
const DUMMY_HASH = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRmb3JkdW1teQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const csrf = (secret: string) => hash(`registry-csrf:${secret}`);
export const cookie = (request: Request, secret: string, lifetime: number) =>
  `registry_session=${secret}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${lifetime}${new URL(request.url).protocol === 'https:' ? '; Secure' : ''}`;

export async function identify(request: Request, env: Env, mutation = false): Promise<Identity> {
  const authorization = request.headers.get('authorization');
  const session = authorization === null;
  const secret = session
    ? request.headers.get('cookie')?.split(';').map(s => s.trim()).find(s => s.startsWith('registry_session='))?.slice(17)
    : authorization?.match(/^Bearer (\S+)$/)?.[1];
  if (!secret) fail(401, 'unauthorized', 'Sign in to continue.');
  const digest = await hash(secret);
  const identity = await env.DB.prepare('SELECT hash,id,username,session FROM credentials WHERE hash=? AND (expires_at>? OR (session=0 AND expires_at=0))')
    .bind(digest, now()).first<Omit<Identity, 'secret'>>();
  if (!identity || Boolean(identity.session) !== session) fail(401, 'unauthorized', 'Sign in to continue.');
  if (session && mutation) {
    origin(request);
    if (request.headers.get('x-csrf-token') !== await csrf(secret))
      fail(403, 'csrf_required', 'Refresh the page and retry this action.');
  }
  return { ...identity, secret };
}

export async function requireRead(request: Request, env: Env): Promise<void> {
  if (env.PUBLIC_READ !== 'true') await identify(request, env);
}

export async function owner(request: Request, env: Env, namespace: string): Promise<Identity> {
  const identity = await identify(request, env, true);
  const row = await env.DB.prepare('SELECT owner_username FROM namespaces WHERE name=?').bind(namespace).first<{owner_username: string}>();
  if (!row) notFound();
  if (row.owner_username !== identity.username) fail(403, 'forbidden', 'You do not own this namespace.');
  return identity;
}

export async function issue(env: Env, username: string, label: string, session: boolean, tokenLifetime: number | null = 90 * DAY) {
  const secret = `${session ? 'wrs_' : 'wrt_'}${random()}`;
  const id = `${session ? 'ses_' : 'pat_'}${random().slice(0, 24)}`;
  const lifetime = session ? DAY : tokenLifetime;
  const createdAt = now();
  // Zero is reserved for non-expiring personal tokens; sessions always expire.
  const expiresAt = lifetime === null ? 0 : createdAt + lifetime;
  // A single conditional INSERT keeps the credential cap safe under concurrent requests.
  const result = await env.DB.prepare(`INSERT INTO credentials(hash,id,username,name,session,created_at,expires_at)
    SELECT ?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM credentials WHERE username=? AND (expires_at>? OR (session=0 AND expires_at=0))) < 30`)
    .bind(await hash(secret), id, username, label, Number(session), createdAt, expiresAt, username, createdAt).run();
  if (!result.meta.changes) fail(429, 'credential_limit', 'Revoke an existing token or session before creating another.');
  return { secret, id, lifetime, expiresAt: expiresAt || null };
}

export async function throttle(env: Env, key: string, maximum: number) {
  const time = now();
  const result = await env.DB.prepare(`INSERT INTO auth_attempts(key,count,expires_at) VALUES (?,1,?)
    ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires_at<=? THEN 1 ELSE count+1 END,
    expires_at=CASE WHEN expires_at<=? THEN ? ELSE expires_at END RETURNING count`)
    .bind(await hash(key), time + 900, time, time, time + 900).first<{count: number}>();
  if (!result || result.count > maximum) fail(429, 'rate_limited', 'Too many attempts. Try again in 15 minutes.');
}

export async function accounts(request: Request, env: Env, path: string): Promise<Response> {
  const method = request.method;
  if (!['GET', 'HEAD'].includes(method)) origin(request);
  if (method === 'GET' && path === '/v1/auth/providers') return json({ email_password: true,
    github: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET), registration: env.REGISTRATION_ENABLED === 'true' });
  if (path === '/v1/auth/github' || path === '/v1/auth/github/callback') return githubAuth(request, env, path);
  if (method === 'POST' && ['/v1/auth/register', '/v1/auth/login'].includes(path)) {
    const register = path.endsWith('/register');
    if (register && env.REGISTRATION_ENABLED !== 'true') fail(403, 'registration_disabled', 'Registration is disabled.');
    const input = await object(request);
    const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
    if ('username' in input) fail(400, 'email_required', 'Use an email address to register or sign in.');
    const password = typeof input.password === 'string' ? input.password : '';
    if (email.length > 254 || !/^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/.test(email))
      fail(400, 'invalid_email', 'Enter a valid email address.');
    if ([...password].length < 12 || utf8(password).length > 128) fail(400, 'invalid_password', 'Use at least 12 characters and no more than 128 UTF-8 bytes.');
    await throttle(env, `ip:${request.headers.get('cf-connecting-ip') || 'local'}`, 40);
    const stored = await env.DB.prepare('SELECT username,password FROM users WHERE email=? COLLATE NOCASE')
      .bind(email).first<{username: string; password: string}>();
    await throttle(env, `user:${email}`, 8);
    let username = `u-${random().slice(0, 24)}`;
    if (register) {
      if (stored) fail(409, 'email_unavailable', 'This email is already in use.');
      const encoded = core().password_hash(password, crypto.getRandomValues(new Uint8Array(32)));
      try {
        await env.DB.prepare('INSERT INTO users(username,password,created_at,email) VALUES (?,?,?,?)').bind(username, encoded, now(), email || null).run();
      } catch (error) {
        if (unique(error)) fail(409, 'account_unavailable', 'This email is already in use.');
        throw error;
      }
    } else {
      const valid = core().password_verify(password, stored?.password || DUMMY_HASH);
      if (!stored || !valid) fail(401, 'invalid_credentials', 'Email or password is incorrect.');
      username = stored.username;
    }
    const token = await issue(env, username, 'Browser session', true);
    await env.DB.prepare('DELETE FROM auth_attempts WHERE key=?').bind(await hash(`user:${email}`)).run();
    return json({ user: { username, email }, csrf_token: await csrf(token.secret), expires_in: token.lifetime }, register ? 201 : 200,
      { 'Set-Cookie': cookie(request, token.secret, DAY) });
  }
  const identity = await identify(request, env, !['GET', 'HEAD'].includes(method));
  if (method === 'GET' && (path === '/v1/account/namespaces' || /^\/v1\/account\/namespaces\/[^/]+\/packages$/.test(path)))
    return workspace(request, env, path, identity.username);
  if (method === 'GET' && path === '/v1/auth/check')
    return json({ authenticated: true, token_id: identity.id, namespace: null, scopes: ['namespace:create', 'package:publish', 'package:read', 'package:yank'] });
  if (method === 'GET' && path === '/v1/auth/me') {
    const user = await env.DB.prepare('SELECT username,email,created_at FROM users WHERE username=?').bind(identity.username).first();
    return json({ user, csrf_token: identity.session ? await csrf(identity.secret) : null });
  }
  if (method === 'POST' && path === '/v1/auth/logout') {
    await object(request);
    await env.DB.prepare('DELETE FROM credentials WHERE hash=?').bind(identity.hash).run();
    return json({ signed_out: true }, 200, { 'Set-Cookie': cookie(request, '', 0) });
  }
  if (path === '/v1/account/tokens') {
    if (method === 'GET') {
      const rows = await env.DB.prepare('SELECT id,name,created_at,NULLIF(expires_at,0) AS expires_at FROM credentials WHERE username=? AND session=0 AND (expires_at>? OR expires_at=0) ORDER BY created_at DESC,id')
        .bind(identity.username, now()).all();
      return json({ tokens: rows.results });
    }
    if (method === 'POST') {
      if (!identity.session) fail(403, 'session_required', 'Sign in with a browser to manage tokens.');
      const input = await object(request), label = typeof input.name === 'string' ? input.name.trim() : '';
      if (!label || utf8(label).length > 64) fail(400, 'invalid_token_name', 'Enter a token name of 1–64 bytes.');
      const lifetime = input.expires_in === undefined ? 90 * DAY : input.expires_in;
      if (lifetime !== null && (typeof lifetime !== 'number' || !Number.isInteger(lifetime) || lifetime < 1 || lifetime > 3650 * DAY))
        fail(400, 'invalid_token_expiry', 'Use an expiry of 1–315360000 seconds, or null for no expiration.');
      const token = await issue(env, identity.username, label, false, lifetime as number | null);
      return json({ id: token.id, token: token.secret, expires_in: token.lifetime, expires_at: token.expiresAt }, 201);
    }
  }
  if (method === 'DELETE' && /^\/v1\/account\/tokens\/[^/]+$/.test(path)) {
    if (!identity.session) fail(403, 'session_required', 'Sign in with a browser to manage tokens.');
    const result = await env.DB.prepare('DELETE FROM credentials WHERE id=? AND username=? AND session=0')
      .bind(path.split('/').at(-1), identity.username).run();
    if (!result.meta.changes) notFound();
    return json({ revoked: true });
  }
  return notFound();
}
