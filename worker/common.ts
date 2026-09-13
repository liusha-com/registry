export interface Env {
  DB: D1Database;
  BLOBS: R2Bucket;
  PUBLIC_READ: string;
  REGISTRATION_ENABLED: string;
  MAX_BLOB_BYTES: string;
  MAX_ANALYSIS_BYTES: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
}
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
export function fail(status: number, code: string, message: string): never {
  throw new ApiError(status, code, message);
}
export function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(value, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}
export const now = () => Math.floor(Date.now() / 1000);
export const iso = () => new Date().toISOString();
export const utf8 = (value: string) => new TextEncoder().encode(value);
export const hex = (bytes: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
export const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
export async function hash(value: string | Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? utf8(value) : value));
}
export function name(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(value))
    fail(400, 'invalid_name', 'Names must contain 1–64 lowercase letters, digits, dots, underscores or hyphens, with alphanumeric edges.');
}
export function digest(value: string): void {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) fail(400, 'invalid_digest', 'Expected sha256: followed by 64 lowercase hex digits.');
}
export function limit(value: string, maximum: number): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1 || n > maximum) fail(500, 'invalid_configuration', 'Invalid configured size limit.');
  return n;
}
export async function body(request: Request, maximum: number): Promise<Uint8Array> {
  const length = request.headers.get('content-length');
  if (length && Number(length) > maximum) fail(413, 'limit_exceeded', 'Request body exceeds the size limit.');
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        fail(413, 'limit_exceeded', 'Request body exceeds the size limit.');
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
export async function object(request: Request, maximum = 8192): Promise<Record<string, unknown>> {
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json')
    fail(415, 'json_required', 'Send an application/json request.');
  const bytes = await body(request, maximum);
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch { /* Stable client error below. */ }
  return fail(400, 'invalid_json', 'Expected a JSON object.');
}
export function origin(request: Request): void {
  const origin = request.headers.get('origin');
  if (origin && origin !== new URL(request.url).origin)
    fail(403, 'origin_rejected', 'This request came from a different origin.');
}
export function unique(error: unknown): boolean { return /UNIQUE constraint failed/.test(String(error)); }
export function notFound(): never { return fail(404, 'not_found', 'Resource not found.'); }
