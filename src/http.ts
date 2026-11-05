import type { IncomingMessage, ServerResponse } from 'node:http';

export async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 16 * 1024) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

// Every HTML page mamori serves: no caching, no framing, no scripts.
export function send(res: ServerResponse, status: number, html: string, headers: Record<string, string | string[]> = {}): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(html);
}

export function redirect(res: ServerResponse, location: string, headers: Record<string, string | string[]> = {}): void {
  res.writeHead(303, { location, 'cache-control': 'no-store', ...headers });
  res.end();
}

export function readCookie(req: IncomingMessage, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return undefined;
}

export function cookie(name: string, value: string, opts: { secure: boolean; maxAge?: number; path?: string }): string {
  const attrs = [`${name}=${value}`, `Path=${opts.path ?? '/'}`, 'HttpOnly', 'SameSite=Lax'];
  if (opts.secure) attrs.push('Secure');
  if (opts.maxAge !== undefined) attrs.push(`Max-Age=${opts.maxAge}`);
  return attrs.join('; ');
}
