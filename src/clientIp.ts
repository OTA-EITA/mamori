import type { IncomingMessage } from 'node:http';

// The address the request came from. Behind a trusted proxy this is the last
// entry of X-Forwarded-For, the one the proxy appended: entries further left
// were sent by the client and can be anything.
export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  const socket = req.socket.remoteAddress ?? 'unknown';
  if (!trustProxy) return socket;
  const header = req.headers['x-forwarded-for'];
  const value = Array.isArray(header) ? header.join(',') : header;
  const last = value?.split(',').map((s) => s.trim()).filter(Boolean).at(-1);
  return last ?? socket;
}
