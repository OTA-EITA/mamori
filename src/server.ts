import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import type { UserStore } from './store/users.js';
import { interactionHandler } from './oidc/interactions.js';
import { errorPage } from './oidc/pages.js';

const INTERACTION = /^\/interaction\/([\w-]+)(?:\/(login|totp))?$/;

export function createRequestHandler(provider: Provider, users: UserStore, now?: () => number) {
  const interactions = interactionHandler(provider, users, now);
  const oidc = provider.callback();
  return (req: IncomingMessage, res: ServerResponse): void => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
      return;
    }
    const match = INTERACTION.exec(path);
    if (!match) {
      oidc(req, res);
      return;
    }
    interactions(req, res, match[1]!, match[2]).catch((err: unknown) => {
      const message =
        err instanceof Error && err.name === 'SessionNotFound'
          ? 'This sign-in has expired. Start again from the app.'
          : 'Something went wrong. Start again from the app.';
      if (!res.headersSent) res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
      res.end(errorPage(message));
    });
  };
}

export function createMamoriServer(provider: Provider, users: UserStore, now?: () => number): Server {
  return createServer(createRequestHandler(provider, users, now));
}
