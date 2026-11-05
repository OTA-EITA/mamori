import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import type { UserStore } from './store/users.js';
import { interactionHandler, type InteractionOptions } from './oidc/interactions.js';
import { errorPage } from './oidc/pages.js';
import { CALLBACK_PATH } from './console/console.js';
import { PASSKEY_SCRIPT } from './passkeys/script.js';

const INTERACTION = /^\/interaction\/([\w-]+)(?:\/(login|totp|setup|continue|passkey-options|passkey))?$/;

export interface RequestHandlerOptions extends InteractionOptions {
  console?: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  scim?: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}

export function createRequestHandler(provider: Provider, users: UserStore, opts: RequestHandlerOptions = {}) {
  const interactions = interactionHandler(provider, users, opts);
  const oidc = provider.callback();
  return (req: IncomingMessage, res: ServerResponse): void => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path === '/assets/passkey.js') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=3600', 'x-content-type-options': 'nosniff' });
      res.end(PASSKEY_SCRIPT);
      return;
    }
    if (opts.scim && path.startsWith('/scim/v2/')) {
      opts.scim(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/scim+json' });
        res.end(JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '500', detail: 'Internal error.' }));
      });
      return;
    }
    if (path === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
      return;
    }
    if (opts.console && (path === '/account' || path.startsWith('/account/') || path === '/admin' || path.startsWith('/admin/') || path.startsWith('/setup/') || path === CALLBACK_PATH)) {
      opts.console(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
        res.end(errorPage('Something went wrong. Open your account page again.'));
      });
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

export function createMamoriServer(provider: Provider, users: UserStore, opts: RequestHandlerOptions = {}): Server {
  return createServer(createRequestHandler(provider, users, opts));
}
