import type { AuditRecord } from '../audit/audit.js';

const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${escape(csrf)}">`;
const day = (iso: string | null) => (iso ? iso.slice(0, 16).replace('T', ' ') : '—');

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)} · mamori admin</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; }
  header { background: #202124; color: #fff; padding: .8rem 1.5rem; display: flex; gap: 1.5rem; align-items: center; }
  header a { color: #fff; text-decoration: none; }
  main { max-width: 60rem; margin: 2rem auto; background: #fff; padding: 2rem; border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: .92rem; }
  th, td { text-align: left; padding: .5rem; border-bottom: 1px solid #e3e5e8; vertical-align: top; }
  form.inline { display: inline; }
  input, select { padding: .45rem; font-size: .95rem; }
  button { padding: .45rem .9rem; font-size: .95rem; }
  .muted { color: #5f6368; }
  .error { color: #b00020; }
  .notice { background: #e8f0fe; padding: .7rem 1rem; border-radius: 6px; }
  .tag { display: inline-block; background: #e8eaed; border-radius: 4px; padding: 0 .4rem; margin-right: .3rem; font-size: .85rem; }
  .danger { color: #b00020; }
  code { font-family: ui-monospace, monospace; word-break: break-all; }
</style>
</head>
<body>
<header><strong>mamori admin</strong><a href="/admin/users">Users</a><a href="/admin/groups">Groups</a><a href="/admin/audit">Audit log</a><a href="/admin/provisioning">Provisioning</a><a href="/account">Your account</a></header>
<main>${body}</main>
</body>
</html>`;
}

const messages = (v: { notice?: string | undefined; error?: string | undefined }) =>
  `${v.notice ? `<p class="notice">${escape(v.notice)}</p>` : ''}${v.error ? `<p class="error">${escape(v.error)}</p>` : ''}`;

export interface UserRowView {
  id: string;
  email: string;
  name: string;
  disabled: boolean;
  isAdmin: boolean;
  hasTotp: boolean;
  passkeys: number;
  lastSignInAt: string | null;
}

function methods(u: UserRowView): string {
  const tags = [u.hasTotp ? 'TOTP' : '', u.passkeys ? `${u.passkeys} passkey${u.passkeys > 1 ? 's' : ''}` : ''].filter(Boolean);
  return tags.length ? tags.map((t) => `<span class="tag">${t}</span>`).join('') : '<span class="muted">none</span>';
}

export function adminUsersPage(v: { users: UserRowView[]; query: string; csrf: string; notice?: string; error?: string }): string {
  const rows = v.users
    .map(
      (u) => `<tr>
<td><a href="/admin/users/${escape(u.id)}">${escape(u.email)}</a>${u.isAdmin ? ' <span class="tag">admin</span>' : ''}</td>
<td>${escape(u.name)}</td>
<td>${u.disabled ? '<span class="danger">disabled</span>' : 'active'}</td>
<td>${methods(u)}</td>
<td>${day(u.lastSignInAt)}</td>
</tr>`,
    )
    .join('');
  return page(
    'Users',
    `<h1>Users</h1>
${messages(v)}
<p><a href="/admin/users/new">Add a user</a></p>
<form method="get" action="/admin/users"><input name="q" value="${escape(v.query)}" placeholder="Search by email or name"> <button type="submit">Search</button></form>
<table><thead><tr><th>Email</th><th>Name</th><th>Status</th><th>Second factors</th><th>Last sign-in</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">No users.</td></tr>'}</tbody></table>`,
  );
}

export function adminUserPage(v: {
  user: UserRowView;
  self: boolean;
  groups: string[];
  passkeys: { name: string; createdAt: string; lastUsedAt: string | null }[];
  events: AuditRecord[];
  csrf: string;
  notice?: string;
  error?: string;
}): string {
  const u = v.user;
  const action = (path: string, label: string, confirm = '') =>
    `<form class="inline" method="post" action="/admin/users/${escape(u.id)}/${path}">${csrfField(v.csrf)}<button type="submit"${confirm ? ` title="${escape(confirm)}"` : ''}>${escape(label)}</button></form>`;
  const actions = v.self
    ? '<p class="muted">This is you. Change your own second factors on <a href="/account">your account page</a>.</p>'
    : `<p>
${u.disabled ? action('enable', 'Enable') : action('disable', 'Disable and sign out everywhere')}
${action('reset-mfa', 'Reset second factors', 'Removes TOTP, passkeys and recovery codes, and signs the user out')}
${u.isAdmin ? action('revoke-admin', 'Remove admin') : action('grant-admin', 'Make admin')}
${action('setup-link', 'New setup link (forgotten password)')}
</p>`;
  const events = v.events
    .map((e) => `<tr><td>${day(e.time)}</td><td><code>${escape(e.event)}</code></td><td>${escape(String(e.ip ?? ''))}</td><td>${escape(String(e.client_id ?? ''))}</td></tr>`)
    .join('');
  return page(
    u.email,
    `<h1>${escape(u.name)}</h1>
<p class="muted">${escape(u.email)} · ${u.disabled ? '<span class="danger">disabled</span>' : 'active'}${u.isAdmin ? ' · admin' : ''} · last sign-in ${day(u.lastSignInAt)}</p>
${messages(v)}
${actions}
<h2>Second factors</h2><p>${methods(u)}</p>
${v.passkeys.length ? `<ul>${v.passkeys.map((p) => `<li>${escape(p.name)} <span class="muted">added ${day(p.createdAt)}, last used ${day(p.lastUsedAt)}</span></li>`).join('')}</ul>` : ''}
<h2>Groups</h2><p>${v.groups.length ? v.groups.map((g) => `<span class="tag">${escape(g)}</span>`).join('') : '<span class="muted">none</span>'}</p>
<h2>Recent activity</h2>
<table><thead><tr><th>Time (UTC)</th><th>Event</th><th>IP</th><th>App</th></tr></thead><tbody>${events || '<tr><td colspan="4" class="muted">Nothing yet.</td></tr>'}</tbody></table>`,
  );
}

export function adminDeniedPage(reason: 'not_admin' | 'needs_mfa', csrf: string): string {
  const text =
    reason === 'not_admin'
      ? 'Your account is not an administrator.'
      : 'Admin pages need a sign-in with two-step verification. Sign out, then sign in again with your authenticator app or a passkey. If you have neither, set one up on your account page first.';
  return page(
    'Not allowed',
    `<h1>Not allowed</h1><p>${escape(text)}</p>
<form method="post" action="/account/logout">${csrfField(csrf)}<button type="submit">Sign out</button></form>`,
  );
}

export function adminNewUserPage(v: { csrf: string; email?: string; name?: string; error?: string }): string {
  return page(
    'Add a user',
    `<h1>Add a user</h1>
${messages(v)}
<p class="muted">You do not set a password. mamori makes a setup link for you to pass to the person; with it they choose a password and set up two-step verification.</p>
<form method="post" action="/admin/users/new">${csrfField(v.csrf)}
  <p><label>Email<br><input type="email" name="email" required value="${escape(v.email ?? '')}"></label></p>
  <p><label>Name<br><input name="name" required value="${escape(v.name ?? '')}"></label></p>
  <button type="submit">Add and make a setup link</button>
</form>`,
  );
}

export function adminSetupLinkPage(v: { email: string; link: string; userId: string; created: boolean }): string {
  return page(
    'Setup link',
    `<h1>${v.created ? 'User added' : 'New setup link'}</h1>
<p class="notice">Send this link to ${escape(v.email)}, for example in a direct message. It works once, for 24 hours, and is shown only now.${v.created ? '' : ' Their earlier links and sessions no longer work.'}</p>
<p><code>${escape(v.link)}</code></p>
<p><a href="/admin/users/${escape(v.userId)}">Back to the user</a></p>`,
  );
}

export function adminGroupsPage(v: { groups: { name: string; description: string; members: number }[]; csrf: string; notice?: string; error?: string }): string {
  const rows = v.groups
    .map((g) => `<tr><td><a href="/admin/groups/${encodeURIComponent(g.name)}">${escape(g.name)}</a></td><td>${escape(g.description)}</td><td>${g.members}</td></tr>`)
    .join('');
  return page(
    'Groups',
    `<h1>Groups</h1>
${messages(v)}
<p class="muted">Apps that ask for the <code>groups</code> scope see these names in the <code>groups</code> claim, so choose names you will not need to change.</p>
<table><thead><tr><th>Name</th><th>Description</th><th>Members</th></tr></thead><tbody>${rows || '<tr><td colspan="3" class="muted">No groups yet.</td></tr>'}</tbody></table>
<h2>Add a group</h2>
<form method="post" action="/admin/groups">${csrfField(v.csrf)}
  <input name="name" required pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" placeholder="engineering">
  <input name="description" placeholder="Description (optional)">
  <button type="submit">Add</button>
</form>`,
  );
}

export function adminGroupPage(v: { name: string; description: string; members: { id: string; email: string; name: string }[]; csrf: string; notice?: string; error?: string }): string {
  const base = `/admin/groups/${encodeURIComponent(v.name)}`;
  const rows = v.members
    .map(
      (m) => `<tr><td><a href="/admin/users/${escape(m.id)}">${escape(m.email)}</a></td><td>${escape(m.name)}</td>
<td><form class="inline" method="post" action="${base}/remove">${csrfField(v.csrf)}<input type="hidden" name="email" value="${escape(m.email)}"><button type="submit">Remove</button></form></td></tr>`,
    )
    .join('');
  return page(
    v.name,
    `<h1>${escape(v.name)}</h1>
<p class="muted">${escape(v.description)}</p>
${messages(v)}
<table><thead><tr><th>Member</th><th>Name</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="3" class="muted">No members.</td></tr>'}</tbody></table>
<h2>Add a member</h2>
<form method="post" action="${base}/add">${csrfField(v.csrf)}<input type="email" name="email" required placeholder="someone@example.co.jp"> <button type="submit">Add</button></form>
<p><a href="/admin/groups">All groups</a></p>`,
  );
}

export function adminAuditPage(v: { events: AuditRecord[]; filter: { event: string; user: string; since: string; until: string } }): string {
  const f = v.filter;
  const who = (e: AuditRecord) => escape(e.actor?.email ?? (e.actor?.type === 'cli' ? 'CLI' : (e.actor?.id ?? '')));
  const rows = v.events
    .map(
      (e) => `<tr><td>${day(e.time)}</td><td><code>${escape(e.event)}</code></td><td>${who(e)}</td><td>${escape(String(e.user_email ?? ''))}</td><td>${escape(String(e.reason ?? e.method ?? ''))}</td><td>${escape(String(e.ip ?? ''))}</td><td>${escape(String(e.client_id ?? ''))}</td></tr>`,
    )
    .join('');
  return page(
    'Audit log',
    `<h1>Audit log</h1>
<form method="get" action="/admin/audit">
  <input name="event" value="${escape(f.event)}" placeholder="Event, e.g. sign_in.failed">
  <input name="user" value="${escape(f.user)}" placeholder="Email">
  <input type="date" name="since" value="${escape(f.since)}"> to <input type="date" name="until" value="${escape(f.until)}">
  <button type="submit">Filter</button>
</form>
<p class="muted">Newest first, up to 200 events. Times are UTC. The same events go to the audit log output as JSON lines.</p>
<table><thead><tr><th>Time</th><th>Event</th><th>Who</th><th>About</th><th>Detail</th><th>IP</th><th>App</th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="muted">No events.</td></tr>'}</tbody></table>`,
  );
}

export function adminProvisioningPage(v: {
  connectors: { name: string; group: string }[];
  jobs: { connector: string; userId: string; email: string | undefined; attempts: number; lastError: string | null; failed: boolean; nextAt: number }[];
}): string {
  const connectors = v.connectors.length
    ? `<table><thead><tr><th>Connector</th><th>Accounts for active members of</th></tr></thead><tbody>${v.connectors
        .map((c) => `<tr><td>${escape(c.name)}</td><td><a href="/admin/groups/${encodeURIComponent(c.group)}">${escape(c.group)}</a></td></tr>`)
        .join('')}</tbody></table>`
    : '<p class="muted">No connectors are configured. Add them under "connectors" in the config file.</p>';
  const rows = v.jobs
    .map(
      (j) => `<tr><td>${escape(j.connector)}</td><td><a href="/admin/users/${escape(j.userId)}">${escape(j.email ?? j.userId)}</a></td>
<td>${j.failed ? '<span class="danger">gave up</span>' : j.attempts ? `retrying (${j.attempts})` : 'waiting'}</td>
<td>${j.failed ? '—' : new Date(j.nextAt * 1000).toISOString().slice(0, 16).replace('T', ' ')}</td><td>${escape(j.lastError ?? '')}</td></tr>`,
    )
    .join('');
  return page(
    'Provisioning',
    `<h1>Provisioning</h1>
${connectors}
<h2>Pending and failed</h2>
<p class="muted">Changes are sent in the background and retried for up to a day. Run <code>mamori-admin provision reconcile &lt;connector&gt;</code> to compare with the service.</p>
<table><thead><tr><th>Connector</th><th>User</th><th>State</th><th>Next try (UTC)</th><th>Last error</th></tr></thead><tbody>${rows || '<tr><td colspan="5" class="muted">Nothing pending.</td></tr>'}</tbody></table>`,
  );
}
