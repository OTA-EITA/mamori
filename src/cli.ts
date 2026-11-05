import { createInterface } from 'node:readline/promises';
import { loadConfig } from './config.js';
import { openDatabase } from './store/db.js';
import { UserStore } from './store/users.js';
import { AuditLog } from './audit/audit.js';
import { SecretBox } from './store/secretBox.js';
import { GroupStore } from './store/groups.js';
import { buildOtpauthUri, generateTotpSecret } from './totp/base32.js';

const USAGE = `usage:
  mamori-admin user add <email> <name>      (reads the password from stdin)
  mamori-admin user disable <email>
  mamori-admin user enable <email>
  mamori-admin user make-admin <email>      (admin pages also need a second factor)
  mamori-admin totp enroll <email>          (prints an otpauth:// URI to scan)
  mamori-admin totp remove <email>
  mamori-admin group add <name> [description]
  mamori-admin group list
  mamori-admin group members <name>
  mamori-admin group add-member <name> <email>
  mamori-admin group remove-member <name> <email>`;

async function readPassword(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: false });
  process.stderr.write('password: ');
  for await (const line of rl) {
    rl.close();
    return line;
  }
  throw new Error('no password on stdin');
}

async function main(argv: string[]): Promise<number> {
  const config = loadConfig(process.env.MAMORI_CONFIG ?? 'mamori.config.json');
  const db = openDatabase(config.database);
  const users = new UserStore(db, SecretBox.fromKeyFile(config.encryptionKeyFile));
  users.sealPlaintextSecrets();
  // CLI actions go to the audit table; the JSON line goes to the configured
  // output too, except stdout, which is for the command's own result.
  const audit = new AuditLog(db, { output: config.auditLog === '-' ? 'off' : config.auditLog });
  const cli = { type: 'cli' as const };
  const [group, command, email, ...rest] = argv;

  if (group === 'group') return groupCommand(new GroupStore(db), users, audit, command, email, rest);
  const user = email ? users.findByEmail(email) : undefined;

  if (group === 'user' && command === 'add' && email && rest.length > 0) {
    const password = await readPassword();
    if (password.length < 12) throw new Error('use a password of at least 12 characters');
    const created = await users.create({ email, name: rest.join(' '), password });
    audit.write({ event: 'user.created', actor: cli, user_id: created.id, user_email: created.email });
    console.log(`created ${created.email} (${created.id})`);
    return 0;
  }
  if (!email || !user) {
    console.error(email ? `no user ${email}` : USAGE);
    return 1;
  }
  if (group === 'user' && command === 'disable') {
    users.setDisabled(user.id, true);
    audit.write({ event: 'user.disabled', actor: cli, user_id: user.id, user_email: user.email });
    console.log(`disabled ${user.email}`);
    return 0;
  }
  if (group === 'user' && command === 'enable') {
    users.setDisabled(user.id, false);
    audit.write({ event: 'user.enabled', actor: cli, user_id: user.id, user_email: user.email });
    console.log(`enabled ${user.email}`);
    return 0;
  }
  if (group === 'user' && command === 'make-admin') {
    users.setAdmin(user.id, true);
    audit.write({ event: 'admin.granted', actor: cli, user_id: user.id, user_email: user.email });
    console.log(`${user.email} is an admin; sign in at /admin with a second factor`);
    return 0;
  }
  if (group === 'totp' && command === 'enroll') {
    const secret = generateTotpSecret();
    users.setTotpSecret(user.id, secret);
    audit.write({ event: 'totp.added', actor: cli, user_id: user.id, user_email: user.email });
    console.log(buildOtpauthUri({ issuer: config.totpIssuer, account: user.email, secret }));
    return 0;
  }
  if (group === 'totp' && command === 'remove') {
    users.setTotpSecret(user.id, null);
    audit.write({ event: 'totp.removed', actor: cli, user_id: user.id, user_email: user.email });
    console.log(`removed TOTP for ${user.email}`);
    return 0;
  }
  console.error(USAGE);
  return 1;
}

function groupCommand(groups: GroupStore, users: UserStore, audit: AuditLog, command?: string, name?: string, rest: string[] = []): number {
  const cli = { type: 'cli' as const };
  if (command === 'list') {
    for (const g of groups.list()) console.log(g.description ? `${g.name}\t${g.description}` : g.name);
    return 0;
  }
  if (!name) {
    console.error(USAGE);
    return 1;
  }
  if (command === 'add') {
    const created = groups.create(name, rest.join(' '));
    audit.write({ event: 'group.created', actor: cli, group: created.name });
    console.log(`created group ${created.name}`);
    return 0;
  }
  const g = groups.findByName(name);
  if (!g) {
    console.error(`no group ${name}`);
    return 1;
  }
  if (command === 'members') {
    for (const m of groups.members(g.id)) console.log(m.email);
    return 0;
  }
  const user = rest[0] ? users.findByEmail(rest[0]) : undefined;
  if ((command === 'add-member' || command === 'remove-member') && !user) {
    console.error(rest[0] ? `no user ${rest[0]}` : USAGE);
    return 1;
  }
  if (command === 'add-member') {
    if (groups.addMember(g.id, user!.id)) audit.write({ event: 'group.member_added', actor: cli, group: g.name, user_id: user!.id, user_email: user!.email });
    console.log(`${user!.email} is in ${g.name}`);
    return 0;
  }
  if (command === 'remove-member') {
    if (groups.removeMember(g.id, user!.id)) audit.write({ event: 'group.member_removed', actor: cli, group: g.name, user_id: user!.id, user_email: user!.email });
    console.log(`${user!.email} is not in ${g.name}`);
    return 0;
  }
  console.error(USAGE);
  return 1;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  },
);
