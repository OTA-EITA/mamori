import { createInterface } from 'node:readline/promises';
import { loadConfig } from './config.js';
import { openDatabase } from './store/db.js';
import { UserStore } from './store/users.js';
import { AuditLog } from './audit/audit.js';
import { buildOtpauthUri, generateTotpSecret } from './totp/base32.js';

const USAGE = `usage:
  mamori-admin user add <email> <name>      (reads the password from stdin)
  mamori-admin user disable <email>
  mamori-admin totp enroll <email>          (prints an otpauth:// URI to scan)
  mamori-admin totp remove <email>`;

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
  const users = new UserStore(db);
  // CLI actions go to the audit table; the JSON line goes to the configured
  // output too, except stdout, which is for the command's own result.
  const audit = new AuditLog(db, { output: config.auditLog === '-' ? 'off' : config.auditLog });
  const cli = { type: 'cli' as const };
  const [group, command, email, ...rest] = argv;
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

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  },
);
