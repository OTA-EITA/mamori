import { loadConfig, resolveMfaPolicy } from './config.js';
import { createProvider } from './oidc/provider.js';
import { createMamoriServer } from './server.js';
import { openDatabase } from './store/db.js';
import { deleteExpired } from './store/oidcAdapter.js';
import { UserStore } from './store/users.js';
import { AuditLog } from './audit/audit.js';
import { SecretBox } from './store/secretBox.js';
import { GroupStore } from './store/groups.js';
import { consoleHandler } from './console/console.js';
import { RecoveryCodes } from './console/recovery.js';
import { ConsoleSessions } from './console/sessions.js';

const config = loadConfig(process.env.MAMORI_CONFIG ?? 'mamori.config.json');
const db = openDatabase(config.database);
const box = SecretBox.fromKeyFile(config.encryptionKeyFile);
const users = new UserStore(db, box);
const sealed = users.sealPlaintextSecrets();
if (sealed > 0) console.log(`sealed ${sealed} TOTP secret(s) stored as plain text by an older version`);
const audit = new AuditLog(db, { output: config.auditLog });
const provider = createProvider(config, db, users, audit, new GroupStore(db));

const now = () => Math.floor(Date.now() / 1000);
const sessions = new ConsoleSessions(db, box, now);
const recovery = new RecoveryCodes(db);
const trustProxy = config.trustProxy ?? false;
const createdBy = (db.prepare("SELECT value FROM settings WHERE key = 'created_by'").get() as { value: string } | undefined)?.value;
const mfa = resolveMfaPolicy(config, createdBy);
if (mfa.warning) console.warn(mfa.warning);
const account = consoleHandler({ provider, users, sessions, recovery, audit, trustProxy, issuer: config.issuer, totpIssuer: config.totpIssuer });

setInterval(() => {
  deleteExpired(db);
  sessions.deleteExpired();
  audit.purge(config.auditRetentionDays);
}, 60 * 60 * 1000).unref();

createMamoriServer(provider, users, { audit, recovery, trustProxy, console: account, mfaPolicy: () => mfa.policy, totpIssuer: config.totpIssuer }).listen(config.port, () => {
  console.log(`mamori listening on :${config.port}, issuer ${config.issuer}`);
});
