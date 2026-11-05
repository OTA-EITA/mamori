import { loadConfig } from './config.js';
import { createProvider } from './oidc/provider.js';
import { createMamoriServer } from './server.js';
import { openDatabase } from './store/db.js';
import { deleteExpired } from './store/oidcAdapter.js';
import { UserStore } from './store/users.js';
import { AuditLog } from './audit/audit.js';

const config = loadConfig(process.env.MAMORI_CONFIG ?? 'mamori.config.json');
const db = openDatabase(config.database);
const users = new UserStore(db);
const audit = new AuditLog(db, { output: config.auditLog });
const provider = createProvider(config, db, users, audit);

setInterval(() => {
  deleteExpired(db);
  audit.purge(config.auditRetentionDays);
}, 60 * 60 * 1000).unref();

createMamoriServer(provider, users, { audit, trustProxy: config.trustProxy ?? false }).listen(config.port, () => {
  console.log(`mamori listening on :${config.port}, issuer ${config.issuer}`);
});
