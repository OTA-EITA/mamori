import { DatabaseSync } from 'node:sqlite';

// Each entry upgrades the schema by one version. Never edit an entry that has
// been released; add a new one instead.
const MIGRATIONS: string[] = [
  // 1: the v0.1 tables (created with IF NOT EXISTS, so v0.1 databases keep
  // their data), plus the account on OIDC models so a user's sessions and
  // grants can be revoked together, and admin and last sign-in on users.
  `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    totp_last_counter INTEGER,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS oidc_models (
    model TEXT NOT NULL,
    id TEXT NOT NULL,
    payload TEXT NOT NULL,
    grant_id TEXT,
    user_code TEXT,
    uid TEXT,
    expires_at INTEGER,
    consumed_at INTEGER,
    PRIMARY KEY (model, id)
  );
  CREATE INDEX IF NOT EXISTS oidc_models_grant_id ON oidc_models (grant_id);
  CREATE INDEX IF NOT EXISTS oidc_models_uid ON oidc_models (model, uid);
  CREATE INDEX IF NOT EXISTS oidc_models_user_code ON oidc_models (model, user_code);

  ALTER TABLE oidc_models ADD COLUMN account_id TEXT;
  CREATE INDEX oidc_models_account_id ON oidc_models (account_id);
  UPDATE oidc_models SET account_id = json_extract(payload, '$.accountId');
  ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE users ADD COLUMN last_sign_in_at TEXT;
  `,
  // 2: the audit log. The full event is kept as JSON; the columns are for filtering.
  `
  CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    event TEXT NOT NULL,
    actor_id TEXT,
    actor_email TEXT,
    data TEXT NOT NULL
  );
  CREATE INDEX audit_events_time ON audit_events (time);
  CREATE INDEX audit_events_event ON audit_events (event, time);
  CREATE INDEX audit_events_actor ON audit_events (actor_id, time);
  `,
];

export const SCHEMA_VERSION = MIGRATIONS.length;

function tableExists(db: DatabaseSync, name: string): boolean {
  return db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined;
}

export function openDatabase(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

  const current = Number((db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version);
  if (current > SCHEMA_VERSION) {
    db.close();
    throw new Error(`${path} has schema version ${current}, newer than this mamori (${SCHEMA_VERSION}). Upgrade mamori.`);
  }
  // A database with v0.1 tables but no version was created by v0.1.
  const createdByV01 = current === 0 && tableExists(db, 'users');

  for (let version = current; version < SCHEMA_VERSION; version++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[version]!);
      db.exec(`PRAGMA user_version = ${version + 1}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
  if (current === 0) {
    db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run('created_by', createdByV01 ? 'v0.1' : 'v0.2');
  }
  return db;
}
