import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
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
`;

export function openDatabase(path: string): DatabaseSync {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return db;
}
