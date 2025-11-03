import path from 'path';
import Database from 'better-sqlite3';
import { dataDir } from '../utils/paths.js';
import { ensureDirSync } from '../utils/fs.js';
import { encryptSecret, decryptSecret } from '../utils/secrets.js';

const effectiveDataDir = process.env.GATE_DATA_DIR
  ? path.resolve(process.env.GATE_DATA_DIR)
  : dataDir;

const DB_FILE = path.join(effectiveDataDir, 'app.db');

export class ConfigStore {
  constructor() {
    ensureDirSync(dataDir);
    this.db = new Database(DB_FILE);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS secrets (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS resources (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        target_url TEXT NOT NULL,
        icon TEXT,
        required_group TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    this.setSettingStatement = this.db.prepare(
      'INSERT INTO settings (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value=excluded.value'
    );
    this.getSettingStatement = this.db.prepare('SELECT value FROM settings WHERE key = ?');
    this.deleteSettingStatement = this.db.prepare('DELETE FROM settings WHERE key = ?');

    this.setSecretStatement = this.db.prepare(
      'INSERT INTO secrets (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value=excluded.value'
    );
    this.getSecretStatement = this.db.prepare('SELECT value FROM secrets WHERE key = ?');
    this.deleteSecretStatement = this.db.prepare('DELETE FROM secrets WHERE key = ?');

    this.listResourcesStatement = this.db.prepare('SELECT * FROM resources ORDER BY name');
  }

  setSetting(key, value) {
    if (value === undefined || value === null) {
      this.deleteSettingStatement.run(key);
      return;
    }
    this.setSettingStatement.run({ key, value: JSON.stringify(value) });
  }

  getSetting(key, defaultValue = null) {
    const row = this.getSettingStatement.get(key);
    if (!row) {
      return defaultValue;
    }
    try {
      return JSON.parse(row.value);
    } catch (error) {
      return defaultValue;
    }
  }

  setSecret(key, value) {
    if (!value) {
      this.deleteSecretStatement.run(key);
      return;
    }
    const encrypted = encryptSecret(value);
    this.setSecretStatement.run({ key, value: encrypted });
  }

  getSecret(key) {
    const row = this.getSecretStatement.get(key);
    if (!row) {
      return null;
    }
    return decryptSecret(row.value);
  }

  listResources() {
    return this.listResourcesStatement.all();
  }

  upsertResource(resource) {
    const stmt = this.db.prepare(`
      INSERT INTO resources (id, name, description, target_url, icon, required_group, created_at, updated_at)
      VALUES (@id, @name, @description, @target_url, @icon, @required_group, datetime('now'), datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        target_url = excluded.target_url,
        icon = excluded.icon,
        required_group = excluded.required_group,
        updated_at = datetime('now')
    `);
    stmt.run(resource);
  }

  deleteResource(id) {
    this.db.prepare('DELETE FROM resources WHERE id = ?').run(id);
  }

  close() {
    this.db.close();
  }
}

export const configStore = new ConfigStore();

