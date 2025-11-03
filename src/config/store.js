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
        allowed_groups TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Migrate existing schema: add allowed_groups column if it doesn't exist
    try {
      this.db.exec(`ALTER TABLE resources ADD COLUMN allowed_groups TEXT`);
    } catch (error) {
      // Column already exists, ignore
      if (!error.message.includes('duplicate column name')) {
        throw error;
      }
    }
    
    // Migrate required_group to allowed_groups for existing resources
    this.db.exec(`
      UPDATE resources 
      SET allowed_groups = json_array(required_group)
      WHERE required_group IS NOT NULL 
        AND required_group != ''
        AND (allowed_groups IS NULL OR allowed_groups = '' OR allowed_groups = '[]')
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
    const resources = this.listResourcesStatement.all();
    // Parse allowed_groups from JSON and handle backwards compatibility
    return resources.map((resource) => {
      // Parse allowed_groups from JSON string
      let allowedGroups = [];
      if (resource.allowed_groups) {
        try {
          allowedGroups = JSON.parse(resource.allowed_groups);
        } catch (e) {
          // Invalid JSON, try as single value
          allowedGroups = resource.allowed_groups ? [resource.allowed_groups] : [];
        }
      } else if (resource.required_group) {
        // Backwards compatibility: migrate required_group to allowed_groups
        allowedGroups = [resource.required_group];
      }
      
      return {
        ...resource,
        allowed_groups: allowedGroups,
        // Keep required_group for backwards compatibility but prefer allowed_groups
        required_group: allowedGroups.length === 1 ? allowedGroups[0] : resource.required_group
      };
    });
  }

  upsertResource(resource) {
    // Normalize resource object to ensure all required fields are present
    // Handle allowed_groups: accept array or single value, convert to JSON array
    let allowedGroups = [];
    if (resource.allowed_groups) {
      allowedGroups = Array.isArray(resource.allowed_groups) 
        ? resource.allowed_groups 
        : [resource.allowed_groups];
    } else if (resource.required_group || resource.requiredGroup || resource.groupDn) {
      // Backwards compatibility: migrate single required_group to allowed_groups
      allowedGroups = [resource.required_group || resource.requiredGroup || resource.groupDn];
    }
    
    const normalized = {
      id: resource.id,
      name: resource.name || '',
      description: resource.description || '',
      target_url: resource.target_url || resource.targetUrl || '',
      icon: resource.icon || '',
      required_group: resource.required_group || resource.requiredGroup || resource.groupDn || null,
      allowed_groups: allowedGroups.length > 0 ? JSON.stringify(allowedGroups) : null
    };

    const stmt = this.db.prepare(`
      INSERT INTO resources (id, name, description, target_url, icon, required_group, allowed_groups, created_at, updated_at)
      VALUES (@id, @name, @description, @target_url, @icon, @required_group, @allowed_groups, datetime('now'), datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        target_url = excluded.target_url,
        icon = excluded.icon,
        required_group = excluded.required_group,
        allowed_groups = excluded.allowed_groups,
        updated_at = datetime('now')
    `);
    stmt.run(normalized);
  }

  deleteResource(id) {
    this.db.prepare('DELETE FROM resources WHERE id = ?').run(id);
  }

  close() {
    this.db.close();
  }
}

export const configStore = new ConfigStore();

