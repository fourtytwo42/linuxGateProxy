import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('config store persists settings and secrets', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateproxy-test-'));
  process.env.GATE_DATA_DIR = tempDir;
  const { ConfigStore } = await import('../src/config/store.js');
  const store = new ConfigStore();
  store.setSetting('site', { listenPort: 6001 });
  const site = store.getSetting('site');
  assert.equal(site.listenPort, 6001);

  store.setSecret('example', 's3cr3t');
  assert.equal(store.getSecret('example'), 's3cr3t');

  store.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
  delete process.env.GATE_DATA_DIR;
});

