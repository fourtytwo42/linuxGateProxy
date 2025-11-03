import { defaultSettings } from './defaults.js';
import { configStore } from './store.js';

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function deepMerge(target, source) {
  if (Array.isArray(source)) {
    return source.slice();
  }
  if (source && typeof source === 'object') {
    const output = { ...target };
    for (const [key, value] of Object.entries(source)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        output[key] = deepMerge(target?.[key] ?? {}, value);
      } else {
        output[key] = value;
      }
    }
    return output;
  }
  return source;
}

export function loadConfig() {
  const result = deepClone(defaultSettings);
  for (const key of Object.keys(defaultSettings)) {
    const stored = configStore.getSetting(key);
    if (stored) {
      result[key] = deepMerge(result[key], stored);
    }
  }
  return result;
}

export function saveConfigSection(section, value) {
  if (!(section in defaultSettings)) {
    throw new Error(`Unknown config section: ${section}`);
  }
  configStore.setSetting(section, value);
}

export function getSecret(key) {
  return configStore.getSecret(key);
}

export function setSecret(key, value) {
  configStore.setSecret(key, value);
}

export function listResources() {
  return configStore.listResources();
}

export function upsertResource(resource) {
  configStore.upsertResource(resource);
}

export function deleteResource(id) {
  configStore.deleteResource(id);
}

