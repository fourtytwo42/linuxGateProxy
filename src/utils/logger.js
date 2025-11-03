/* eslint-disable no-console */
import fs from 'fs';
import path from 'path';
import { logsDir } from './paths.js';
import { ensureDirSync } from './fs.js';

ensureDirSync(logsDir);

const logFile = path.join(logsDir, 'app.log');

function write(level, message, meta) {
  const timestamp = new Date().toISOString();
  const payload = {
    level,
    message,
    timestamp,
    ...meta
  };
  const line = JSON.stringify(payload);
  fs.appendFile(logFile, line + '\n', () => {});
  if (level === 'error') {
    console.error(`[${timestamp}] ${message}`, meta ?? '');
  } else {
    console.log(`[${timestamp}] ${message}`, meta ?? '');
  }
}

export const logger = {
  info(message, meta) {
    write('info', message, meta);
  },
  warn(message, meta) {
    write('warn', message, meta);
  },
  error(message, meta) {
    write('error', message, meta);
  },
  debug(message, meta) {
    // In development mode, debug logs are shown as info
    // In production, they could be filtered out
    if (process.env.NODE_ENV === 'development') {
      write('debug', message, meta);
    }
  }
};

