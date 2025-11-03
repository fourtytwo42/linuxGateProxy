import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const projectRoot = path.resolve(__dirname, '..', '..');
export const dataDir = path.join(projectRoot, 'data');
export const shareDir = path.join(dataDir, 'share');
export const runtimeDir = path.join(dataDir, 'runtime');
export const logsDir = path.join(runtimeDir, 'logs');
export const tempDir = path.join(runtimeDir, 'tmp');
export const publicDir = path.join(projectRoot, 'public');

