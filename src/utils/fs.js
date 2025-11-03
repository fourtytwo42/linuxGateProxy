import fs from 'fs';

export function ensureDirSync(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode: 0o750 });
  }
}

export function writeFileSecureSync(filePath, data) {
  fs.writeFileSync(filePath, data, { mode: 0o600 });
}

