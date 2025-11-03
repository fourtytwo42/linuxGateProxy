import { spawnSync } from 'child_process';

export function commandExists(command) {
  const shellCheck = spawnSync('sh', ['-c', `command -v ${command}`], { stdio: 'ignore' });
  if (shellCheck.status === 0) {
    return true;
  }
  const versionCheck = spawnSync(command, ['--version'], { stdio: 'ignore' });
  return !(versionCheck.error && versionCheck.error.code === 'ENOENT');
}
