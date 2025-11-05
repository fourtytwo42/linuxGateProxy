import { spawnSync } from 'child_process';

export function commandExists(command) {
  try {
    // First try: use 'command -v' which is POSIX compliant
    const shellCheck = spawnSync('sh', ['-c', `command -v ${command}`], { 
      stdio: 'ignore',
      timeout: 2000
    });
    if (shellCheck.status === 0) {
      return true;
    }
    
    // Second try: try to run the command with --version
    const versionCheck = spawnSync(command, ['--version'], { 
      stdio: 'ignore',
      timeout: 2000
    });
    
    // If no error occurred (ENOENT means command not found), it exists
    if (!versionCheck.error || versionCheck.error.code !== 'ENOENT') {
      return true;
    }
    
    return false;
  } catch (error) {
    // If we catch an error, assume command doesn't exist
    return false;
  }
}
