import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
import { normalize, relative, resolve } from 'node:path';

/**
 * Returns paths (absolute, normalized) of tracked/changed source files for incremental scan.
 * Falls back to null if git is unavailable or not a repo.
 */
export async function getGitChangedPaths(cwd: string): Promise<readonly string[] | null> {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['-C', cwd, 'diff', '--name-only', 'HEAD'],
      { maxBuffer: 50_000_000, windowsHide: true },
    );
    const rels = stdout
      .split(/\r?\n/)
      .map((line: string) => line.trim())
      .filter((line: string) => line.length > 0);

    const normalized = new Set<string>();
    for (const r of rels) {
      normalized.add(normalize(resolve(cwd, r)));
    }
    return [...normalized];
  } catch {
    return null;
  }
}

export function toRepoRelativePaths(cwd: string, absPaths: readonly string[]): Set<string> {
  const s = new Set<string>();
  for (const p of absPaths) {
    s.add(relative(cwd, p).replaceAll('\\', '/'));
  }
  return s;
}
