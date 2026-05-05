import { relative } from 'node:path';

/** Stable forward-slash key relative to cwd (for cache JSON keys). */
export function relKey(cwd: string, absPath: string): string {
  return relative(cwd, absPath).replaceAll('\\', '/');
}
