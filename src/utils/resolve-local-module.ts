import { existsSync, statSync } from 'node:fs';
import { dirname, extname, join, normalize, resolve as resolvePath } from 'node:path';

const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'] as const;

function tryFile(path: string): string | null {
  if (!existsSync(path)) {
    return null;
  }
  if (statSync(path).isFile()) {
    return normalize(path);
  }
  return null;
}

/**
 * Resolve a relative import specifier to an absolute file path if it exists in the repo.
 */
export function resolveLocalImport(importerPath: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) {
    return null;
  }

  const baseDir = dirname(importerPath);
  const withoutQuery = specifier.split('?')[0] ?? specifier;
  const direct = resolvePath(baseDir, withoutQuery);

  const candidates: string[] = [direct];
  if (extname(direct) === '.js') {
    candidates.push(direct.replace(/\.js$/i, '.ts'), direct.replace(/\.js$/i, '.tsx'));
  }

  for (const candidate of candidates) {
    const hit = tryFile(candidate);
    if (hit) {
      return hit;
    }
  }

  const ext = extname(direct);
  if (ext === '') {
    for (const e of EXTENSIONS) {
      const hit = tryFile(direct + e);
      if (hit) {
        return hit;
      }
    }

    for (const e of EXTENSIONS) {
      const indexHit = tryFile(join(direct, `index${e}`));
      if (indexHit) {
        return indexHit;
      }
    }
  }

  return null;
}
