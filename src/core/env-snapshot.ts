import fg from 'fast-glob';
import { relative, resolve } from 'node:path';

import { sha256File } from './file-hash.js';

export type EnvHashes = Record<string, string>;

export async function buildEnvHashes(cwd: string): Promise<EnvHashes> {
  const root = resolve(cwd);
  const envLike = await fg(['**/.env', '**/.env.*'], {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    unique: true,
    ignore: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/build/**',
      '**/coverage/**',
      '**/.git/**',
      '**/.cache/**',
      '**/project-report/**',
    ],
  });
  const out: EnvHashes = {};
  for (const abs of envLike) {
    const base = abs.split(/[/\\]/).pop()?.toLowerCase() ?? '';
    if (base.endsWith('.sample') || base.endsWith('.example')) {
      continue;
    }
    try {
      const rel = relative(root, abs).replaceAll('\\', '/');
      out[rel] = await sha256File(abs);
    } catch {
      continue;
    }
  }
  return out;
}
