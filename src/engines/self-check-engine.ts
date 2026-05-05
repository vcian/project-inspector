import fg from 'fast-glob';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Issue } from '../core/types.js';

export async function runSelfCheckEngine(cwd: string): Promise<{ readonly issues: readonly Issue[] }> {
  const root = resolve(cwd);
  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) {
    return { issues: [] };
  }
  let name = '';
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { name?: string };
    name = pkg.name ?? '';
  } catch {
    return { issues: [] };
  }
  if (name !== 'project-inspector') {
    return { issues: [] };
  }

  const hits = await fg(['**/*.{test,spec}.ts'], {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    ignore: ['**/node_modules/**', '**/dist/**'],
  });
  if (hits.length > 0) {
    return { issues: [] };
  }

  return {
    issues: [
      {
        id: 'self-check:dogfooding:no-tests',
        engine: 'self-check',
        severity: 'HIGH',
        title: 'Tool has no automated tests — dogfooding gap',
        file: pkgPath,
        line: 1,
        description:
          'This workspace is project-inspector but no *.test.ts or *.spec.ts files were found at scan time.',
        impact: 'CLI and engine regressions may ship unnoticed.',
        fix: 'Add Jest/Vitest coverage for parsers and `project-inspector check` in CI.',
      },
    ],
  };
}
