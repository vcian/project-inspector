import { relative, resolve } from 'node:path';

export class PathSafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathSafetyError';
  }
}

/**
 * Throws PathSafetyError when outDir would resolve outside projectDir.
 * Guards against path-traversal via `--out ../../../etc`.
 */
export function checkSafeOutDir(projectDir: string, outDir: string): void {
  const root = resolve(projectDir);
  const target = resolve(outDir);
  const rel = relative(root, target);
  if (rel === '..' || rel.split(/[/\\]/).some((segment) => segment === '..')) {
    throw new PathSafetyError(
      `--out must stay inside the project directory. Got: ${outDir}`,
    );
  }
}
