import fg from 'fast-glob';
import { resolve } from 'node:path';

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/.next/**',
  '**/build/**',
  '**/coverage/**',
  '**/.git/**',
  '**/vendor/**',
  '**/out/**',
  '**/.turbo/**',
  '**/.cache/**',
  '**/android/**',
  '**/ios/**',
  '**/.venv/**',
  '**/__pycache__/**',
  '**/Pods/**',
  '**/.gradle/**',
  '**/target/**',
  '**/project-report/**',
  '**/.pnpm-store/**',
];

/**
 * JS + TS extensions used for AST / security / perf analysis.
 */
const JS_LIKE_PATTERNS = ['**/*.{ts,tsx,js,jsx,mjs,cjs}'];

/**
 * Markup + component files used by frameworks (Angular templates, Vue/Svelte SFCs).
 * Scanned by secondary engines (security/memory/perf) when applicable; NOT fed to ts-morph.
 */
const MARKUP_PATTERNS = ['**/*.{vue,svelte}', '**/*.component.html'];

export async function discoverSourceFiles(cwd: string): Promise<string[]> {
  const files = await fg(JS_LIKE_PATTERNS, {
    cwd,
    absolute: true,
    onlyFiles: true,
    ignore: DEFAULT_IGNORE,
    unique: true,
    followSymbolicLinks: false,
  });

  return files.map((f) => resolve(f));
}

/**
 * Template / SFC files (Angular / Vue / Svelte). Used by framework-aware rules.
 */
export async function discoverMarkupFiles(cwd: string): Promise<string[]> {
  const files = await fg(MARKUP_PATTERNS, {
    cwd,
    absolute: true,
    onlyFiles: true,
    ignore: DEFAULT_IGNORE,
    unique: true,
    followSymbolicLinks: false,
  });
  return files.map((f) => resolve(f));
}
