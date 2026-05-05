import fg from 'fast-glob';
import { basename, dirname, join, normalize, relative, resolve } from 'node:path';

import type { Issue, TestCoverageScanResult } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';

const DEFAULT_TEST_GLOBS = [
  '**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}',
  '**/__tests__/**/*.{ts,tsx,js,jsx,mjs,cjs}',
] as const;
const DEFAULT_TEST_IGNORE = ['**/node_modules/**', '**/dist/**', '**/.next/**'] as const;

function mkIssue(
  engine: string,
  severity: Issue['severity'],
  title: string,
  file: string,
  line: number,
  description: string,
  impact: string,
  fix: string,
): Issue {
  const id = `${engine}:${file}:${String(line)}:${title}`.replaceAll(/\s+/g, '_');
  return { id, engine, severity, title, file, line, description, impact, fix };
}

export interface TestEngineOptions {
  /** Merged with built-in `*.test.*` / `*.spec.*` / `__tests__/**` globs. */
  readonly testFileGlobs?: readonly string[];
}

export async function runTestEngine(
  cwd: string,
  sourceFiles?: readonly string[],
  options?: TestEngineOptions,
): Promise<TestCoverageScanResult> {
  const root = resolve(cwd);
  const sources =
    sourceFiles && sourceFiles.length > 0 ? [...sourceFiles] : await discoverSourceFiles(root);
  const globs =
    options?.testFileGlobs !== undefined && options.testFileGlobs.length > 0
      ? [...new Set([...DEFAULT_TEST_GLOBS, ...options.testFileGlobs])]
      : [...DEFAULT_TEST_GLOBS];
  const testFilesArr = await fg(globs, {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    ignore: [...DEFAULT_TEST_IGNORE],
    unique: true,
  });
  const testSet = new Set(testFilesArr.map((p) => normalize(p)));
  const sourceOnly = sources.filter((p) => !testSet.has(normalize(p)));
  const testFileCount = testSet.size;
  const sourceFileCount = sourceOnly.length;
  const ratioApprox = sourceFileCount > 0 ? Math.round((testFileCount / sourceFileCount) * 1000) / 1000 : 0;

  const issues: Issue[] = [];
  const pkgPath = join(root, 'package.json');

  if (sourceFileCount >= 30 && testFileCount === 0) {
    issues.push(
      mkIssue(
        'tests',
        'HIGH',
        'No automated test files detected',
        pkgPath,
        1,
        `Scanned ${String(sourceFileCount)} source files; zero matches for globs [${globs.join(', ')}] with ignore [${DEFAULT_TEST_IGNORE.join(', ')}].`,
        'Regressions ship undetected; refactors are unsafe.',
        'Add unit tests (Vitest/Jest) and CI test gate; start with critical modules.',
      ),
    );
  } else if (sourceFileCount >= 20 && ratioApprox < 0.05) {
    issues.push(
      mkIssue(
        'tests',
        'MEDIUM',
        'Very low test-to-code file ratio',
        pkgPath,
        1,
        `Approx ratio test/source files = ${String(ratioApprox)} (${String(testFileCount)}/${String(sourceFileCount)}).`,
        'Thin safety net for production changes.',
        'Increase coverage for business logic, API handlers, and parsers.',
      ),
    );
  }

  const entryHints: string[] = [];
  const entryNames = new Set(['index.ts', 'index.js', 'main.ts', 'main.js', 'server.ts', 'server.js', 'app.ts']);
  for (const abs of sourceOnly) {
    const base = basename(abs).toLowerCase();
    if (!entryNames.has(base)) {
      continue;
    }
    const rel = relative(root, abs).replaceAll('\\', '/');
    const stem = abs.replace(/\.[^.]+$/, '');
    const hasSibling =
      testSet.has(normalize(`${stem}.test.ts`)) ||
      testSet.has(normalize(`${stem}.spec.ts`)) ||
      testSet.has(normalize(`${stem}.test.js`)) ||
      testSet.has(normalize(`${stem}.spec.js`)) ||
      testSet.has(normalize(join(dirname(abs), '__tests__', `${basename(stem)}.test.ts`)));
    if (!hasSibling) {
      entryHints.push(rel);
      if (entryHints.length <= 8) {
        issues.push(
          mkIssue(
            'tests',
            'LOW',
            `Entry-like module without adjacent test: ${rel}`,
            abs,
            1,
            'Heuristic: no co-located *.test.* / __tests__ sibling detected.',
            'Hot paths may lack regression tests.',
            'Add focused tests for startup, routing, and DI wiring.',
          ),
        );
      }
    }
  }

  return {
    issues,
    testFileCount,
    sourceFileCount,
    ratioApprox,
    uncoveredEntryHints: entryHints.slice(0, 12),
    testDetection: {
      globs,
      ignore: [...DEFAULT_TEST_IGNORE],
      matchedSample: testFilesArr
        .slice(0, 8)
        .map((p) => relative(root, p).replaceAll('\\', '/')),
    },
  };
}
