import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, normalize, relative, resolve } from 'node:path';

import { CACHE_SUBDIR } from '../core/scan-cache.js';
import type { FileAstAnalysis } from './ast-engine.js';

const AST_BY_FILE_JSON = 'ast-by-file.json';

interface AstByFileV1 {
  readonly version: 1;
  readonly files: Record<string, FileAstAnalysis>;
}

export async function loadAstByFileMap(outDir: string, cwd: string): Promise<Map<string, FileAstAnalysis>> {
  const m = new Map<string, FileAstAnalysis>();
  try {
    const raw = await readFile(join(outDir, CACHE_SUBDIR, AST_BY_FILE_JSON), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || !('files' in parsed)) {
      return m;
    }
    const data = parsed as AstByFileV1;
    for (const [rel, analysis] of Object.entries(data.files)) {
      m.set(normalize(resolve(cwd, rel)), analysis);
    }
  } catch {
    return m;
  }
  return m;
}

export async function saveAstByFileMap(
  outDir: string,
  cwd: string,
  analyses: readonly FileAstAnalysis[],
): Promise<void> {
  const dir = join(outDir, CACHE_SUBDIR);
  await mkdir(dir, { recursive: true });
  const files: Record<string, FileAstAnalysis> = {};
  for (const a of analyses) {
    const rel = relativePosix(cwd, a.file);
    files[rel] = a;
  }
  const body: AstByFileV1 = { version: 1, files };
  await writeFile(join(dir, AST_BY_FILE_JSON), `${JSON.stringify(body, null, 2)}\n`, 'utf8');
}

function relativePosix(cwd: string, abs: string): string {
  return relative(cwd, abs).replaceAll('\\', '/');
}
