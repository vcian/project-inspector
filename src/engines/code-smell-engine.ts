import { readFile } from 'node:fs/promises';
import { normalize } from 'node:path';

import type { CodeSmellScanResult, Issue } from '../core/types.js';
import type { FileFilterOptions } from '../core/engine-options.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { runPool } from '../utils/async-pool.js';

const MAX_FILE_LINES = 600;
const BAD_NAME_RE = /^(tmp|foo|bar|data|handler|cb|x|y)\b/i;

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

function hashLines(lines: readonly string[], start: number, len: number): string {
  return lines.slice(start, start + len).join('\n').replaceAll(/\s+/g, ' ').trim();
}

async function scanFile(
  path: string,
  getSourceText?: (normalizedAbs: string) => string | undefined,
): Promise<Issue[]> {
  const issues: Issue[] = [];
  let text: string | undefined = getSourceText?.(normalize(path));
  if (text === undefined) {
    try {
      text = await readFile(path, 'utf8');
    } catch {
      return issues;
    }
  }
  const lines = text.split(/\r?\n/);
  if (lines.length >= MAX_FILE_LINES) {
    issues.push(
      mkIssue(
        'code-smell',
        'MEDIUM',
        'Large source file',
        path,
        1,
        `File has ${String(lines.length)} lines (threshold ${String(MAX_FILE_LINES)}).`,
        'Harder reviews, merges, and defect localization.',
        'Split by responsibility; extract modules and tests.',
      ),
    );
  }

  const base = path.split(/[/\\]/).pop() ?? '';
  if (BAD_NAME_RE.test(base.replace(/\.[^.]+$/, ''))) {
    issues.push(
      mkIssue(
        'code-smell',
        'LOW',
        'Weakly descriptive file name',
        path,
        1,
        `Filename "${base}" is vague for a production codebase.`,
        'Discoverability and ownership clarity suffer.',
        'Rename to reflect domain responsibility.',
      ),
    );
  }

  const chunkHashes = new Map<string, number>();
  const window = 5;
  for (let i = 0; i <= lines.length - window; i += 1) {
    const h = hashLines(lines, i, window);
    if (h.length < 40) {
      continue;
    }
    chunkHashes.set(h, (chunkHashes.get(h) ?? 0) + 1);
  }
  for (const [h, count] of chunkHashes) {
    if (count >= 3) {
      issues.push(
        mkIssue(
          'code-smell',
          'LOW',
          'Duplicate 5-line block pattern detected',
          path,
          1,
          `A repeated block appears ~${String(count)} times (normalized). Preview: ${h.slice(0, 120)}…`,
          'Copy-paste drift; bugs fixed in one copy may be missed elsewhere.',
          'Extract a shared helper or configuration table.',
        ),
      );
      break;
    }
  }

  return issues;
}

export interface CodeSmellEngineOptions extends FileFilterOptions {
  readonly pathsOverride?: ReadonlySet<string>;
}

export async function runCodeSmellEngine(
  cwd: string,
  concurrency: number,
  options?: CodeSmellEngineOptions,
): Promise<CodeSmellScanResult> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  let scoped = normalizedAll;
  if (options?.fileFilter) {
    scoped = scoped.filter((f) => options.fileFilter?.has(f));
  }
  const pathsOverride = options?.pathsOverride;
  if (pathsOverride) {
    scoped = scoped.filter((f) => pathsOverride.has(f));
  }
  const filtered = Boolean(options?.fileFilter || pathsOverride);
  if (filtered && scoped.length === 0) {
    return { issues: [] };
  }
  const targets = filtered ? scoped : normalizedAll;
  const getText = options?.getSourceText;
  const chunks = await runPool(targets, concurrency, (f) => scanFile(f, getText));
  return { issues: chunks.flat() };
}
