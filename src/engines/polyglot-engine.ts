import fg from 'fast-glob';
import { readFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

import type { Issue } from '../core/types.js';

const IGNORE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/.git/**',
  '**/vendor/**',
  '**/coverage/**',
  '**/__pycache__/**',
  '**/.venv/**',
];

/**
 * Best-effort text/RX scan for Python and Go (tree-sitter deferred).
 * Findings are merged into the code-smell engine list for reporting.
 */
export async function runPolyglotEngine(cwd: string): Promise<readonly Issue[]> {
  const files = await fg(['**/*.py', '**/*.go'], {
    cwd,
    absolute: true,
    onlyFiles: true,
    ignore: IGNORE,
    unique: true,
    followSymbolicLinks: false,
  });
  const unique = files.map((f) => resolve(f)).slice(0, 80);
  const issues: Issue[] = [];
  for (const file of unique) {
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    const rel = relative(cwd, file).replaceAll('\\', '/');
    const isPy = file.endsWith('.py');
    const lineOf = (idx: number): number => text.slice(0, idx).split(/\r?\n/u).length;
    if (isPy) {
      const m = /\b(?:eval|exec|subprocess\.\s*call|os\.system)\s*\(/u.exec(text);
      if (m?.index !== undefined) {
        issues.push({
          id: `polyglot-py-${rel}-${String(lineOf(m.index))}`,
          title: 'Potentially dangerous Python API (heuristic)',
          description:
            'Detected a call pattern that often wraps shell or dynamic code. Tree-sitter deep analysis is not enabled; review manually.',
          severity: 'MEDIUM',
          engine: 'code-smell',
          file,
          line: lineOf(m.index),
          impact: 'Arbitrary code execution or shell injection if user input reaches this path.',
          fix: 'Use safer APIs, parameter lists for subprocess, and strict input validation.',
          category: 'quality',
          confidence: 'low',
        });
      }
    } else {
      const m = /\bexec\.Command(?:Context)?\s*\(\s*["']/u.exec(text);
      if (m?.index !== undefined) {
        issues.push({
          id: `polyglot-go-${rel}-${String(lineOf(m.index))}`,
          title: 'Go external command construction (heuristic)',
          description:
            'String-literal `exec.Command` is often safe; ensure no user-controlled segments are concatenated.',
          severity: 'LOW',
          engine: 'code-smell',
          file,
          line: lineOf(m.index),
          impact: 'Command injection if arguments are built from untrusted input.',
          fix: 'Use dedicated argument arrays and validate inputs.',
          category: 'quality',
          confidence: 'low',
        });
      }
    }
  }
  if (unique.length > 0 && issues.length === 0) {
    const first = unique[0];
    const sampleRel =
      first !== undefined ? relative(cwd, first).replaceAll('\\', '/') : 'polyglot';
    issues.push({
      id: `polyglot-scan-${sampleRel}`,
      title: `Polyglot scan: ${String(unique.length)} Python/Go file(s) (no high-risk patterns matched)`,
      description:
        '_Full tree-sitter analysis for Python/Go is planned; this pass uses regex heuristics only._',
      severity: 'LOW',
      engine: 'code-smell',
      file: first ?? join(cwd, 'package.json'),
      line: 1,
      impact: 'Informational — confirms non-JS sources were considered.',
      fix: 'Keep JS/TS modules primary for gates; track polyglot folders in CODEOWNERS.',
      category: 'inventory',
      confidence: 'low',
    });
  }
  return issues;
}
