import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Issue, LintScanResult } from '../core/types.js';

interface SpawnResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
  readonly timedOut: boolean;
}

function runCommand(
  cmd: string,
  args: readonly string[],
  cwd: string,
  timeoutMs: number,
): Promise<SpawnResult> {
  return new Promise((resolveFn) => {
    const child = spawn(cmd, [...args], {
      cwd,
      shell: process.platform === 'win32',
      windowsHide: true,
      env: { ...process.env, FORCE_COLOR: '0', NO_COLOR: '1' },
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveFn({ stdout, stderr, code, timedOut });
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolveFn({ stdout, stderr, code: -1, timedOut });
    });
  });
}

function findLocalBin(cwd: string, name: string): string | undefined {
  const bin = process.platform === 'win32' ? `${name}.cmd` : name;
  const candidate = join(cwd, 'node_modules', '.bin', bin);
  return existsSync(candidate) ? candidate : undefined;
}

interface EslintMessage {
  readonly ruleId: string | null;
  readonly severity: 0 | 1 | 2;
  readonly message: string;
  readonly line: number;
  readonly column?: number;
}

interface EslintFileResult {
  readonly filePath: string;
  readonly messages: readonly EslintMessage[];
  readonly errorCount: number;
  readonly warningCount: number;
}

async function runEslint(
  cwd: string,
  bin: string,
  budgetMs: number,
): Promise<{ readonly issues: readonly Issue[]; readonly errors: number; readonly warnings: number }> {
  const issues: Issue[] = [];
  const { stdout, code, timedOut } = await runCommand(
    bin,
    ['--format', 'json', '--no-color', '.'],
    cwd,
    budgetMs,
  );
  if (timedOut) {
    return { issues, errors: 0, warnings: 0 };
  }
  if (stdout.trim().length === 0) {
    return { issues, errors: 0, warnings: 0 };
  }
  let parsed: readonly EslintFileResult[] = [];
  try {
    parsed = JSON.parse(stdout) as readonly EslintFileResult[];
  } catch {
    return { issues, errors: 0, warnings: 0 };
  }
  let errors = 0;
  let warnings = 0;
  const capPerFile = 10;
  for (const file of parsed) {
    let kept = 0;
    for (const m of file.messages) {
      if (m.severity === 2) {
        errors += 1;
      } else if (m.severity === 1) {
        warnings += 1;
      }
      if (kept >= capPerFile) {
        continue;
      }
      kept += 1;
      const sev = m.severity === 2 ? 'MEDIUM' : 'LOW';
      issues.push({
        id: `lint:eslint:${file.filePath}:${String(m.line)}:${m.ruleId ?? 'rule'}`,
        engine: 'lint',
        severity: sev,
        title: `ESLint: ${m.ruleId ?? 'rule'}`,
        file: file.filePath,
        line: m.line || 1,
        description: m.message,
        impact: 'Static rule violation. Fix to keep the codebase consistent and bug-resistant.',
        fix: 'Run `eslint --fix` or adjust the code per the rule.',
        category: 'lint',
        confidence: 'high',
        whyItMatters: 'ESLint rules codify team conventions and catch real bugs (shadowing, unused code, async misuse).',
      });
    }
    // Hint that we truncated per-file messages.
    if (file.messages.length > capPerFile) {
      issues.push({
        id: `lint:eslint:${file.filePath}:truncated`,
        engine: 'lint',
        severity: 'LOW',
        title: 'ESLint output truncated for this file',
        file: file.filePath,
        line: 1,
        description: `${String(file.messages.length)} messages from ESLint in this file — showing first ${String(capPerFile)}.`,
        impact: 'Remaining messages are available by running ESLint locally.',
        fix: 'Run `eslint <file>` to see all messages.',
        category: 'lint',
        confidence: 'high',
        count: file.messages.length - capPerFile,
      });
    }
  }
  if (code === null && parsed.length === 0) {
    // ESLint might have crashed; no data to emit.
    return { issues, errors, warnings };
  }
  return { issues, errors, warnings };
}

async function runTsc(
  cwd: string,
  bin: string,
  budgetMs: number,
): Promise<{ readonly issues: readonly Issue[]; readonly errors: number }> {
  const issues: Issue[] = [];
  const { stdout, stderr, timedOut } = await runCommand(
    bin,
    ['--noEmit', '--pretty', 'false'],
    cwd,
    budgetMs,
  );
  if (timedOut) {
    return { issues, errors: 0 };
  }
  const combined = `${stdout}\n${stderr}`;
  // TS diagnostics: path(line,col): error TS#### : message
  const re = /^(.+?)\((\d+),(\d+)\):\s+(error|warning)\s+TS(\d+):\s+(.+)$/gm;
  let errors = 0;
  let match: RegExpExecArray | null = re.exec(combined);
  const cap = 200;
  let kept = 0;
  while (match !== null) {
    const [, file, lineStr, colStr, kind, codeNum, msg] = match;
    if (kind === 'error') {
      errors += 1;
    }
    if (kept < cap && file !== undefined && lineStr !== undefined) {
      kept += 1;
      const colNum = colStr !== undefined ? Number(colStr) : Number.NaN;
      issues.push({
        id: `lint:tsc:${file}:${lineStr}:${codeNum ?? 'TS'}`,
        engine: 'lint',
        severity: kind === 'error' ? 'MEDIUM' : 'LOW',
        title: `TypeScript ${kind ?? 'diagnostic'} TS${codeNum ?? ''}`,
        file: resolve(cwd, file),
        line: Number(lineStr) || 1,
        ...(Number.isFinite(colNum) && colNum > 0 ? { column: colNum } : {}),
        description: msg ?? '',
        impact: 'Type errors signal real bugs and often block compile for consumers.',
        fix: 'Fix types; do not silence with `any`. Use `unknown` or precise generics.',
        category: 'lint',
        confidence: 'high',
        whyItMatters: 'A broken tsc means the project will not ship cleanly.',
      });
    }
    match = re.exec(combined);
  }
  return { issues, errors };
}

async function runPrettier(
  cwd: string,
  bin: string,
  budgetMs: number,
): Promise<{ readonly issues: readonly Issue[]; readonly count: number }> {
  const issues: Issue[] = [];
  const { stdout, stderr, timedOut } = await runCommand(
    bin,
    ['--check', '--log-level', 'warn', '.'],
    cwd,
    budgetMs,
  );
  if (timedOut) {
    return { issues, count: 0 };
  }
  const combined = `${stdout}\n${stderr}`;
  const lines = combined.split(/\r?\n/);
  const files: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[warn]') && !trimmed.includes('Code style issues')) {
      const rel = trimmed.replace('[warn]', '').trim();
      if (rel.length > 0 && !rel.toLowerCase().includes('ignored')) {
        files.push(rel);
      }
    }
  }
  const cap = 40;
  for (const f of files.slice(0, cap)) {
    issues.push({
      id: `lint:prettier:${f}`,
      engine: 'lint',
      severity: 'LOW',
      title: 'Prettier: file is not formatted',
      file: resolve(cwd, f),
      line: 1,
      description: 'Prettier --check reported style differences.',
      impact: 'Inconsistent formatting increases review noise and merge conflicts.',
      fix: 'Run `prettier --write` and commit the result.',
      category: 'lint',
      confidence: 'high',
    });
  }
  return { issues, count: files.length };
}

export interface LintEngineOptions {
  readonly skip?: boolean;
  readonly budgetMs?: number;
}

export async function runLintEngine(cwd: string, opts?: LintEngineOptions): Promise<LintScanResult> {
  const started = Date.now();
  if (opts?.skip) {
    return {
      issues: [],
      eslintAvailable: false,
      tscAvailable: false,
      prettierAvailable: false,
      eslintErrorCount: 0,
      eslintWarningCount: 0,
      tscErrorCount: 0,
      prettierUnformattedCount: 0,
      skippedReason: 'skip-lint flag set',
      durationMs: Date.now() - started,
    };
  }
  const perToolBudget = Math.max(15_000, opts?.budgetMs ?? 60_000);
  const eslintBin = findLocalBin(cwd, 'eslint');
  const tscBin = findLocalBin(cwd, 'tsc');
  const prettierBin = findLocalBin(cwd, 'prettier');

  const issues: Issue[] = [];
  let eslintErrorCount = 0;
  let eslintWarningCount = 0;
  let tscErrorCount = 0;
  let prettierUnformattedCount = 0;

  if (eslintBin !== undefined) {
    const r = await runEslint(cwd, eslintBin, perToolBudget);
    issues.push(...r.issues);
    eslintErrorCount = r.errors;
    eslintWarningCount = r.warnings;
  }
  if (tscBin !== undefined) {
    const r = await runTsc(cwd, tscBin, perToolBudget);
    issues.push(...r.issues);
    tscErrorCount = r.errors;
  }
  if (prettierBin !== undefined) {
    const r = await runPrettier(cwd, prettierBin, perToolBudget);
    issues.push(...r.issues);
    prettierUnformattedCount = r.count;
  }

  return {
    issues,
    eslintAvailable: eslintBin !== undefined,
    tscAvailable: tscBin !== undefined,
    prettierAvailable: prettierBin !== undefined,
    eslintErrorCount,
    eslintWarningCount,
    tscErrorCount,
    prettierUnformattedCount,
    durationMs: Date.now() - started,
  };
}
