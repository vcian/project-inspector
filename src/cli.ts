#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { Command, Option } from 'commander';
import { appendFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import { exit } from 'node:process';
import { relative, resolve } from 'node:path';
import chalk from 'chalk';

import { runChatCommand } from './commands/chat.js';
import { runUpdateVulnDbCommand } from './commands/update-vuln-db.js';
import { runWatchCommand } from './commands/watch.js';
import { runCheckGate } from './core/check-gate.js';
import { clearProjectReportDir } from './core/clear-project-report.js';
import { defaultReportDir, runScan } from './core/scan-runner.js';
import type { ScanMode, ScanResult } from './core/types.js';
import { writeSarifReport } from './reports/sarif-writer.js';
import { logger } from './utils/logger.js';

const _require = createRequire(import.meta.url);
const pkgVersion = (_require('../package.json') as { version: string }).version;

async function appendGithubStepSummary(result: ScanResult): Promise<void> {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath === undefined || summaryPath.length === 0) {
    return;
  }
  const gate =
    result.productionDecision?.gateOk === true ? 'PASS' : result.productionDecision?.gateOk === false ? 'FAIL' : '—';
  const line = `**project-inspector** · readiness **${String(result.scores.productionReadiness)}/100** · gate **${gate}** · trusted **${String(result.trustedIssues?.length ?? 0)}**\n`;
  await appendFile(summaryPath, line, 'utf8');
}

/**
 * Renders a Unicode box summary with chalk colors.
 * READY/PASS = green, BLOCKED/FAIL = red, medium scores = yellow.
 * Replaces the old PI_VERDICT=... machine-readable line.
 */
function formatScanBoxSummary(result: ScanResult): string {
  const verdict = result.productionDecision?.verdict ?? 'UNKNOWN';
  const gate =
    result.productionDecision?.gateOk === true
      ? 'PASS'
      : result.productionDecision?.gateOk === false
        ? 'FAIL'
        : 'UNKNOWN';
  const readiness = result.scores.productionReadiness;
  const security = result.scores.security;
  const trusted = result.trustedIssues?.length ?? 0;

  // Colorise values — escape codes don't affect the raw length we track separately.
  const verdictColored =
    verdict === 'READY' ? chalk.green.bold(verdict) : chalk.red.bold(verdict);
  const gateColored = gate === 'PASS' ? chalk.green(gate) : chalk.red(gate);
  const readinessColored =
    readiness >= 70
      ? chalk.green(`${String(readiness)}/100`)
      : readiness >= 50
        ? chalk.yellow(`${String(readiness)}/100`)
        : chalk.red(`${String(readiness)}/100`);
  const securityColored =
    security >= 70
      ? chalk.green(`${String(security)}/100`)
      : security >= 50
        ? chalk.yellow(`${String(security)}/100`)
        : chalk.red(`${String(security)}/100`);

  const W = 42; // inner width (between │ chars)
  const hr = '─'.repeat(W);

  // Build a padded row; rawLen = visible length of the value string (no escape codes).
  function row(label: string, colored: string, rawLen: number): string {
    const prefix = `  ${label.padEnd(13)}`;
    const pad = Math.max(0, W - prefix.length - rawLen);
    return `│${prefix}${colored}${' '.repeat(pad)}│`;
  }

  return [
    `┌${hr}┐`,
    row('Verdict', verdictColored, verdict.length),
    row('Readiness', readinessColored, `${String(readiness)}/100`.length),
    row('Security', securityColored, `${String(security)}/100`.length),
    row('Trusted', `${String(trusted)} issues`, `${String(trusted)} issues`.length),
    row('Gate', gateColored, gate.length),
    `└${hr}┘`,
  ].join('\n');
}

function openReportPreview(outDir: string): void {
  const fullPath = resolve(outDir, 'index.html');
  if (process.platform === 'win32') {
    spawn('cmd', ['/c', 'start', '', fullPath], { detached: true, stdio: 'ignore' }).unref();
    return;
  }
  const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
  spawn(opener, [fullPath], { detached: true, stdio: 'ignore' }).unref();
}

process.on('uncaughtException', (error) => {
  logger.error({ err: error }, 'uncaught exception');
  process.stderr.write(`[project-inspector] ${error instanceof Error ? error.message : String(error)}\n`);
  exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error({ err: reason }, 'unhandled rejection');
  process.stderr.write(`[project-inspector] ${reason instanceof Error ? reason.message : String(reason)}\n`);
  exit(1);
});

type OutputFormat = 'md' | 'json' | 'sarif';

function defaultConcurrency(): number {
  return Math.max(2, Math.min(32, os.cpus().length));
}

function parseConcurrency(raw: string | number): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 32) {
    process.stderr.write('[project-inspector] --concurrency must be an integer between 1 and 32.\n');
    exit(1);
  }
  return value;
}

function assertSafeOutDir(projectDir: string, outDir: string): void {
  const root = resolve(projectDir);
  const target = resolve(outDir);
  const rel = relative(root, target);
  if (rel === '..' || rel.split(/[/\\]/).some((segment: string) => segment === '..')) {
    process.stderr.write('[project-inspector] --out must stay inside the project directory.\n');
    exit(1);
  }
}

function resolveProjectPath(project?: string, cwd?: string): string {
  return resolve(project ?? cwd ?? process.cwd());
}

function scanModeOption(): Option {
  return new Option('--mode <mode>', 'scan mode').choices(['quick', 'deep', 'diff']).default('deep');
}

function formatOption(): Option {
  return new Option('--format <format>', 'extra output format').choices(['md', 'json', 'sarif']).default('md');
}

/**
 * Attaches all options shared by scan / check / watch to the given command.
 * Each command may add its own extras after calling this.
 */
function addSharedScanOptions(cmd: Command): Command {
  return cmd
    .option('--project <path>', 'project root path')
    .option('-c, --cwd <path>', 'alias for --project')
    .option('-o, --out <dir>', 'output directory')
    .addOption(scanModeOption())
    .addOption(formatOption())
    .option('--concurrency <n>', 'scan concurrency', (value) => parseConcurrency(value), defaultConcurrency())
    .option('--online', 'allow online dependency audit', false)
    .option('--auto-update-db', 'silently refresh local vulnerability DB before dependency scan', false)
    .option('--no-cache', 'disable cache reuse', false)
    .option('--rescan', 'full workspace scan: ignore caches and git incremental scope', false)
    .option('--incremental', 'analyze only changed files where supported', false)
    .option('--offline', 'disable vuln DB staleness checks and online refresh', false)
    .option('--budget-ms <n>', 'soft scan budget in milliseconds', (value) => parseBudget(value))
    .option('--skip-lint', 'skip lint/tsc/prettier checks', false);
}

interface SharedScanCliOptions {
  readonly project?: string;
  readonly cwd?: string;
  readonly out?: string;
  readonly concurrency: number;
  readonly mode: ScanMode;
  readonly format: OutputFormat;
  readonly online?: boolean;
  readonly autoUpdateDb?: boolean;
  readonly noCache?: boolean;
  readonly incremental?: boolean;
  /** Full workspace rescan: ignore caches and git-scoped incremental analysis. */
  readonly rescan?: boolean;
  readonly offline?: boolean;
  readonly budgetMs?: number;
  readonly skipLint?: boolean;
  /** Open `index.html` after scan (local report hub). */
  readonly open?: boolean;
  /** Write trusted-issue fingerprint baseline for future delta runs. */
  readonly saveBaseline?: boolean;
  /** File with one repo-relative path per line to scope `audit-summary.md` (optional). */
  readonly prScopeFile?: string;
}

function parseBudget(value: string | undefined): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1000) {
    process.stderr.write('[project-inspector] --budget-ms must be a number >= 1000.\n');
    exit(1);
  }
  return Math.floor(numeric);
}

async function emitFormatOutput(result: ScanResult, outDir: string, format: OutputFormat): Promise<void> {
  if (format === 'sarif') {
    await writeSarifReport(result, outDir);
    return;
  }
  if (format === 'json') {
    await writeFile(resolve(outDir, 'results.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  }
}

async function executeScan(opts: SharedScanCliOptions): Promise<{ result: ScanResult; outDir: string }> {
  const projectDir = resolveProjectPath(opts.project, opts.cwd);
  const outDir = resolve(opts.out ?? defaultReportDir(projectDir));
  assertSafeOutDir(projectDir, outDir);
  const result = await runScan({
    cwd: projectDir,
    outDir,
    concurrency: opts.concurrency,
    mode: opts.mode,
    online: opts.online ?? false,
    incremental: opts.rescan === true ? false : (opts.incremental ?? false),
    useFileCache: opts.rescan === true ? false : opts.noCache !== true,
    ...(opts.rescan === true ? { rescan: true as const } : {}),
    ...(opts.offline !== undefined ? { offline: opts.offline } : {}),
    ...(opts.autoUpdateDb !== undefined ? { autoUpdateDb: opts.autoUpdateDb } : {}),
    ...(opts.budgetMs !== undefined ? { budgetMs: opts.budgetMs } : {}),
    ...(opts.skipLint !== undefined ? { skipLint: opts.skipLint } : {}),
    ...(opts.saveBaseline === true ? { saveBaseline: true as const } : {}),
    ...(opts.prScopeFile !== undefined && opts.prScopeFile.length > 0 ? { prScopeFile: opts.prScopeFile } : {}),
  });
  await emitFormatOutput(result, outDir, opts.format);
  await appendGithubStepSummary(result);
  return { result, outDir };
}

const program = new Command();

program
  .name('project-inspector')
  .description('Offline-first static analysis CLI')
  .version(pkgVersion);

addSharedScanOptions(
  program
    .command('scan')
    .description('Run the scanner and write project-report/'),
)
  .option('--open', 'open index.html in a browser after scan', false)
  .option('--save-baseline', 'save trusted-issue fingerprint baseline for delta tracking', false)
  .option(
    '--pr-scope-file <path>',
    'file listing repo-relative paths (one per line) to scope audit-summary.md output',
  )
  .action(async (opts: SharedScanCliOptions) => {
    const { result, outDir } = await executeScan(opts);
    process.stdout.write(`\n${formatScanBoxSummary(result)}\n`);
    process.stdout.write(`\nReport: ${resolve(outDir, 'index.html')}\n`);
    if (opts.open === true) {
      openReportPreview(outDir);
    }
  });

addSharedScanOptions(
  program
    .command('check')
    .description('Run the scan and fail on blocking conditions'),
)
  .option('--save-baseline', 'save trusted-issue fingerprint baseline for delta tracking', false)
  .option(
    '--pr-scope-file <path>',
    'file listing repo-relative paths (one per line) to scope audit-summary.md output',
  )
  .action(async (opts: SharedScanCliOptions) => {
    const { result, outDir } = await executeScan(opts);
    process.stdout.write(`\n${formatScanBoxSummary(result)}\n`);
    process.stdout.write(`\nReport: ${resolve(outDir, 'index.html')}\n`);
    const gate = runCheckGate(result);
    if (gate.passed) {
      exit(0);
    }
    process.stderr.write('\nCheck failed:\n');
    for (const failure of gate.failures) {
      process.stderr.write(`  ${chalk.red('✖')} ${failure.reason} (${failure.file}:${String(failure.line)})\n`);
    }
    exit(1);
  });

program
  .command('chat')
  .description('Offline REPL over project-report markdown and merged-scan cache')
  .option('--project <path>', 'project root path')
  .option('-c, --cwd <path>', 'alias for --project')
  .action(async (opts: { project?: string; cwd?: string }) => {
    await runChatCommand(resolveProjectPath(opts.project, opts.cwd));
  });

program
  .command('clear')
  .description('Remove project-report and cache state')
  .option('--project <path>', 'project root path')
  .option('-c, --cwd <path>', 'alias for --project')
  .option('-o, --out <dir>', 'output directory')
  .action(async (opts: { project?: string; cwd?: string; out?: string }) => {
    const projectDir = resolveProjectPath(opts.project, opts.cwd);
    const outDir = resolve(opts.out ?? defaultReportDir(projectDir));
    assertSafeOutDir(projectDir, outDir);
    await clearProjectReportDir(outDir);
    process.stdout.write(`Removed ${outDir}\n`);
  });

addSharedScanOptions(
  program
    .command('watch')
    .description('Watch source files and re-run scan'),
).action(async (opts: SharedScanCliOptions) => {
  const projectDir = resolveProjectPath(opts.project, opts.cwd);
  const outDir = resolve(opts.out ?? defaultReportDir(projectDir));
  assertSafeOutDir(projectDir, outDir);
  await runWatchCommand({
    cwd: projectDir,
    outDir,
    concurrency: opts.concurrency,
    mode: opts.mode,
    online: opts.online ?? false,
    incremental: opts.rescan === true ? false : (opts.incremental ?? false),
    useFileCache: opts.rescan === true ? false : opts.noCache !== true,
    rescan: opts.rescan === true,
    ...(opts.offline !== undefined ? { offline: opts.offline } : {}),
    ...(opts.autoUpdateDb !== undefined ? { autoUpdateDb: opts.autoUpdateDb } : {}),
    outputFormat: opts.format,
    ...(opts.budgetMs !== undefined ? { budgetMs: opts.budgetMs } : {}),
    ...(opts.skipLint !== undefined ? { skipLint: opts.skipLint } : {}),
  });
});

program
  .command('update-vuln-db')
  .description('Refresh the local vulnerability override database')
  .option('--project <path>', 'project root path')
  .option('-c, --cwd <path>', 'alias for --project')
  .option('-o, --out <dir>', 'output directory')
  .action(async (opts: { project?: string; cwd?: string; out?: string }) => {
    const projectDir = resolveProjectPath(opts.project, opts.cwd);
    const outDir = resolve(opts.out ?? defaultReportDir(projectDir));
    assertSafeOutDir(projectDir, outDir);
    const update = await runUpdateVulnDbCommand(outDir);
    if (update.ok) {
      process.stdout.write(`${update.message}\n`);
      exit(0);
    }
    process.stderr.write(`${update.message}\n`);
    exit(1);
  });

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    logger.error({ err: error }, 'cli failed');
    process.stderr.write(`[project-inspector] ${error instanceof Error ? error.message : String(error)}\n`);
    exit(1);
  }
}

void main();
