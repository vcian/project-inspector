import chokidar from 'chokidar';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { runScan } from '../core/scan-runner.js';
import type { ScanMode, ScanResult } from '../core/types.js';
import { writeSarifReport } from '../reports/sarif-writer.js';

export interface WatchCommandOptions {
  readonly cwd: string;
  readonly outDir: string;
  readonly concurrency: number;
  readonly mode: ScanMode;
  readonly online: boolean;
  readonly incremental: boolean;
  readonly useFileCache: boolean;
  /** When true, each scan run behaves like CLI `--rescan`. */
  readonly rescan?: boolean;
  readonly offline?: boolean;
  readonly autoUpdateDb?: boolean;
  readonly outputFormat?: 'md' | 'json' | 'sarif';
  readonly budgetMs?: number;
  readonly skipLint?: boolean;
}

async function emitAdditionalOutput(result: ScanResult, outDir: string, format: WatchCommandOptions['outputFormat']): Promise<void> {
  if (format === 'sarif') {
    await writeSarifReport(result, outDir);
    return;
  }
  if (format === 'json') {
    await writeFile(resolve(outDir, 'results.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  }
}

export async function runWatchCommand(options: WatchCommandOptions): Promise<void> {
  const watcher = chokidar.watch(['**/*.{ts,tsx,js,jsx,mjs,cjs}'], {
    cwd: options.cwd,
    ignoreInitial: true,
    ignored: ['**/node_modules/**', '**/dist/**', '**/.next/**'],
  });

  let isScanning = false;
  let rerunQueued = false;
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;

  const runOnce = async (): Promise<void> => {
    const result = await runScan({
      cwd: options.cwd,
      outDir: options.outDir,
      concurrency: options.concurrency,
      mode: options.mode,
      online: options.online,
      incremental: options.incremental,
      useFileCache: options.useFileCache,
      ...(options.rescan === true ? { rescan: true as const } : {}),
      ...(options.offline !== undefined ? { offline: options.offline } : {}),
      ...(options.autoUpdateDb !== undefined ? { autoUpdateDb: options.autoUpdateDb } : {}),
      ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
      ...(options.skipLint !== undefined ? { skipLint: options.skipLint } : {}),
    });
    await emitAdditionalOutput(result, options.outDir, options.outputFormat);
    process.stdout.write(
      `[watch] scan complete: readiness ${String(result.scores.productionReadiness)}/100 -> ${options.outDir}\n`,
    );
  };

  const flushScan = async (): Promise<void> => {
    if (isScanning) {
      rerunQueued = true;
      return;
    }
    isScanning = true;
    try {
      await runOnce();
    } finally {
      isScanning = false;
      if (rerunQueued) {
        rerunQueued = false;
        scheduleScan();
      }
    }
  };

  const scheduleScan = (): void => {
    if (debounceTimer !== undefined) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      debounceTimer = undefined;
      void flushScan();
    }, 1500);
  };

  const shutdown = async (): Promise<void> => {
    if (debounceTimer !== undefined) {
      clearTimeout(debounceTimer);
    }
    await watcher.close();
    process.exit(0);
  };

  process.once('SIGINT', () => {
    void shutdown();
  });
  process.once('SIGTERM', () => {
    void shutdown();
  });

  watcher.on('all', () => {
    scheduleScan();
  });

  await runOnce();
  process.stdout.write(`Watching ${options.cwd} for changes...\n`);
}
