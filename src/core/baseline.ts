import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

import type { BaselineComparison, BaselineHistoryEntry, Issue } from './types.js';

export const BASELINE_CACHE_FILE = 'baseline-trusted.json';
export const BASELINE_HISTORY_FILE = 'baseline-history.json';

const BASELINE_HISTORY_MAX = 10;

interface BaselineFileV1 {
  readonly version: 1;
  readonly savedAt: string;
  readonly fingerprints: readonly string[];
}

function relPosix(cwd: string, file: string): string {
  return relative(cwd, file).replaceAll('\\', '/');
}

/** Stable id for delta when title/code drift slightly. */
export function fingerprintTrustedIssue(cwd: string, issue: Issue): string {
  const rel = relPosix(cwd, issue.file);
  const rule = issue.code ?? issue.title;
  return `${issue.engine}::${rule}::${rel}::${String(issue.line)}`;
}

export async function loadBaselineTrusted(outDir: string): Promise<BaselineFileV1 | undefined> {
  const path = join(outDir, '.cache', BASELINE_CACHE_FILE);
  try {
    const raw = await readFile(path, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null) {
      return undefined;
    }
    const rec = parsed as Record<string, unknown>;
    if (rec.version !== 1 || !Array.isArray(rec.fingerprints) || typeof rec.savedAt !== 'string') {
      return undefined;
    }
    const fps = rec.fingerprints.filter((fp): fp is string => typeof fp === 'string');
    return { version: 1, savedAt: rec.savedAt, fingerprints: fps };
  } catch {
    return undefined;
  }
}

export async function saveBaselineTrusted(outDir: string, trusted: readonly Issue[], cwd: string): Promise<void> {
  const dir = join(outDir, '.cache');
  await mkdir(dir, { recursive: true });
  const fingerprints = [...new Set(trusted.map((i) => fingerprintTrustedIssue(cwd, i)))].sort();
  const previous = await loadBaselineTrusted(outDir);
  const payload: BaselineFileV1 = {
    version: 1,
    savedAt: new Date().toISOString(),
    fingerprints,
  };
  await writeFile(join(outDir, '.cache', BASELINE_CACHE_FILE), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  let newVsPrevious: number | undefined;
  if (previous !== undefined) {
    const prevSet = new Set(previous.fingerprints);
    newVsPrevious = fingerprints.filter((f) => !prevSet.has(f)).length;
  }
  await appendBaselineHistory(outDir, {
    savedAt: payload.savedAt,
    fingerprintCount: fingerprints.length,
    ...(newVsPrevious !== undefined ? { newVsPrevious } : {}),
  });
}

async function appendBaselineHistory(outDir: string, entry: BaselineHistoryEntry): Promise<void> {
  const path = join(outDir, '.cache', BASELINE_HISTORY_FILE);
  let history: BaselineHistoryEntry[] = [];
  try {
    const raw = await readFile(path, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed)) {
      history = parsed.filter(
        (h): h is BaselineHistoryEntry =>
          typeof h === 'object' &&
          h !== null &&
          typeof (h as BaselineHistoryEntry).savedAt === 'string' &&
          typeof (h as BaselineHistoryEntry).fingerprintCount === 'number',
      );
    }
  } catch {
    history = [];
  }
  history.unshift(entry);
  history = history.slice(0, BASELINE_HISTORY_MAX);
  await writeFile(path, `${JSON.stringify({ version: 1 as const, entries: history }, null, 2)}\n`, 'utf8');
}

export async function loadBaselineHistory(outDir: string): Promise<readonly BaselineHistoryEntry[]> {
  try {
    const raw = await readFile(join(outDir, '.cache', BASELINE_HISTORY_FILE), 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null) {
      return [];
    }
    const rec = parsed as Record<string, unknown>;
    if (rec.version === 1 && Array.isArray(rec.entries)) {
      return rec.entries.filter(
        (h): h is BaselineHistoryEntry =>
          typeof h === 'object' &&
          h !== null &&
          typeof (h as BaselineHistoryEntry).savedAt === 'string',
      );
    }
  } catch {
    /* empty */
  }
  return [];
}

export function compareTrustedToBaseline(
  cwd: string,
  trusted: readonly Issue[],
  baseline: BaselineFileV1 | undefined,
): BaselineComparison | undefined {
  if (baseline === undefined) {
    return undefined;
  }
  const prev = new Set(baseline.fingerprints);
  const nowFp = trusted.map((i) => fingerprintTrustedIssue(cwd, i));
  const now = new Set(nowFp);
  let newCount = 0;
  for (const n of now) {
    if (!prev.has(n)) {
      newCount += 1;
    }
  }
  let resolvedCount = 0;
  for (const p of prev) {
    if (!now.has(p)) {
      resolvedCount += 1;
    }
  }
  const unchangedCount = nowFp.length - newCount;
  return {
    baselineSavedAt: baseline.savedAt,
    newCount,
    resolvedCount,
    unchangedCount,
  };
}
