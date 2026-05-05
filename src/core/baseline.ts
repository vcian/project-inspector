import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

import type { BaselineComparison, Issue } from './types.js';

export const BASELINE_CACHE_FILE = 'baseline-trusted.json';

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
  const payload: BaselineFileV1 = {
    version: 1,
    savedAt: new Date().toISOString(),
    fingerprints,
  };
  await writeFile(join(outDir, '.cache', BASELINE_CACHE_FILE), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
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
