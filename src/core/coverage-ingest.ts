import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface LcovSummary {
  readonly linesFound: number;
  readonly linesHit: number;
  readonly percentApprox: number;
  readonly filesWithCoverage: number;
}

/** Parse a subset of LCOV for line coverage ratio (best-effort). */
export async function tryReadLcovSummary(cwd: string): Promise<LcovSummary | undefined> {
  const jsonSummary = await tryReadCoverageJsonSummary(cwd);
  if (jsonSummary !== undefined) {
    return jsonSummary;
  }
  const candidates = ['coverage/lcov.info', 'coverage/lcov.dat'];
  for (const rel of candidates) {
    try {
      const text = await readFile(join(cwd, rel), 'utf8');
      return parseLcov(text);
    } catch {
      /* try next */
    }
  }
  return undefined;
}

/** Jest / Vitest `coverage/coverage-summary.json` total lines (when present). */
async function tryReadCoverageJsonSummary(cwd: string): Promise<LcovSummary | undefined> {
  try {
    const raw = await readFile(join(cwd, 'coverage/coverage-summary.json'), 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const total = parsed.total;
    if (typeof total !== 'object' || total === null || Array.isArray(total)) {
      return undefined;
    }
    const lines = (total as Record<string, unknown>).lines;
    if (typeof lines !== 'object' || lines === null) {
      return undefined;
    }
    const lf = (lines as Record<string, unknown>).total;
    const lh = (lines as Record<string, unknown>).covered;
    const linesFound = typeof lf === 'number' ? lf : 0;
    const linesHit = typeof lh === 'number' ? lh : 0;
    const percentApprox = linesFound > 0 ? Math.round((linesHit / linesFound) * 1000) / 10 : 0;
    const filesWithCoverage = Object.keys(parsed).filter((k) => k !== 'total').length;
    return { linesFound, linesHit, percentApprox, filesWithCoverage };
  } catch {
    return undefined;
  }
}

function parseLcov(text: string): LcovSummary {
  let lf = 0;
  let lh = 0;
  let files = 0;
  let inBlock = false;
  for (const line of text.split(/\r?\n/u)) {
    if (line.startsWith('SF:')) {
      inBlock = true;
      files += 1;
      continue;
    }
    if (line.startsWith('end_of_record')) {
      inBlock = false;
      continue;
    }
    if (inBlock && line.startsWith('LF:')) {
      lf += Number(line.slice(3).trim()) || 0;
    }
    if (inBlock && line.startsWith('LH:')) {
      lh += Number(line.slice(3).trim()) || 0;
    }
  }
  const percentApprox = lf > 0 ? Math.round((lh / lf) * 1000) / 10 : 0;
  return { linesFound: lf, linesHit: lh, percentApprox, filesWithCoverage: files };
}
