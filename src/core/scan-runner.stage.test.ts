import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';
import { after, before, describe, it } from 'node:test';

import { scanFingerprint, resolveCache, defaultReportDir } from './scan-runner.js';
import type { ScanResult } from './types.js';

// ─── scanFingerprint ──────────────────────────────────────────────────────────

describe('scanFingerprint', () => {
  function minimalResult(overrides?: {
    filesAnalyzed?: number;
    trustedCount?: number;
    readiness?: number;
    finishedAt?: string;
  }): ScanResult {
    return {
      ast: { filesAnalyzed: overrides?.filesAnalyzed ?? 10, functions: [], issues: [], importGraph: [], circularDependencyChains: [] },
      trustedIssues: Array.from({ length: overrides?.trustedCount ?? 5 }, (_, i) => ({
        id: `issue-${i}`, engine: 'security', title: 'T', severity: 'LOW' as const,
        file: '/a.ts', line: 1, description: '', impact: '', fix: '',
      })),
      scores: {
        security: 80, performance: 80, codeQuality: 80, compliance: 80, tests: 80,
        productionReadiness: overrides?.readiness ?? 75,
      },
      finishedAt: overrides?.finishedAt ?? '2025-01-01T00:00:00.000Z',
    } as unknown as ScanResult;
  }

  it('returns a non-empty hex string', () => {
    const fp = scanFingerprint(minimalResult());
    assert.ok(fp.length > 0);
    assert.match(fp, /^[0-9a-f]+$/);
  });

  it('is stable — same inputs produce the same fingerprint', () => {
    const r = minimalResult();
    assert.equal(scanFingerprint(r), scanFingerprint(r));
  });

  it('differs when filesAnalyzed changes', () => {
    const a = scanFingerprint(minimalResult({ filesAnalyzed: 10 }));
    const b = scanFingerprint(minimalResult({ filesAnalyzed: 11 }));
    assert.notEqual(a, b);
  });

  it('differs when productionReadiness changes', () => {
    const a = scanFingerprint(minimalResult({ readiness: 70 }));
    const b = scanFingerprint(minimalResult({ readiness: 71 }));
    assert.notEqual(a, b);
  });

  it('differs when finishedAt changes', () => {
    const a = scanFingerprint(minimalResult({ finishedAt: '2025-01-01T00:00:00.000Z' }));
    const b = scanFingerprint(minimalResult({ finishedAt: '2025-06-01T00:00:00.000Z' }));
    assert.notEqual(a, b);
  });
});

// ─── defaultReportDir ─────────────────────────────────────────────────────────

describe('defaultReportDir', () => {
  it('returns a path inside the given cwd', () => {
    const cwd = join(os.tmpdir(), 'my-project');
    const dir = defaultReportDir(cwd);
    assert.ok(dir.startsWith(cwd), `expected ${dir} to start with ${cwd}`);
  });
});

// ─── resolveCache — cold-start path ──────────────────────────────────────────

let testDir: string;

before(async () => {
  testDir = join(os.tmpdir(), `pi-cache-test-${randomUUID()}`);
  await mkdir(testDir, { recursive: true });
});

after(async () => {
  await rm(testDir, { recursive: true, force: true });
});

describe('resolveCache', () => {
  it('returns coldStart=true when no cache files exist (fresh directory)', async () => {
    const state = await resolveCache({
      cwd: testDir,
      outDir: testDir,
      useFileCache: true,
    });
    assert.equal(state.coldStart, true, 'fresh dir should always be a cold start');
    assert.equal(state.previousMerged, undefined);
  });

  it('returns coldStart=true when rescan=true regardless of existing cache', async () => {
    const state = await resolveCache({
      cwd: testDir,
      outDir: testDir,
      rescan: true,
      useFileCache: true,
    });
    assert.equal(state.coldStart, true);
  });

  it('returns coldStart=true when useFileCache=false', async () => {
    const state = await resolveCache({
      cwd: testDir,
      outDir: testDir,
      useFileCache: false,
    });
    assert.equal(state.coldStart, true);
  });

  it('returns empty previousHashes when no cache exists', async () => {
    const state = await resolveCache({
      cwd: testDir,
      outDir: testDir,
      useFileCache: true,
    });
    assert.deepEqual(state.previousHashes, {});
  });
});
