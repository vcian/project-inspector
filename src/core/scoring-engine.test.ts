import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { computeScores, deduplicateIssues, computeHotspots } from './scoring-engine.js';
import type { Issue } from './types.js';

function makeIssue(overrides: Partial<Issue> = {}): Issue {
  return {
    id: 'test:rule:/src/app.ts:1',
    engine: 'security',
    title: 'Test issue',
    severity: 'MEDIUM',
    file: '/src/app.ts',
    line: 1,
    description: 'Test description',
    impact: 'Test impact',
    fix: 'Test fix',
    ...overrides,
  };
}

// ─── computeScores ────────────────────────────────────────────────────────────

describe('computeScores', () => {
  it('starts every axis at 100 with no issues', () => {
    const s = computeScores([]);
    assert.equal(s.security, 100);
    assert.equal(s.performance, 100);
    assert.equal(s.codeQuality, 100);
    assert.equal(s.compliance, 100);
    assert.equal(s.tests, 100);
    assert.equal(s.productionReadiness, 100);
  });

  it('deducts 25 pts from security for a CRITICAL security issue', () => {
    const s = computeScores([makeIssue({ severity: 'CRITICAL', engine: 'security' })]);
    assert.equal(s.security, 75);
  });

  it('deducts 10 pts from security for a HIGH security issue', () => {
    const s = computeScores([makeIssue({ severity: 'HIGH', engine: 'security' })]);
    assert.equal(s.security, 90);
  });

  it('caps productionReadiness at 40 when there is at least one CRITICAL security issue', () => {
    const s = computeScores([makeIssue({ severity: 'CRITICAL', engine: 'security' })]);
    assert.ok(s.productionReadiness <= 40, `expected ≤40, got ${s.productionReadiness}`);
  });

  it('caps tests at 35 and productionReadiness at 50 for large projects with zero test files', () => {
    const s = computeScores([], { testFileCount: 0, sourceFileCount: 21 });
    assert.ok(s.tests <= 35, `tests should be ≤35, got ${s.tests}`);
    assert.ok(s.productionReadiness <= 50, `readiness should be ≤50, got ${s.productionReadiness}`);
  });

  it('does NOT apply the no-tests cap for small projects (<= 20 source files)', () => {
    const s = computeScores([], { testFileCount: 0, sourceFileCount: 20 });
    assert.equal(s.tests, 100);
  });

  it('caps productionReadiness at 30 on an env-engine credential leak', () => {
    const issue = makeIssue({
      engine: 'env',
      severity: 'HIGH',
      title: 'Exposed API secret',
      description: 'Secret token leaked in .env file',
    });
    const s = computeScores([issue]);
    assert.ok(s.productionReadiness <= 30, `expected ≤30, got ${s.productionReadiness}`);
  });

  it('floors all scores at 0 (never negative)', () => {
    const criticals = Array.from({ length: 10 }, (_, i) =>
      makeIssue({ id: `id-${i}`, severity: 'CRITICAL', engine: 'security' }),
    );
    const s = computeScores(criticals);
    assert.equal(s.security, 0);
    assert.ok(s.productionReadiness >= 0);
  });
});

// ─── deduplicateIssues ────────────────────────────────────────────────────────

describe('deduplicateIssues', () => {
  it('preserves issues with unique engine+title combos', () => {
    const issues = [
      makeIssue({ id: 'a', title: 'Issue A' }),
      makeIssue({ id: 'b', title: 'Issue B' }),
    ];
    assert.equal(deduplicateIssues(issues).length, 2);
  });

  it('merges duplicates (same engine + title) across files into one grouped issue', () => {
    const title = 'eval() usage';
    const dupes = [
      makeIssue({ id: '1', title, file: '/a.ts' }),
      makeIssue({ id: '2', title, file: '/b.ts' }),
      makeIssue({ id: '3', title, file: '/c.ts' }),
    ];
    const result = deduplicateIssues(dupes);
    assert.equal(result.length, 1);
    assert.match(result[0]!.description, /3 occurrences/);
    assert.match(result[0]!.description, /3 file/);
  });

  it('treats the same title on different engines as distinct rules', () => {
    const a = makeIssue({ id: '1', title: 'Blocking call', engine: 'security' });
    const b = makeIssue({ id: '2', title: 'Blocking call', engine: 'performance' });
    assert.equal(deduplicateIssues([a, b]).length, 2);
  });

  it('sets count on the grouped representative', () => {
    const title = 'Hardcoded secret';
    const dupes = Array.from({ length: 5 }, (_, i) =>
      makeIssue({ id: `d-${i}`, title, file: `/file${i}.ts` }),
    );
    const result = deduplicateIssues(dupes);
    assert.equal(result[0]!.count, 5);
  });

  it('returns an empty array for an empty input', () => {
    assert.deepEqual(deduplicateIssues([]), []);
  });
});

// ─── computeHotspots ─────────────────────────────────────────────────────────

describe('computeHotspots', () => {
  it('returns at most 10 items regardless of input size', () => {
    const issues = Array.from({ length: 20 }, (_, i) =>
      makeIssue({ id: `h-${i}`, title: `Issue ${i}`, severity: 'HIGH' }),
    );
    assert.ok(computeHotspots(issues, []).length <= 10);
  });

  it('ranks CRITICAL above LOW', () => {
    const issues = [
      makeIssue({ id: 'low', severity: 'LOW', title: 'Low issue' }),
      makeIssue({ id: 'crit', severity: 'CRITICAL', title: 'Critical issue' }),
    ];
    const hotspots = computeHotspots(issues, []);
    assert.equal(hotspots[0]!.severity, 'CRITICAL');
  });

  it('returns an empty array for an empty input', () => {
    assert.deepEqual(computeHotspots([], []), []);
  });
});
