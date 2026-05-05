import type { ApiRouteInfo, Issue, ScoreAxisDiagnostics, ScoreDiagnostics, Scores } from './types.js';

const AXIS_WEIGHTS = {
  security: 0.4,
  performance: 0.15,
  codeQuality: 0.15,
  compliance: 0.15,
  tests: 0.15,
} as const;

/** Populated during each scan for summary “signal vs noise” (writers read this). */
export interface ScanReportingMetrics {
  rawGatherCount: number;
  pipelineOutCount: number;
  dedupedCount: number;
}

export const scanReportingMetrics: ScanReportingMetrics = {
  rawGatherCount: 0,
  pipelineOutCount: 0,
  dedupedCount: 0,
};

/** True after `resetScanReportingMetrics()` for the current scan (even when counts are zero). */
let scanReportingMetricsActive = false;

export function resetScanReportingMetrics(): void {
  scanReportingMetrics.rawGatherCount = 0;
  scanReportingMetrics.pipelineOutCount = 0;
  scanReportingMetrics.dedupedCount = 0;
  scanReportingMetricsActive = true;
}

export function noteRawGatherIssueCount(count: number): void {
  scanReportingMetrics.rawGatherCount = count;
}

export function notePipelineAndDedupedCounts(piped: number, deduped: number): void {
  scanReportingMetrics.pipelineOutCount = piped;
  scanReportingMetrics.dedupedCount = deduped;
}

export function scanReportingMetricsAreFresh(): boolean {
  return scanReportingMetricsActive;
}

const SECURITY_ENGINES = new Set(['security', 'dependency', 'env', 'database']);
const PERF_ENGINES = new Set(['performance', 'memory']);
const QUALITY_ENGINES = new Set(['ast', 'code-smell']);
const COMPLIANCE_ENGINES = new Set(['api', 'outdated', 'migration']);
const TEST_ENGINES = new Set(['test', 'tests']);

function deductSecurity(score: number, issue: Issue): number {
  let d = 0;
  if (issue.severity === 'CRITICAL') {
    d = 25;
  } else if (issue.severity === 'HIGH') {
    d = 10;
  } else if (issue.severity === 'MEDIUM') {
    d = 3;
  } else {
    d = 1;
  }
  return Math.max(0, score - d);
}

function deductOtherAxis(score: number, issue: Issue): number {
  let d = 0;
  if (issue.severity === 'CRITICAL') {
    d = 18;
  } else if (issue.severity === 'HIGH') {
    d = 7;
  } else if (issue.severity === 'MEDIUM') {
    d = 3;
  } else {
    d = 1;
  }
  return Math.max(0, score - d);
}

/**
 * Collapse repeated findings (same engine + rule key + title) across files/lines.
 * Representative keeps first occurrence; description notes volume.
 */
export function deduplicateIssues(issues: readonly Issue[]): Issue[] {
  const groups = new Map<string, Issue[]>();
  for (const issue of issues) {
    const ruleKey = issue.code ?? '_';
    const key = `${issue.engine}::${ruleKey}::${issue.title}`;
    const list = groups.get(key);
    if (list === undefined) {
      groups.set(key, [issue]);
    } else {
      list.push(issue);
    }
  }

  const result: Issue[] = [];
  for (const [, group] of groups) {
    const rep = group[0];
    if (rep === undefined) {
      continue;
    }
    if (group.length === 1) {
      result.push(rep);
    } else {
      const fileCount = new Set(group.map((i) => i.file)).size;
      result.push({
        ...rep,
        id: `${rep.id}-grouped`,
        description: `${rep.description} _(${String(group.length)} occurrences across ${String(fileCount)} file(s))_`,
        count: group.length,
      });
    }
  }

  return result;
}

function severityRankForHotspot(severity: Issue['severity']): number {
  if (severity === 'CRITICAL') {
    return 4;
  }
  if (severity === 'HIGH') {
    return 3;
  }
  if (severity === 'MEDIUM') {
    return 2;
  }
  return 1;
}

/** Unique file count for a deduped row (parses grouped description when present). */
function affectedFileCountForHotspot(issue: Issue): number {
  const m = issue.description.match(/across (\d+) file/i);
  if (m?.[1] !== undefined) {
    const n = Number(m[1]);
    return Number.isFinite(n) && n > 0 ? n : 1;
  }
  return 1;
}

function hotspotScore(issue: Issue): number {
  const severityWeight = severityRankForHotspot(issue.severity);
  const affectedFileCount = affectedFileCountForHotspot(issue);
  const complianceTagCount = issue.compliance?.length ?? 0;
  return severityWeight * 25 + affectedFileCount + complianceTagCount * 0.5;
}

export interface ScoreScanMeta {
  readonly testFileCount: number;
  readonly sourceFileCount: number;
}

function countForAxis(issues: readonly Issue[], engines: ReadonlySet<string>): ScoreAxisDiagnostics {
  const matched = issues.filter((i) => engines.has(i.engine));
  const enginesRepresented = [...new Set(matched.map((i) => i.engine))].sort((a, b) => a.localeCompare(b));
  return { contributingTrustedIssueCount: matched.length, enginesRepresented };
}

/**
 * Per-axis trusted counts so **0** is read as “heavy deductions”, not “axis disabled”.
 */
export function buildScoreDiagnostics(issues: readonly Issue[]): ScoreDiagnostics {
  return {
    version: 1,
    axes: {
      security: countForAxis(issues, SECURITY_ENGINES),
      performance: countForAxis(issues, PERF_ENGINES),
      codeQuality: countForAxis(issues, QUALITY_ENGINES),
      compliance: countForAxis(issues, COMPLIANCE_ENGINES),
      tests: countForAxis(issues, TEST_ENGINES),
    },
    readinessWeightNotes:
      'Production readiness blends axes: **security 40%**, **compliance 15%**, **code quality 15%**, **performance 15%**, **tests 15%**. Each axis starts at **100**; trusted findings mapped to that axis deduct by severity. **0 means many stacked deductions on that axis — engines ran; the axis was scored.**',
  };
}

export function computeScores(issues: readonly Issue[], meta?: ScoreScanMeta): Scores {
  let security = 100;
  let performance = 100;
  let codeQuality = 100;
  let compliance = 100;
  let tests = 100;

  for (const issue of issues) {
    const eng = issue.engine;
    if (SECURITY_ENGINES.has(eng)) {
      security = deductSecurity(security, issue);
    } else if (PERF_ENGINES.has(eng)) {
      performance = deductOtherAxis(performance, issue);
    } else if (QUALITY_ENGINES.has(eng)) {
      codeQuality = deductOtherAxis(codeQuality, issue);
    } else if (COMPLIANCE_ENGINES.has(eng)) {
      compliance = deductOtherAxis(compliance, issue);
    } else if (TEST_ENGINES.has(eng)) {
      tests = deductOtherAxis(tests, issue);
    }
  }

  if (meta !== undefined && meta.testFileCount === 0 && meta.sourceFileCount > 20) {
    tests = Math.min(tests, 35);
  }

  const clampedSecurity = Math.round(Math.max(0, Math.min(100, security)));
  const clampedPerformance = Math.round(Math.max(0, Math.min(100, performance)));
  const clampedCodeQuality = Math.round(Math.max(0, Math.min(100, codeQuality)));
  const clampedCompliance = Math.round(Math.max(0, Math.min(100, compliance)));
  const clampedTests = Math.round(Math.max(0, Math.min(100, tests)));

  let productionReadiness = Math.round(
    clampedSecurity * AXIS_WEIGHTS.security +
      clampedCompliance * AXIS_WEIGHTS.compliance +
      clampedCodeQuality * AXIS_WEIGHTS.codeQuality +
      clampedPerformance * AXIS_WEIGHTS.performance +
      clampedTests * AXIS_WEIGHTS.tests,
  );
  productionReadiness = Math.max(0, Math.min(100, productionReadiness));

  const hasCriticalSecurity = issues.some(
    (i) => i.severity === 'CRITICAL' && SECURITY_ENGINES.has(i.engine),
  );
  if (hasCriticalSecurity) {
    productionReadiness = Math.min(productionReadiness, 40);
  }

  if (meta !== undefined && meta.testFileCount === 0 && meta.sourceFileCount > 20) {
    productionReadiness = Math.min(productionReadiness, 50);
  }

  const envLeak = issues.some(
    (i) =>
      i.engine === 'env' &&
      (i.severity === 'HIGH' || i.severity === 'CRITICAL') &&
      /leak|exposed|secret|credential|private|token|key/i.test(`${i.title} ${i.description}`),
  );
  if (envLeak) {
    productionReadiness = Math.min(productionReadiness, 30);
  }

  return {
    security: clampedSecurity,
    performance: clampedPerformance,
    codeQuality: clampedCodeQuality,
    compliance: clampedCompliance,
    tests: clampedTests,
    productionReadiness,
  };
}

export function computeHotspots(issues: readonly Issue[], routes: readonly ApiRouteInfo[]): Issue[] {
  void routes;
  return [...issues]
    .sort((a, b) => hotspotScore(b) - hotspotScore(a))
    .slice(0, 10);
}
