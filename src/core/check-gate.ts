import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { gatherAllIssues } from './issue-collect.js';
import type { CheckFailure, CheckResult, Issue, ScanResult } from './types.js';

function getEffectiveIssues(result: ScanResult): Issue[] {
  if (result.trustedIssues !== undefined) {
    return [...result.trustedIssues];
  }
  return gatherAllIssues(result);
}

export interface GateResult {
  readonly passed: boolean;
  readonly failureReasons: readonly string[];
  readonly failures: readonly CheckFailure[];
}

function evaluateFailures(result: ScanResult): CheckFailure[] {
  const failures: CheckFailure[] = [];
  const allIssues = getEffectiveIssues(result);
  const minReadiness = result.gateThresholds?.minProductionReadiness ?? 48;
  const minSecurity = result.gateThresholds?.minSecurityScore ?? 50;

  if (result.scores.productionReadiness < minReadiness) {
    failures.push({
      file: result.cwd,
      line: 1,
      reason: `Production readiness score ${String(result.scores.productionReadiness)}/100 is below the ${String(minReadiness)} gate.`,
      fix: 'Reduce critical and high-severity findings, then re-run `project-inspector check`.',
    });
  }

  if (result.scores.security < minSecurity) {
    failures.push({
      file: result.cwd,
      line: 1,
      reason: `Security score ${String(result.scores.security)}/100 is below the ${String(minSecurity)} gate.`,
      fix: 'Resolve security, env, dependency, database, and auth-related findings before release.',
    });
  }

  for (const issue of allIssues) {
    if (issue.severity !== 'CRITICAL') {
      continue;
    }
    failures.push({
      file: issue.file,
      line: issue.line,
      reason: `[CRITICAL] ${issue.engine}: ${issue.title}`,
      fix: issue.fix,
    });
  }

  if (result.tests.testFileCount === 0 && result.tests.sourceFileCount > 25) {
    failures.push({
      file: result.cwd,
      line: 1,
      reason: `No tests were detected while ${String(result.tests.sourceFileCount)} source files were scanned.`,
      fix: 'Add unit/integration coverage for critical modules and wire tests into CI.',
    });
  }

  const unique: CheckFailure[] = [];
  const seen = new Set<string>();
  for (const failure of failures) {
    const key = `${failure.file}:${String(failure.line)}:${failure.reason}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(failure);
  }
  return unique;
}

export function runCheckGate(result: ScanResult): GateResult {
  const failures = evaluateFailures(result);
  const gateResult: GateResult = {
    passed: failures.length === 0,
    failureReasons: failures.map((failure) => failure.reason),
    failures,
  };

  mkdirSync(result.outDir, { recursive: true });
  writeFileSync(
    join(result.outDir, 'ci-result.json'),
    `${JSON.stringify(
      {
        passed: gateResult.passed,
        failureReasons: gateResult.failureReasons,
        failures: gateResult.failures,
        scores: {
          security: result.scores.security,
          performance: result.scores.performance,
          codeQuality: result.scores.codeQuality,
          compliance: result.scores.compliance,
          tests: result.scores.tests,
          readiness: result.scores.productionReadiness,
        },
        scannedAt: result.finishedAt,
      },
      null,
      2,
    )}\n`,
    'utf8',
  );

  return gateResult;
}

export function evaluateCheckGates(result: ScanResult): CheckResult {
  const failures = evaluateFailures(result);
  return {
    ok: failures.length === 0,
    failures,
  };
}
