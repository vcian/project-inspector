import { relative } from 'node:path';

import { buildAttackChainNarrative } from './attack-chain.js';
import { evaluateCheckGates } from './check-gate.js';
import type {
  Issue,
  ProductionDecision,
  ProductionDecisionTopItem,
  ProductionVerdict,
  Scores,
  ScanResult,
} from './types.js';

function severityRank(s: Issue['severity']): number {
  if (s === 'CRITICAL') {
    return 4;
  }
  if (s === 'HIGH') {
    return 3;
  }
  if (s === 'MEDIUM') {
    return 2;
  }
  return 1;
}

function verificationHint(issue: Issue): string {
  if (issue.engine === 'lint') {
    return 'Run `npm run lint` / `npm run typecheck` (or project equivalents) until clean; re-scan.';
  }
  if (issue.engine === 'dependency' || issue.engine === 'outdated') {
    return 'Bump or replace the dependency, refresh the lockfile, run `npm audit` if online, then re-scan.';
  }
  if (issue.engine === 'database') {
    return 'Add/adjust a focused test that exercises the query path with fixtures; re-run scan.';
  }
  if (issue.engine === 'security' || issue.engine === 'env') {
    return 'Patch the sink, add regression coverage, then re-run `project-inspector scan`.';
  }
  return 'Re-run `project-inspector scan` after change; add or extend a unit test for the touched module.';
}

function pickTopTrusted(cwd: string, trusted: readonly Issue[], limit: number): ProductionDecisionTopItem[] {
  const sorted = [...trusted].sort((a, b) => {
    const d = severityRank(b.severity) - severityRank(a.severity);
    if (d !== 0) {
      return d;
    }
    return b.impact.length - a.impact.length;
  });
  const out: ProductionDecisionTopItem[] = [];
  const seen = new Set<string>();
  for (const issue of sorted) {
    const key = `${issue.engine}:${issue.title}:${issue.file}:${String(issue.line)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push({
      rank: out.length + 1,
      severity: issue.severity,
      relFile: relative(cwd, issue.file).replaceAll('\\', '/'),
      line: issue.line,
      title: issue.title,
      engine: issue.engine,
      rootCause: issue.whyItMatters ?? issue.description,
      fix: issue.fix,
      verify: verificationHint(issue),
      attackChain: buildAttackChainNarrative(issue),
    });
    if (out.length >= limit) {
      break;
    }
  }
  return out;
}

function verdictFrom(
  scores: Scores,
  trusted: readonly Issue[],
  minReadiness: number,
  minSecurity: number,
): ProductionVerdict {
  const critical = trusted.some((i) => i.severity === 'CRITICAL');
  if (critical || scores.productionReadiness < minReadiness || scores.security < minSecurity) {
    return 'NOT_READY';
  }
  return 'READY';
}

/**
 * Single structured answer: production readiness decision, not a raw issue dump.
 */
export function buildProductionDecision(result: ScanResult, trusted: readonly Issue[], scores: Scores): ProductionDecision {
  const cwd = result.cwd;
  const gate = evaluateCheckGates({ ...result, scores, trustedIssues: trusted });
  const minReadiness = result.gateThresholds?.minProductionReadiness ?? 48;
  const minSecurity = result.gateThresholds?.minSecurityScore ?? 50;
  const verdict: ProductionVerdict = gate.ok
    ? verdictFrom(scores, trusted, minReadiness, minSecurity)
    : 'NOT_READY';
  const top = pickTopTrusted(cwd, trusted, 10);

  const blockers: string[] = [];
  if (verdict === 'NOT_READY') {
    blockers.push('Production readiness score or CRITICAL findings fail the release bar (see gate section).');
  }
  for (const f of gate.failures.slice(0, 8)) {
    blockers.push(`${f.reason} — ${f.fix}`);
  }

  const quickWins: string[] = [];
  for (const t of top.filter((x) => x.severity === 'HIGH' || x.severity === 'CRITICAL').slice(0, 5)) {
    quickWins.push(`Fix **${t.title}** at \`${t.relFile}:${String(t.line)}\` — ${t.fix}`);
  }
  if (quickWins.length === 0 && top.length > 0) {
    quickWins.push(`Address top MEDIUM item: **${top[0]?.title ?? ''}** at \`${top[0]?.relFile ?? ''}:${String(top[0]?.line ?? 0)}\`.`);
  }

  const majorRisks: string[] = [];
  const highCount = trusted.filter((i) => i.severity === 'HIGH').length;
  const medCount = trusted.filter((i) => i.severity === 'MEDIUM').length;
  if (highCount > 0) {
    majorRisks.push(`${String(highCount)} HIGH-severity trusted finding(s) remain — prioritize before scaling traffic.`);
  }
  if (result.tests.testFileCount === 0 && result.tests.sourceFileCount > 20) {
    majorRisks.push('No test files detected for a non-trivial codebase — regression risk on every deploy.');
  }
  if (result.dependency.auditSummary !== undefined && result.dependency.auditSummary.high > 0) {
    majorRisks.push(
      `npm audit reports ${String(result.dependency.auditSummary.high)} high-severity advisories (when online audit ran).`,
    );
  }
  if (medCount > 12) {
    majorRisks.push(`Elevated MEDIUM noise (${String(medCount)} items) — tune suppressions or refactors to sustain velocity.`);
  }

  const nextSteps: string[] = [
    'Triage the **Top 10 issues** below (severity-sorted); ship nothing CRITICAL to production.',
    'Run your test suite and `project-inspector check` in CI on every PR.',
    'For database changes, validate with integration tests and EXPLAIN on hot queries.',
  ];
  if (result.profile?.topology === 'monorepo' || (result.profile?.projects?.length ?? 0) > 1) {
    nextSteps.push('In monorepos, repeat focused scans per package root if boundaries differ.');
  }

  return {
    verdict,
    confidenceNote:
      'Deterministic static heuristics only — confirm with tests, threat modeling, and operational runbooks.',
    blockers: blockers.slice(0, 12),
    quickWins: quickWins.slice(0, 8),
    majorRisks: majorRisks.slice(0, 8),
    nextSteps,
    topCritical: top,
    gateOk: gate.ok,
    readinessScore: scores.productionReadiness,
  };
}
