import { readFileSync } from 'node:fs';
import { appendFile, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, normalize, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadBaselineTrusted } from '../core/baseline.js';
import { loadInspectorConfig } from '../core/inspector-config.js';
import { evaluateCheckGates } from '../core/check-gate.js';
import { gatherAllIssues } from '../core/issue-collect.js';
import {
  computeSegmentScores,
  scanReportingMetrics,
  scanReportingMetricsAreFresh,
} from '../core/scoring-engine.js';
import type { ApiRouteInfo, Issue, ScanResult } from '../core/types.js';
import { writeOsvSummary } from '../core/osv-summary.js';
import { buildOpenApi31FromRoutes } from './openapi-export.js';
import { renderPrCommentMarkdown } from './pr-comment.js';
import { writeCycloneDxSbom } from './sbom-writer.js';
import { writeReportIndexHtml } from './html-report.js';
import { writeSarifReport } from './sarif-writer.js';
import { loadCodeOwnersRules, ownerForPath, type CodeOwnersRule } from '../utils/codeowners.js';
import {
  enforceMarkdownLineCap,
  issueConfidenceCell,
  renderBoundedIssuesSection,
  sortIssuesBySeverity,
} from '../report/markdown.js';
import { reportClosingMarkdown, reportDocumentHeader } from '../report/report-presentation.js';

async function copyDecisionSchemaToReport(outDir: string): Promise<void> {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const src = join(here, '..', '..', 'schemas', 'decision.schema.json');
    const body = await readFile(src, 'utf8');
    const destDir = join(outDir, 'schemas');
    await mkdir(destDir, { recursive: true });
    await writeFile(join(destDir, 'decision.schema.json'), body, 'utf8');
  } catch {
    /* optional when running from unusual layouts */
  }
}

function finalizeReport(result: ScanResult, markdownBody: string): string {
  const trimmed = markdownBody.replace(/\s+$/, '');
  return `${trimmed}\n\n${reportClosingMarkdown(result)}`;
}

export type ReportSection =
  | 'summary'
  | 'production-decision'
  | 'security'
  | 'dependencies'
  | 'api'
  | 'architecture'
  | 'performance'
  | 'ast'
  | 'test'
  | 'database';

export const ALL_REPORT_SECTIONS: readonly ReportSection[] = [
  'summary',
  'production-decision',
  'security',
  'dependencies',
  'api',
  'architecture',
  'performance',
  'ast',
  'test',
  'database',
] as const;

const REPORT_FILENAMES: Readonly<Record<ReportSection, string>> = {
  summary: 'summary.md',
  'production-decision': 'production-decision.md',
  security: 'security.md',
  dependencies: 'dependencies.md',
  api: 'api.md',
  architecture: 'architecture.md',
  performance: 'performance.md',
  ast: 'ast.md',
  test: 'test.md',
  database: 'database.md',
};

const LEGACY_MARKDOWN_REPORT_FILES = [
  'memory.md',
  'migration.md',
  'compliance.md',
  'attack-scenarios.md',
  'hotspots.md',
] as const;

/** Issues after false-positive control — used for decision-facing reports. */
function effectiveIssues(result: ScanResult): Issue[] {
  return result.trustedIssues !== undefined ? [...result.trustedIssues] : gatherAllIssues(result);
}

function rel(cwd: string, file: string): string {
  return relative(cwd, file).replaceAll('\\', '/');
}

function segmentRiskSummary(result: ScanResult): Record<string, { readonly CRITICAL: number; readonly HIGH: number; readonly MEDIUM: number; readonly LOW: number }> {
  const trusted = effectiveIssues(result);
  const map = new Map<string, { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number }>();
  for (const issue of trusted) {
    const parts = rel(result.cwd, issue.file).split('/');
    const seg = parts.length > 1 ? parts[0] ?? 'root' : 'root';
    const row = map.get(seg) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    if (issue.severity === 'CRITICAL') {
      row.CRITICAL += 1;
    } else if (issue.severity === 'HIGH') {
      row.HIGH += 1;
    } else if (issue.severity === 'MEDIUM') {
      row.MEDIUM += 1;
    } else {
      row.LOW += 1;
    }
    map.set(seg, row);
  }
  return Object.fromEntries(map);
}

function severityWeight(severity: Issue['severity']): number {
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

function confidenceWeight(confidence: Issue['confidence']): number {
  if (confidence === 'high') {
    return 3;
  }
  if (confidence === 'medium') {
    return 2;
  }
  return 1;
}

function mapBusinessImpact(issue: Issue): { readonly area: string; readonly statement: string } {
  const hay = `${issue.title} ${issue.description} ${issue.impact}`.toLowerCase();
  if (/\b(auth|login|token|jwt|session|oauth|password|guard)\b/.test(hay)) {
    return { area: 'Login/Auth', statement: 'Authentication or authorization paths can fail open/closed.' };
  }
  if (/\b(chat|socket|websocket|message|realtime)\b/.test(hay)) {
    return { area: 'Chat/Realtime', statement: 'Realtime messaging can leak data or become unstable.' };
  }
  if (/\b(payment|billing|invoice|stripe|razorpay|refund)\b/.test(hay)) {
    return { area: 'Billing', statement: 'Payment flows can fail, overcharge, or miss reconciliation.' };
  }
  if (/\b(pi[i]|secret|token|credential|leak|exposure|gdpr|hipaa|privacy)\b/.test(hay)) {
    return { area: 'Data leak risk', statement: 'Sensitive data can be exposed to unauthorized actors.' };
  }
  if (/\b(crash|memory|performance|timeout|latency|availability|dos|block)\b/.test(hay)) {
    return { area: 'Availability', statement: 'Service reliability and latency can degrade under load.' };
  }
  return { area: 'Core service', statement: 'Can cause production instability or quality regressions.' };
}

function estimateEta(issue: Issue): string {
  if (issue.severity === 'CRITICAL') {
    return 'Same day';
  }
  if (issue.severity === 'HIGH') {
    return '1-2 days';
  }
  if (issue.engine === 'dependency' || issue.engine === 'outdated') {
    return '0.5-1 day';
  }
  return '2-5 days';
}

function priorityLabel(issue: Issue): 'P0' | 'P1' | 'P2' | 'P3' {
  if (issue.severity === 'CRITICAL') {
    return 'P0';
  }
  if (issue.severity === 'HIGH') {
    return 'P1';
  }
  if (issue.severity === 'MEDIUM') {
    return 'P2';
  }
  return 'P3';
}

function actionRank(issue: Issue): number {
  const sev = severityWeight(issue.severity) * 100;
  const conf = confidenceWeight(issue.confidence) * 20;
  const mutatingAuthBonus = /\b(post|put|patch|delete)\b/i.test(issue.title) ? 10 : 0;
  return sev + conf + mutatingAuthBonus;
}

function legacyGetBodyValidationFalsePositiveCount(issues: readonly Issue[]): number {
  return issues.filter(
    (i) =>
      i.engine === 'api' &&
      /GET|DELETE|HEAD|OPTIONS/.test(i.title) &&
      /lack DTO|mutating route/i.test(i.title),
  ).length;
}

function formatRouteExamples(routes: readonly ApiRouteInfo[], predicate: (r: ApiRouteInfo) => boolean, max: number): string {
  const picked = routes.filter(predicate).slice(0, max);
  if (picked.length === 0) {
    return '—';
  }
  return picked.map((r) => `${r.method} \`${r.pathPattern}\``).join(', ');
}

function topOwaspIssuesForCode(issues: readonly Issue[], code: string, limit: number): Issue[] {
  const upper = code.toUpperCase();
  const filtered = issues.filter((issue) =>
    (issue.compliance ?? []).some(
      (t) => t.framework === 'OWASP_TOP_10' && t.ruleId.toUpperCase().startsWith(upper),
    ),
  );
  const sorted = sortIssuesBySeverity(filtered);
  const out: Issue[] = [];
  const seen = new Set<string>();
  for (const issue of sorted) {
    const key = `${issue.engine}::${issue.title}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(issue);
    if (out.length >= limit) {
      break;
    }
  }
  return out;
}

function owaspRows(issues: readonly Issue[]): readonly { readonly code: string; readonly name: string; readonly count: number }[] {
  const rows: readonly { readonly code: string; readonly name: string }[] = [
    { code: 'A01', name: 'Broken Access Control' },
    { code: 'A02', name: 'Cryptographic Failures' },
    { code: 'A03', name: 'Injection' },
    { code: 'A04', name: 'Insecure Design' },
    { code: 'A05', name: 'Security Misconfiguration' },
    { code: 'A06', name: 'Vulnerable and Outdated Components' },
    { code: 'A07', name: 'Identification and Authentication Failures' },
    { code: 'A08', name: 'Software and Data Integrity Failures' },
    { code: 'A09', name: 'Security Logging and Monitoring Failures' },
    { code: 'A10', name: 'Server-Side Request Forgery' },
  ];
  return rows.map((row) => ({
    ...row,
    count: issues.filter((issue) =>
      (issue.compliance ?? []).some(
        (tag) => tag.framework === 'OWASP_TOP_10' && tag.ruleId.toUpperCase().startsWith(row.code),
      ),
    ).length,
  }));
}

function badge(score: number): string {
  if (score >= 80) {
    return 'READY';
  }
  if (score >= 60) {
    return 'CAUTION';
  }
  if (score >= 48) {
    return 'AT RISK';
  }
  return 'BLOCKED';
}

function inferRouteFramework(result: ScanResult, route: ApiRouteInfo): string {
  if (route.method === 'CLI') {
    return 'commander';
  }
  const file = route.file.replaceAll('\\', '/').toLowerCase();
  if (file.includes('/app/api/') || file.includes('/pages/api/')) {
    return 'nextjs';
  }
  if (file.includes('.controller.')) {
    return 'nestjs';
  }
  if (file.includes('fastify')) {
    return 'fastify';
  }
  if (file.includes('express') || file.includes('router')) {
    return 'express';
  }
  return result.profile?.primaryFramework ?? 'unknown';
}

function issueEvidencePreview(issue: Issue): string {
  const s = issue.codeSnippet?.replace(/\s+/g, ' ').trim() ?? '';
  if (s.length > 0) {
    return s.slice(0, 100).replaceAll('|', '\\|');
  }
  const c = issue.code?.replace(/\s+/g, ' ').trim() ?? '';
  if (c.length > 0) {
    return c.slice(0, 100).replaceAll('|', '\\|');
  }
  return '—';
}

function renderIssueTable(issues: readonly Issue[], cwd: string): string[] {
  if (issues.length === 0) {
    return ['_No findings in this section._', ''];
  }
  const lines = [
    '| Severity | Engine | Confidence | File | Line | Finding | Evidence | Fix |',
    '| --- | --- | --- | --- | ---: | --- | --- | --- |',
  ];
  for (const issue of issues) {
    lines.push(
      `| ${issue.severity} | ${issue.engine} | ${issueConfidenceCell(issue)} | \`${rel(cwd, issue.file)}\` | ${String(issue.line)} | ${issue.title.replaceAll('|', '\\|')} | ${issueEvidencePreview(issue)} | ${issue.fix.replaceAll('|', '\\|')} |`,
    );
  }
  lines.push('');
  return lines;
}

function buildProductionDecisionDoc(result: ScanResult): string {
  const d = result.productionDecision;
  if (d === undefined) {
    return finalizeReport(
      result,
      [
        reportDocumentHeader(
          result,
          'Production readiness decision',
          '_Structured verdict output was not available for this scan._',
        ),
        '_Decision engine did not run (internal error)._',
      ].join('\n'),
    );
  }
  const topLines = d.topCritical.map(
    (t) =>
      `### \`TOP-${String(t.rank)}\` — **${t.severity}** — ${t.title}\n\n| Field | Value |\n| --- | --- |\n| **Where** | \`${t.relFile}:${String(t.line)}\` |\n| **Engine** | \`${t.engine}\` |\n| **Attack chain** | ${t.attackChain.replaceAll('|', '\\|')} |\n| **Root cause** | ${t.rootCause.replaceAll('|', '\\|')} |\n| **Fix** | ${t.fix.replaceAll('|', '\\|')} |\n| **Verify** | ${t.verify.replaceAll('|', '\\|')} |\n`,
  );
  const trustedAll = effectiveIssues(result);
  const confHigh = trustedAll.filter((i) => i.confidence === 'high').length;
  const confMed = trustedAll.filter((i) => i.confidence === 'medium').length;
  const confLow = trustedAll.filter((i) => i.confidence === 'low' || i.confidence === undefined).length;
  const confTotal = trustedAll.length;
  const pct = (n: number): string =>
    confTotal > 0 ? `${String(Math.round((n / confTotal) * 1000) / 10)}%` : '—';
  return finalizeReport(
    result,
    [
      reportDocumentHeader(
        result,
        'Production readiness decision',
        '_Single-page answer: verdict, blockers, next steps, and top trusted issues._',
      ),
      '## Verdict',
    '',
    `### **${d.verdict.replaceAll('_', ' ')}**`,
    '',
    d.confidenceNote,
    '',
    '### Confidence breakdown (trusted findings)',
    '',
    '| Band | Count | Share |',
    '| --- | ---: | ---: |',
    `| High | ${String(confHigh)} | ${pct(confHigh)} |`,
    `| Medium | ${String(confMed)} | ${pct(confMed)} |`,
    `| Low / unset | ${String(confLow)} | ${pct(confLow)} |`,
    '',
    '_The same structured payload is written to `decision.json` next to this file for CI (`jq .verdict decision.json`) and automation._',
    '',
    '| Gate | Readiness (0–100) |',
    '| --- | ---: |',
    `| CI gate ${d.gateOk ? 'PASS' : 'FAIL'} | ${String(d.readinessScore)} |`,
    '',
    '## Blockers',
    '',
    ...(d.blockers.length ? d.blockers.map((b) => `- ${b}`) : ['_None._']),
    '',
    '## Quick wins',
    '',
    ...(d.quickWins.length ? d.quickWins.map((b) => `- ${b}`) : ['_None listed._']),
    '',
    '## Major risks',
    '',
    ...(d.majorRisks.length ? d.majorRisks.map((b) => `- ${b}`) : ['_None highlighted._']),
    '',
    '## Recommended next steps',
    '',
    ...d.nextSteps.map((b) => `- ${b}`),
    '',
    '## Top issues (trusted set)',
    '',
    ...topLines,
  ].join('\n'),
  );
}

function buildScoreExplanationSection(result: ScanResult): string[] {
  const d = result.scoreDiagnostics;
  const lines = [
    '## How scores work (trust & scope)',
    '',
    '_Each numeric axis starts at **100**. Only **trusted** findings (after `project-inspector.config.json` filters + dedupe) deduct points. **0 on an axis means many stacked deductions — engines ran; the axis was scored.**_',
    '',
  ];
  if (d === undefined) {
    lines.push('_Per-axis diagnostics were not attached to this result._', '');
    return lines;
  }
  lines.push(
    '| Axis | Score | Trusted findings on axis | Engines feeding axis |',
    '| --- | ---: | ---: | --- |',
    `| Security | ${String(result.scores.security)} | ${String(d.axes.security.contributingTrustedIssueCount)} | ${d.axes.security.enginesRepresented.join(', ') || '—'} |`,
    `| Performance | ${String(result.scores.performance)} | ${String(d.axes.performance.contributingTrustedIssueCount)} | ${d.axes.performance.enginesRepresented.join(', ') || '—'} |`,
    `| Code quality | ${String(result.scores.codeQuality)} | ${String(d.axes.codeQuality.contributingTrustedIssueCount)} | ${d.axes.codeQuality.enginesRepresented.join(', ') || '—'} |`,
    `| Compliance | ${String(result.scores.compliance)} | ${String(d.axes.compliance.contributingTrustedIssueCount)} | ${d.axes.compliance.enginesRepresented.join(', ') || '—'} |`,
    `| Tests | ${String(result.scores.tests)} | ${String(d.axes.tests.contributingTrustedIssueCount)} | ${d.axes.tests.enginesRepresented.join(', ') || '—'} |`,
    '',
    d.readinessWeightNotes,
    '',
    '_The **lint** engine may list issues in the trusted set for docs/gates but **does not** decrement the five numeric axes above unless the same finding is also emitted under another engine._',
    '',
  );
  return lines;
}

function buildSummary(result: ScanResult): string {
  const gate = evaluateCheckGates(result);
  const trusted = effectiveIssues(result);
  const allGathered = gatherAllIssues(result);
  const actionableHigh = trusted.filter((i) => i.severity === 'HIGH' || i.severity === 'CRITICAL').length;
  const getValFpRemain = legacyGetBodyValidationFalsePositiveCount(allGathered);
  const metricsFresh = scanReportingMetricsAreFresh();
  const rawForTable = metricsFresh ? scanReportingMetrics.rawGatherCount : allGathered.length;
  const afterFilterForTable = metricsFresh ? scanReportingMetrics.pipelineOutCount : trusted.length;
  const afterDedupForTable = metricsFresh ? scanReportingMetrics.dedupedCount : trusted.length;
  const hotspotLines =
    result.hotspots.length === 0
      ? ['_No hotspots were computed._']
      : result.hotspots.slice(0, 5).map((hotspot) => {
          const chain =
            hotspot.attackChain !== undefined && hotspot.attackChain.length > 0
              ? ` — _${hotspot.attackChain.replaceAll('_', '\\_').slice(0, 140)}${hotspot.attackChain.length > 140 ? '…' : ''}_`
              : '';
          return `- **${hotspot.severity}** ${hotspot.title} at \`${rel(result.cwd, hotspot.file)}:${String(hotspot.line)}\`${chain}`;
        });
  const verdictLine =
    result.productionDecision !== undefined
      ? `**${result.productionDecision.verdict.replaceAll('_', ' ')}** — ${result.productionDecision.confidenceNote}`
      : `**${badge(result.scores.productionReadiness)}** (legacy badge)`;
  const fw = result.profile?.primaryFramework ?? 'unknown';
  const topo = result.profile?.topology ?? 'single';
  const metaSeg = {
    testFileCount: result.tests.testFileCount,
    sourceFileCount: result.tests.sourceFileCount,
  };
  const segmentScores = computeSegmentScores(result.cwd, trusted, metaSeg);
  const segRisk = segmentRiskSummary(result);
  const whatChangedSinceScan =
    result.baselineComparison !== undefined
      ? [
          '## What changed since last scan',
          '',
          `New **${String(result.baselineComparison.newCount)}** · resolved **${String(result.baselineComparison.resolvedCount)}** · unchanged **${String(result.baselineComparison.unchangedCount)}**${result.productionDecision !== undefined ? ` · verdict **${result.productionDecision.verdict}**` : ''}.`,
          '',
        ]
      : [];
  const baselineHistSection =
    result.baselineHistory !== undefined && result.baselineHistory.length > 0
      ? [
          '## Recent baseline snapshots',
          '',
          '| Saved at | Fingerprints | New vs previous |',
          '| --- | --- | ---: |',
          ...[...result.baselineHistory].slice(-12).map((h) => {
            const delta = h.newVsPrevious !== undefined ? String(h.newVsPrevious) : '—';
            return `| ${h.savedAt} | ${String(h.fingerprintCount)} | ${delta} |`;
          }),
          '',
        ]
      : [];
  const segFolderSection =
    Object.keys(segRisk).length > 0
      ? [
          '## Trusted findings by top-level folder',
          '',
          '| Folder | CRITICAL | HIGH | MEDIUM | LOW |',
          '| --- | ---: | ---: | ---: | ---: |',
          ...Object.entries(segRisk)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([k, v]) => `| \`${k.replaceAll('|', '\\|')}\` | ${String(v.CRITICAL)} | ${String(v.HIGH)} | ${String(v.MEDIUM)} | ${String(v.LOW)} |`),
          '',
        ]
      : [];
  const segScoreSection =
    segmentScores.filter((s) => s.segment !== 'root').length > 0
      ? [
          '## Per-folder readiness (monorepo)',
          '',
          '| Folder | Readiness | Security | Trusted issues |',
          '| --- | ---: | ---: | ---: |',
          ...segmentScores.map(
            (s) =>
              `| \`${s.segment.replaceAll('|', '\\|')}\` | ${String(s.productionReadiness)} | ${String(s.security)} | ${String(s.trustedIssueCount)} |`,
          ),
          '',
        ]
      : [];
  const lines = [
    reportDocumentHeader(
      result,
      'Project summary & readiness',
      '_Executive overview: production verdict, scores, signal vs noise, and where to read next._',
    ),
    ...whatChangedSinceScan,
    '## Scan context (heuristic)',
    '',
    `- **Framework (primary):** ${fw} — tune expectations if this is wrong for a library or monorepo leaf package.`,
    `- **Topology:** ${topo}`,
    `- **Scan mode:** \`${result.mode}\` · **Online dependency audit:** ${result.online ? '**yes** (npm audit may run)' : '**no** (offline / quick)'}`,
    '',
    '## Production decision (trusted)',
    '',
    verdictLine,
    '',
    '## Readiness scores (from trusted findings)',
    '',
    `**${badge(result.scores.productionReadiness)}**`,
    '',
    '| Score | Value |',
    '| --- | ---: |',
    `| Security | ${String(result.scores.security)} |`,
    `| Performance | ${String(result.scores.performance)} |`,
    `| Code Quality | ${String(result.scores.codeQuality)} |`,
    `| Compliance | ${String(result.scores.compliance)} |`,
    `| Tests | ${String(result.scores.tests)} |`,
    `| Production Readiness | ${String(result.scores.productionReadiness)} |`,
    '',
    ...buildScoreExplanationSection(result),
    '## Signal vs Noise',
    '',
    '| Metric | Count |',
    '| --- | ---: |',
    `| Issues before deduplication (post-filter pipeline) | ${String(afterFilterForTable)} |`,
    `| Issues after cross-file deduplication (trusted set) | ${String(afterDedupForTable)} |`,
    `| All engine findings merged (pre-pipeline) | ${String(rawForTable)} |`,
    `| GET/HEAD/OPTIONS/DELETE @Body() false positives still present | ${String(getValFpRemain)} |`,
    `| Actionable findings (trusted, HIGH or CRITICAL) | ${String(actionableHigh)} |`,
    '',
    '_GET/DELETE/HEAD/OPTIONS routes are not flagged for missing @Body() validation. Public paths (health, login, webhooks, etc.) skip missing-auth heuristics._',
    '',
    '## Gate status',
    '',
    `- CI gate: ${gate.ok ? 'PASS' : 'FAIL'}`,
    `- Trusted-issue count: ${String(trusted.length)} (after suppressions / test-path filters / dedupe)`,
    `- Critical (trusted): ${String(trusted.filter((issue) => issue.severity === 'CRITICAL').length)}`,
    `- Routes detected: ${String(result.api.routes.length)}`,
    `- Test files: ${String(result.tests.testFileCount)}`,
    `- Source files: ${String(result.tests.sourceFileCount)}`,
    '',
    ...(result.baselineComparison !== undefined
      ? [
          '## Baseline delta (trusted issues)',
          '',
          `- Baseline saved at: ${result.baselineComparison.baselineSavedAt}`,
          `- New since baseline: ${String(result.baselineComparison.newCount)}`,
          `- Resolved since baseline: ${String(result.baselineComparison.resolvedCount)}`,
          `- Unchanged: ${String(result.baselineComparison.unchangedCount)}`,
          '',
          '_Re-run with `--save-baseline` after triage to refresh the stored baseline._',
          '',
        ]
      : []),
    ...baselineHistSection,
    ...segFolderSection,
    ...segScoreSection,
    '## Top 5 hotspots (cross-engine)',
    '',
    ...hotspotLines,
    '',
    '## Trusted finding counts (by severity)',
    '',
    '| Severity | Count |',
    '| --- | ---: |',
    `| CRITICAL | ${String(trusted.filter((i) => i.severity === 'CRITICAL').length)} |`,
    `| HIGH | ${String(trusted.filter((i) => i.severity === 'HIGH').length)} |`,
    `| MEDIUM | ${String(trusted.filter((i) => i.severity === 'MEDIUM').length)} |`,
    `| LOW | ${String(trusted.filter((i) => i.severity === 'LOW').length)} |`,
    '',
    '_Per-engine raw totals still exist inside each engine artifact; scores and gates use the **trusted** set above._',
    '',
    '## Full report index',
    '',
    '- `production-decision.md` — single-page readiness answer',
    '- `action-plan.md` — top 5 prioritized fixes (priority, owner, ETA, status)',
    '- `for-users.md` — plain-language impact + next steps for non-security teams',
    '- `summary.md` — scores, gate, hotspots teaser',
    '- `security.md` — trusted findings, OWASP, compliance detail, hotspots table, threat scenarios',
    '- `dependencies.md` — lockfile, audits, migration-engine hints',
    '- `performance.md` — blocking I/O / throughput + memory-engine signals',
    '- `api.md` — route map and OpenAPI-style digest',
    '- `architecture.md` — ER (Prisma/ORM/SQL), segment↔entity map, API→DB flow, sample HTTP',
    '- `database.md` — SQL/ORM issues and indexing hints',
    '- `ast.md` — complexity hotspots',
    '- `test.md` — test heuristics',
    '- `decision.json` — **machine-readable** verdict (same facts as production-decision) for CI scripts, dashboards, and `jq` — not a duplicate human doc',
    '- `schemas/decision.schema.json` — JSON Schema (draft 2020-12) for validating `decision.json`',
    '- `scores.json` — numeric axes + score diagnostics + segment summary for dashboards',
    '- `index.html` — static **report hub** (open locally; links to Markdown + JSON + SARIF)',
    '- `results.sarif` — SARIF 2.1.0 (trusted findings; written every scan for CI uploads)',
    '- `sbom.cdx.json` — CycloneDX SBOM (from npm lockfile)',
    '- `openapi.json` — OpenAPI **3.1** export from detected routes',
    '- `osv-summary.json` — OSV vulnerability hints (skipped in offline mode)',
    '- `pr-comment.md` — scoped Markdown for PR comments / job summaries',
    '- `governance-suppressions.json` — snapshot of active governance suppressions',
    '',
  ];
  return finalizeReport(result, lines.join('\n'));
}

function truncateCell(text: string, max: number): string {
  const t = text.replaceAll('|', '\\|').replaceAll('\n', ' ');
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function buildSecurity(result: ScanResult): string {
  const bySeverity: readonly Issue['severity'][] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const issues = effectiveIssues(result).filter((issue) =>
    ['security', 'dependency', 'outdated', 'api', 'env', 'database'].includes(issue.engine),
  );
  const crit = issues.filter((i) => i.severity === 'CRITICAL').length;
  const high = issues.filter((i) => i.severity === 'HIGH').length;
  const med = issues.filter((i) => i.severity === 'MEDIUM').length;
  const low = issues.filter((i) => i.severity === 'LOW').length;
  const execRows = sortIssuesBySeverity(issues).slice(0, 18);
  const execTable: string[] = [];
  if (execRows.length > 0) {
    execTable.push(
      '## Executive summary',
      '',
      `Trusted findings in scope for this report: **${String(issues.length)}** (**${String(crit)}** critical, **${String(high)}** high, **${String(med)}** medium, **${String(low)}** low). Suppressions and test-only paths are excluded.`,
      '',
      '| # | Severity | Category | Engine | Location | Finding |',
      '| ---: | --- | --- | --- | --- | --- |',
    );
    execRows.forEach((issue, idx) => {
      const cat = issue.category ?? '—';
      execTable.push(
        `| ${String(idx + 1)} | **${issue.severity}** | ${cat} | \`${issue.engine}\` | \`${rel(result.cwd, issue.file)}:${String(issue.line)}\` | ${truncateCell(issue.title, 72)} |`,
      );
    });
    execTable.push('');
  }
  const lines = [
    reportDocumentHeader(
      result,
      'Security & supply chain review',
      '_Trusted issue set (security, dependency, env, database, API) plus OWASP drill-down, cross-engine hotspots, and threat scenarios. Tune suppressions in `project-inspector.config.json`._',
    ),
    ...execTable,
    '## OWASP Top 10 mapping (trusted)',
    '',
    '| Category | Findings |',
    '| --- | ---: |',
  ];
  for (const row of owaspRows(issues)) {
    lines.push(`| ${row.code} ${row.name} | ${String(row.count)} |`);
  }
  lines.push('', '## Findings by severity (capped per band)', '');
  for (const severity of bySeverity) {
    const matching = issues
      .filter((issue) => issue.severity === severity)
      .slice(0, severity === 'LOW' ? 20 : 35);
    lines.push(`### ${severity}`, '');
    lines.push(...renderIssueTable(matching, result.cwd));
    const omitted = issues.filter((issue) => issue.severity === severity).length - matching.length;
    if (omitted > 0) {
      lines.push(`_…${String(omitted)} more ${severity} finding(s) omitted; tighten code or adjust suppressions._`, '');
    }
  }
  lines.push(...buildOwaspPerCategoryDetailLines(result));
  lines.push(...buildHotspotMarkdownTable(result));
  lines.push(...buildAttackScenariosMarkdownLines(result));
  return finalizeReport(result, lines.join('\n'));
}

function detectPackageName(issue: Issue): string {
  const titleMatch = issue.title.match(/[: ]([@A-Za-z0-9._/-]+)$/);
  if (titleMatch?.[1] !== undefined) {
    return titleMatch[1];
  }
  const descMatch = issue.description.match(/\b([@A-Za-z0-9._/-]+)@/);
  return descMatch?.[1] ?? 'unknown';
}

function dependencyKind(issue: Issue): string {
  const title = issue.title.toLowerCase();
  if (title.includes('deprecated')) {
    return 'deprecated';
  }
  if (title.includes('drift')) {
    return 'drift';
  }
  if (title.includes('vulnerab') || issue.engine === 'dependency') {
    return 'vulnerable';
  }
  return 'outdated';
}

function tryLicenseSampleLines(cwd: string): string[] {
  try {
    const raw = readFileSync(join(cwd, 'package-lock.json'), 'utf8');
    const lock = JSON.parse(raw) as { packages?: Record<string, { license?: string }> };
    const rows: { name: string; license: string }[] = [];
    for (const [pathKey, meta] of Object.entries(lock.packages ?? {})) {
      if (pathKey === '' || meta.license === undefined) {
        continue;
      }
      const tail = pathKey.includes('node_modules/') ? pathKey.split('node_modules/').pop() ?? pathKey : pathKey;
      rows.push({ name: tail, license: meta.license });
    }
    const cap = rows.slice(0, 35);
    if (cap.length === 0) {
      return [];
    }
    return [
      '## License sample (from lockfile)',
      '',
      '| Package | License |',
      '| --- | --- |',
      ...cap.map((r) => `| \`${r.name.replaceAll('|', '\\|')}\` | ${r.license.replaceAll('|', '\\|')} |`),
      '',
      '_Policies like GPL may affect distribution — validate with legal for enterprise use._',
      '',
    ];
  } catch {
    return [];
  }
}

function buildDependencies(result: ScanResult): string {
  const issues = [...result.dependency.issues, ...result.outdated.issues];
  const lines = [
    reportDocumentHeader(
      result,
      'Dependencies review',
      '_Lockfile health, audits, outdated packages, drift signals, and migration-engine upgrade hints._',
    ),
    '## Package Summary',
    '',
    `- Lockfile: \`${result.dependency.lockfileKind}\``,
    `- Workspace manifests: ${String(result.dependency.projectManifestCount ?? 1)}`,
    `- Direct dependency declarations: ${String(result.dependency.directDependencyCount)}`,
    '',
    ...tryLicenseSampleLines(result.cwd),
  ];
  if (result.dependency.auditSummary !== undefined) {
    lines.push(
      '| Audit Severity | Count |',
      '| --- | ---: |',
      `| Critical | ${String(result.dependency.auditSummary.critical)} |`,
      `| High | ${String(result.dependency.auditSummary.high)} |`,
      `| Moderate | ${String(result.dependency.auditSummary.moderate)} |`,
      `| Low | ${String(result.dependency.auditSummary.low)} |`,
      `| Info | ${String(result.dependency.auditSummary.info)} |`,
      '',
    );
  }
  if (issues.length === 0) {
    lines.push('_No dependency findings were emitted._', '');
  } else {
    lines.push(
      '| Package | Kind | Severity | File | Finding |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const issue of issues) {
      lines.push(
        `| ${detectPackageName(issue)} | ${dependencyKind(issue)} | ${issue.severity} | \`${rel(result.cwd, issue.file)}\` | ${issue.title.replaceAll('|', '\\|')} |`,
      );
    }
    lines.push('');
  }
  lines.push('## Migration & upgrade hints (migration engine)', '', ...renderIssueTable(result.migration.issues, result.cwd));
  return finalizeReport(result, lines.join('\n'));
}

export function inferApiOperationId(method: string, pathPattern: string): string {
  const slug = pathPattern
    .replaceAll(/[{}"'`]/g, '')
    .replaceAll(/[/:.-]+/g, '_')
    .replaceAll(/[^A-Za-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  const base = slug.length > 0 ? slug : 'route';
  return `${method.toLowerCase()}_${base}`.slice(0, 88);
}

function buildApi(result: ScanResult): string {
  const routes = result.api.routes;
  const httpRoutes = routes.filter((r) => r.method !== 'CLI');
  const hasCliRoutes = routes.length > httpRoutes.length;
  const lines = [
    reportDocumentHeader(
      result,
      'API surface review',
      '_Route matrix, OpenAPI-style operation digest, auth/validation heuristics, and trusted API findings._',
    ),
    '## Routes',
    '',
  ];
  if (routes.length === 0) {
    lines.push('_No routes were detected._', '');
  } else {
    lines.push(
      '| Method | Path | Access | Auth | Validation | Framework | File |',
      '| --- | --- | --- | --- | --- | --- | --- |',
    );
    for (const route of routes) {
      const access =
        route.accessClassification ??
        (route.authHeuristic === 'likely-open'
          ? 'public'
          : route.authHeuristic === 'likely-protected'
            ? 'authenticated'
            : 'unknown');
      lines.push(
        `| ${route.method} | \`${route.pathPattern}\` | ${access} | ${route.authHeuristic === 'likely-protected' ? 'Y' : route.authHeuristic === 'likely-open' ? 'N' : '?'} | ${route.validationHeuristic === 'likely-present' ? 'Y' : route.validationHeuristic === 'likely-missing' ? 'N' : '?'} | ${inferRouteFramework(result, route)} | \`${rel(result.cwd, route.file)}:${String(route.line)}\` |`,
      );
    }
    lines.push('');
  }

  const classify = (r: ApiRouteInfo): 'public' | 'authenticated' | 'role-based' | 'unknown' =>
    r.accessClassification ??
    (r.authHeuristic === 'likely-open'
      ? 'public'
      : r.authHeuristic === 'likely-protected'
        ? 'authenticated'
        : 'unknown');
  const routeMatrix = {
    public: httpRoutes.filter((r) => classify(r) === 'public'),
    authenticated: httpRoutes.filter((r) => classify(r) === 'authenticated'),
    roleBased: httpRoutes.filter((r) => classify(r) === 'role-based'),
    unknown: httpRoutes.filter((r) => classify(r) === 'unknown'),
  };
  lines.push('## Endpoint access matrix', '', '| Class | Count | Example routes |', '| --- | ---: | --- |');
  lines.push(`| Public | ${String(routeMatrix.public.length)} | ${formatRouteExamples(routeMatrix.public, () => true, 4)} |`);
  lines.push(
    `| Authenticated | ${String(routeMatrix.authenticated.length)} | ${formatRouteExamples(routeMatrix.authenticated, () => true, 4)} |`,
  );
  lines.push(
    `| Role-based | ${String(routeMatrix.roleBased.length)} | ${formatRouteExamples(routeMatrix.roleBased, () => true, 4)} |`,
  );
  lines.push(`| Unknown | ${String(routeMatrix.unknown.length)} | ${formatRouteExamples(routeMatrix.unknown, () => true, 4)} |`);
  lines.push('');

  const guarded = httpRoutes.filter((r) => r.authHeuristic === 'likely-protected');
  const unguarded = httpRoutes.filter((r) => r.authHeuristic !== 'likely-protected');
  lines.push('## Auth Coverage', '', '| Status | Count | Example routes |', '| --- | ---: | --- |');
  lines.push(
    `| ✅ Guarded | ${String(guarded.length)} | ${formatRouteExamples(httpRoutes, (r) => r.authHeuristic === 'likely-protected', 4)} |`,
  );
  lines.push(
    `| ⚠️ Unguarded / unknown | ${String(unguarded.length)} | ${formatRouteExamples(httpRoutes, (r) => r.authHeuristic !== 'likely-protected', 4)} |`,
    '',
  );
  if (hasCliRoutes) {
    lines.push(
      '_Auth counts are **HTTP routes only**; Commander `CLI` rows in the route table are excluded here._',
      '',
    );
  }

  const mutating = httpRoutes.filter((r) => ['POST', 'PUT', 'PATCH'].includes(r.method));
  const mutatingDtoOk = mutating.filter((r) => r.validationHeuristic === 'likely-present');
  const mutatingDtoMissing = mutating.filter((r) => r.validationHeuristic === 'likely-missing');
  lines.push('## Validation Coverage', '', '| Status | Count | Methods |', '| --- | ---: | --- |');
  lines.push(
    `| ✅ Has DTO / validation signal | ${String(mutatingDtoOk.length)} | POST, PUT, PATCH |`,
    `| ⚠️ Missing near handler | ${String(mutatingDtoMissing.length)} | POST, PUT, PATCH only |`,
    '',
  );

  const apiTrusted = effectiveIssues(result).filter((i) => i.engine === 'api');
  const highPri = sortIssuesBySeverity(
    apiTrusted.filter((i) => i.severity === 'HIGH' || i.severity === 'CRITICAL'),
  ).slice(0, 20);
  lines.push('## High-priority API findings (trusted, deduped, severity ≥ HIGH)', '');
  if (highPri.length === 0) {
    lines.push('_No HIGH or CRITICAL API issues in the trusted set._', '');
  } else {
    lines.push('| Severity | Title | File | Line |', '| --- | --- | --- | ---: |');
    for (const issue of highPri) {
      lines.push(
        `| ${issue.severity} | ${issue.title.replaceAll('|', '\\|')} | \`${rel(result.cwd, issue.file)}\` | ${String(issue.line)} |`,
      );
    }
    lines.push('');
  }

  lines.push(
    '## API catalog (OpenAPI-style digest)',
    '',
    '_Static reconstruction from detected routes — complement, not replace, a real `openapi.yaml` / Swagger doc._',
    '',
  );
  if (routes.length === 0) {
    lines.push('_No operations to describe._', '');
  } else {
    const cap = 40;
    for (const route of routes.slice(0, cap)) {
      const opId = inferApiOperationId(route.method, route.pathPattern);
      const fw = inferRouteFramework(result, route);
      const relFile = rel(result.cwd, route.file);
      const tag = relFile.split('/').filter((s) => s.length > 0)[0] ?? 'api';
      lines.push(`### \`${route.method} ${route.pathPattern}\``, '');
      lines.push('| Field | Value |');
      lines.push('| --- | --- |');
      lines.push(`| operationId | \`${opId}\` |`);
      lines.push(`| tags | \`${tag}\` |`);
      lines.push(`| summary | _Not extracted — document intent in your API spec._ |`);
      lines.push(`| x-framework | ${fw} |`);
      const sec =
        route.authHeuristic === 'likely-protected'
          ? 'bearer / session (heuristic)'
          : route.authHeuristic === 'likely-open'
            ? 'none (heuristic)'
            : 'unknown';
      lines.push(`| security (heuristic) | ${sec} |`);
      if (['POST', 'PUT', 'PATCH'].includes(route.method)) {
        const vb =
          route.validationHeuristic === 'likely-present'
            ? 'DTO / validation signal (heuristic)'
            : route.validationHeuristic === 'likely-missing'
              ? 'missing validation signal (heuristic)'
              : 'unknown';
        lines.push(`| requestBody | ${vb} |`);
      }
      lines.push(`| x-source | \`${relFile}:${String(route.line)}\` |`);
      lines.push('');
    }
    if (routes.length > cap) {
      lines.push(
        `_…${String(routes.length - cap)} additional route(s) omitted; export from your gateway or raise scan coverage._`,
        '',
      );
    }
  }

  return finalizeReport(result, lines.join('\n'));
}

function sanitizeMermaidIdent(raw: string): string {
  const s = raw.replaceAll(/[^A-Za-z0-9_]/g, '_').replace(/^_+|_+$/g, '');
  if (s.length === 0) {
    return 'NODE';
  }
  return /^\d/.test(s) ? `_${s}` : s;
}

function modelFieldRichness(m: { readonly fields: readonly { readonly typeToken: string }[] }): number {
  return m.fields.filter((f) => f.typeToken.length > 0 && f.typeToken !== 'unknown').length;
}

function buildIntelligenceErMermaid(result: ScanResult): string[] {
  const intel = result.database.intelligence;
  if (intel === undefined || intel.models.length === 0) {
    return ['_No parsed Prisma / ORM models — add `prisma/schema.prisma` or entity/schema modules._'];
  }
  const sortedModels = [...intel.models].sort(
    (a, b) => modelFieldRichness(b) - modelFieldRichness(a) || b.fields.length - a.fields.length,
  );
  const lines = ['```mermaid', 'erDiagram'];
  for (const m of sortedModels.slice(0, 18)) {
    const id = sanitizeMermaidIdent(m.name);
    lines.push(`  ${id} {`);
    const fs =
      m.fields.length > 0
        ? m.fields
        : [{ name: 'columns', typeToken: 'not_extracted_run_deep_scan' }];
    for (const f of fs.slice(0, 10)) {
      const typePart = sanitizeMermaidIdent(f.typeToken) || 'unknown';
      const namePart = sanitizeMermaidIdent(f.name) || 'field';
      lines.push(`    ${typePart} ${namePart}`);
    }
    lines.push('  }');
  }
  for (const r of intel.relations.slice(0, 30)) {
    lines.push(
      `  ${sanitizeMermaidIdent(r.from)} ||--o{ ${sanitizeMermaidIdent(r.to)} : '${r.cardinality}'`,
    );
  }
  lines.push('```');
  lines.push(
    `_Sources: ${intel.sources.length ? intel.sources.join(', ') : 'none'} — ER is a **logical** view; physical tables live in migrations/DDL._`,
  );
  return lines;
}

interface DomainRollup {
  readonly segment: string;
  readonly fileCount: number;
  readonly controllers: number;
  readonly services: number;
  readonly entities: number;
  readonly modules: number;
}

function inferDomainSegment(relPath: string): string {
  const parts = relPath.replaceAll('\\', '/').split('/').filter((s) => s.length > 0);
  const idx = parts.lastIndexOf('src');
  const seg = idx >= 0 ? parts[idx + 1] : undefined;
  if (seg !== undefined && seg.length > 0) {
    return seg;
  }
  return parts.length > 0 ? (parts[0] ?? 'app') : 'app';
}

function aggregateDomainRollups(inv: ScanResult['inventory']): DomainRollup[] {
  const map = new Map<string, { fc: number; c: number; s: number; e: number; m: number }>();
  for (const f of inv.files) {
    const d = inferDomainSegment(f.relPath);
    const row = map.get(d) ?? { fc: 0, c: 0, s: 0, e: 0, m: 0 };
    row.fc += 1;
    if (f.kind === 'controller') {
      row.c += 1;
    }
    if (f.kind === 'service') {
      row.s += 1;
    }
    if (f.kind === 'entity') {
      row.e += 1;
    }
    if (f.kind === 'module') {
      row.m += 1;
    }
    map.set(d, row);
  }
  return [...map.entries()]
    .map(([segment, v]) => ({
      segment,
      fileCount: v.fc,
      controllers: v.c,
      services: v.s,
      entities: v.e,
      modules: v.m,
    }))
    .sort((a, b) => b.fileCount - a.fileCount);
}

function buildOverallSystemDiagram(result: ScanResult): string[] {
  const fw = result.profile?.primaryFramework ?? 'app';
  const ormLabel =
    result.database.ormSignals.length > 0 ? result.database.ormSignals.join(', ') : 'ORM / SQL layer';
  const rollups = aggregateDomainRollups(result.inventory);
  const top = rollups.slice(0, 10);
  const lines: string[] = [
    '```mermaid',
    'flowchart TB',
    `  Client(["Clients / integrations"]) --> GW["HTTP API\\n${fw}"]`,
    `  GW --> ORM["${ormLabel.replaceAll('"', "'")}"]`,
    '  ORM --> DB[("Database")]',
  ];
  if (top.length > 0) {
    lines.push('  GW --> MODS{{"Feature areas (src/*)"}}');
    for (const r of top) {
      const id = sanitizeMermaidIdent(r.segment) || 'mod';
      const safeSeg = r.segment.replaceAll('"', "'");
      const label = `${safeSeg}\\n${String(r.controllers)} ctrl · ${String(r.services)} svc · ${String(r.entities)} ent`;
      lines.push(`  MODS --> ${id}["${label}"]`);
    }
  }
  lines.push('```');
  lines.push(
    '_Rollup from inventory paths under `src/` (or first path segment when `src` is absent). This is not a runtime dependency graph._',
    '',
    '| `src/*` segment | Files | Controllers | Services | Entities | Nest modules |',
    '| --- | ---: | ---: | ---: | ---: | ---: |',
  );
  for (const r of rollups.slice(0, 18)) {
    lines.push(
      `| \`${r.segment}\` | ${String(r.fileCount)} | ${String(r.controllers)} | ${String(r.services)} | ${String(r.entities)} | ${String(r.modules)} |`,
    );
  }
  lines.push('');
  return lines;
}

function buildDatabaseDesignSummary(result: ScanResult): string[] {
  const intel = result.database.intelligence;
  const migrations = result.inventory.kindCounts.migration;
  const entitiesInv = result.inventory.kindCounts.entity;
  const lines = [
    '## Database design summary',
    '',
    '_Logical schema view from static parsing. Always diff against real migrations and the live database._',
    '',
    '| Metric | Value |',
    '| --- | ---: |',
    `| Entity files (inventory) | ${String(entitiesInv)} |`,
    `| Migration files (inventory) | ${String(migrations)} |`,
    `| Parsed models (merged) | ${intel !== undefined ? String(intel.models.length) : '0'} |`,
    `| Parsed relation edges | ${intel !== undefined ? String(intel.relations.length) : '0'} |`,
    '',
  ];
  if (intel === undefined || intel.models.length === 0) {
    lines.push(
      '_No merged models — add Prisma schema or ensure TypeORM `@Entity` sources are readable in the scan workspace._',
      '',
    );
    return lines;
  }
  lines.push('| Model | Source | Sample columns | Outbound relations |', '| --- | --- | --- | --- |');
  const sorted = [...intel.models].sort(
    (a, b) => modelFieldRichness(b) - modelFieldRichness(a) || b.fields.length - a.fields.length,
  );
  for (const m of sorted.slice(0, 28)) {
    const cols =
      m.fields
        .slice(0, 5)
        .map((f) => `${f.name}: ${f.typeToken}`)
        .join(', ') || '_none parsed_';
    const relOut = intel.relations
      .filter((r) => r.from === m.name)
      .map((r) => `${r.to} (${r.cardinality})`)
      .slice(0, 5)
      .join(', ');
    lines.push(
      `| \`${m.name}\` | ${m.source} | ${cols.replaceAll('|', '\\|')} | ${(relOut.length > 0 ? relOut : '—').replaceAll('|', '\\|')} |`,
    );
  }
  lines.push('');
  if (intel.indexingHints.length > 0) {
    lines.push('### Indexing hints', '');
    lines.push(...intel.indexingHints.slice(0, 10).map((h) => `- ${h}`));
    lines.push('');
  }
  return lines;
}

function buildLogicalDataFlow(result: ScanResult): string[] {
  const fw = result.profile?.primaryFramework ?? 'app';
  return [
    '```mermaid',
    'flowchart LR',
    '  C(["HTTP client"]) --> R["Route / controller"]',
    `  R --> H["${fw} handler"]`,
    '  H --> S["Service / domain"]',
    '  S --> P["ORM / SQL layer"]',
    '  P --> DB[("Database")]',
    '```',
    '_Logical layering (not a proven dynamic call graph)._',
  ];
}

function collectImportClosureAbs(result: ScanResult, startAbs: string, maxHops: number): Set<string> {
  const start = normalize(startAbs);
  const visited = new Set<string>([start]);
  let frontier = [start];
  for (let hop = 0; hop < maxHops; hop += 1) {
    const next = new Set<string>();
    for (const cur of frontier) {
      for (const e of result.ast.importGraph) {
        if (normalize(e.from) !== cur) {
          continue;
        }
        const to = normalize(e.to);
        if (!visited.has(to)) {
          visited.add(to);
          next.add(to);
        }
      }
    }
    frontier = [...next];
    if (frontier.length === 0) {
      break;
    }
  }
  return visited;
}

function guessModelsFromPaths(paths: Iterable<string>, modelNames: readonly string[]): string[] {
  const text = [...paths].join(' ').toLowerCase();
  const hits: string[] = [];
  for (const name of modelNames) {
    const nRaw = name.toLowerCase();
    if (
      text.includes(nRaw) ||
      text.includes(`${nRaw}s`) ||
      text.includes(`${nRaw}service`) ||
      text.includes(`${nRaw}repository`) ||
      text.includes(`${nRaw}repo`)
    ) {
      hits.push(name);
      continue;
    }
    const deSnake = nRaw.replaceAll('_', '');
    if (deSnake.length > 1 && text.includes(deSnake)) {
      hits.push(name);
    }
  }
  return [...new Set(hits)].slice(0, 8);
}

function buildSegmentEntityMap(result: ScanResult): string[] {
  const intel = result.database.intelligence;
  if (intel === undefined || intel.models.length === 0) {
    return ['_No parsed schema entities to attach to segments._', ''];
  }
  const modelNames = intel.models.map((m) => m.name);
  const rollups = aggregateDomainRollups(result.inventory);
  const lines = [
    '### Domain segments ↔ parsed entities (guess)',
    '',
    '| Segment | Guessed entities (from file paths + names) |',
    '| --- | --- |',
  ];
  for (const r of rollups.slice(0, 12)) {
    const paths = result.inventory.files
      .filter((f) => inferDomainSegment(f.relPath) === r.segment)
      .map((f) => normalize(join(result.cwd, f.relPath)));
    const guessed = guessModelsFromPaths(paths, modelNames).join(', ') || '—';
    lines.push(`| \`${r.segment}\` | ${guessed.replaceAll('|', '\\|')} |`);
  }
  lines.push('');
  return lines;
}

function buildApiDatabaseFlow(result: ScanResult): string[] {
  const intel = result.database.intelligence;
  const modelNames = intel !== undefined ? intel.models.map((m) => m.name) : [];
  const lines: string[] = [
    '## API → database flow (heuristic)',
    '',
    '_Correlates detected HTTP routes with a 2-hop import closure and parsed schema entity names. Not a dynamic trace._',
    '',
  ];
  if (result.api.routes.length === 0) {
    lines.push('_No routes in the API map — ensure controllers/routes are under the scanned workspace._', '');
    return lines;
  }
  lines.push(
    '| Method | Path | Route file | Related modules (imports) | Guessed entities |',
    '| --- | --- | --- | --- | --- |',
  );
  for (const route of result.api.routes.slice(0, 12)) {
    const routeAbs = normalize(route.file);
    const closure = collectImportClosureAbs(result, routeAbs, 2);
    const relMods = [...closure]
      .map((p) => rel(result.cwd, p))
      .filter((p) => p !== rel(result.cwd, routeAbs))
      .slice(0, 8)
      .map((p) => `\`${p}\``)
      .join(' ');
    const guessed =
      modelNames.length > 0 ? guessModelsFromPaths(closure, modelNames).join(', ') || '—' : '— (_no schema models_)';
    const safePath = route.pathPattern.replaceAll('|', '\\|');
    lines.push(
      `| ${route.method} | \`${safePath}\` | \`${rel(result.cwd, routeAbs)}:${String(route.line)}\` | ${relMods.length > 0 ? relMods.replaceAll('|', '\\|') : '—'} | ${guessed.replaceAll('|', '\\|')} |`,
    );
  }
  if (result.api.routes.length > 12) {
    lines.push('', `_…${String(result.api.routes.length - 12)} more route(s) omitted._`, '');
  } else {
    lines.push('');
  }
  return lines;
}

function buildModuleDbMap(result: ScanResult): string[] {
  const inv = result.inventory;
  const rows = Object.entries(inv.kindCounts)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 14)
    .map(([k, n]) => `| ${k} | ${String(n)} |`);
  const lines = [
    '## Module → datastore map',
    '',
    '| Inventory kind | Count |',
    '| --- | ---: |',
    ...rows,
    '',
    ...buildSegmentEntityMap(result),
    '### Controllers → data-layer imports (heuristic)',
    '',
  ];
  const controllers = inv.files.filter((f) => f.kind === 'controller').slice(0, 8);
  for (const c of controllers) {
    const fromAbs = normalize(join(result.cwd, c.relPath));
    const outs = result.ast.importGraph
      .filter((e) => e.from === fromAbs)
      .map((e) => rel(result.cwd, e.to))
      .filter((p) => /(repository|service|prisma|mongoose|typeorm|schema|entity|db)/i.test(p))
      .slice(0, 5);
    lines.push(
      `- \`${rel(result.cwd, fromAbs)}\` → ${outs.length > 0 ? outs.map((x) => `\`${x}\``).join(', ') : '_no obvious data-layer import_'}`,
    );
  }
  if (controllers.length === 0) {
    lines.push('_No controller-classified files — classify entry routes or Nest controllers for a richer map._');
  }
  lines.push('');
  return lines;
}

function buildRequestFlow(result: ScanResult): string[] {
  const lines = ['```mermaid', 'sequenceDiagram'];
  const routes = result.api.routes.slice(0, 6);
  if (routes.length === 0) {
    lines.push('  participant User');
    lines.push('  participant App');
    lines.push('  User->>App: No route map available');
  } else {
    lines.push('  participant Client');
    lines.push('  participant Route');
    lines.push('  participant Service');
    lines.push('  participant Data');
    for (const route of routes) {
      lines.push(`  Client->>Route: ${route.method} ${route.pathPattern}`);
      lines.push(`  Route->>Service: ${inferRouteFramework(result, route)} handler`);
      lines.push(`  Service->>Data: ${rel(result.cwd, route.file)}`);
    }
  }
  lines.push('```');
  return lines;
}

function buildArchitecture(result: ScanResult): string {
  const lines = [
    reportDocumentHeader(
      result,
      'Architecture & data design',
      '_Database ER (Prisma, TypeORM, Mongoose, SQL DDL) and summaries first; runtime layout; module→data map; API→DB heuristic; sample HTTP; then architecture-engine findings._',
    ),
    '## Database schema (ER + summary)',
    '',
    ...buildIntelligenceErMermaid(result),
    '',
    ...buildDatabaseDesignSummary(result),
    '',
    '## Runtime layout (heuristic)',
    '',
    ...buildOverallSystemDiagram(result),
    '',
    '## Logical request / data path',
    '',
    ...buildLogicalDataFlow(result),
    '',
    ...buildModuleDbMap(result),
    ...buildApiDatabaseFlow(result),
    '## Sample HTTP sequence (detected routes)',
    '',
    ...buildRequestFlow(result),
    '',
    renderBoundedIssuesSection('Architecture findings', result.architecture.issues, { findingIdPrefix: 'ARCH' }),
  ];
  return finalizeReport(result, lines.join('\n'));
}

function buildPerformance(result: ScanResult): string {
  const issues = result.performance.issues;
  const mem = result.memory.issues;
  return finalizeReport(
    result,
    [
      reportDocumentHeader(
        result,
        'Performance & memory review',
        '_Blocking calls, sync I/O, throughput risks, and memory-engine leak-style heuristics._',
      ),
      '## Blocking calls and throughput risks',
      '',
      ...renderIssueTable(issues, result.cwd),
      '## Memory / retention signals',
      '',
      ...renderIssueTable(mem, result.cwd),
    ].join('\n'),
  );
}

interface AttackScenario {
  readonly name: string;
  readonly attackVector: string;
  readonly impact: string;
  readonly mitigation: string;
  readonly match: (issue: Issue) => boolean;
}

const ATTACK_SCENARIO_DEFS: readonly AttackScenario[] = [
  {
    name: 'Hardcoded credential extraction',
    attackVector: 'Secrets committed in code or config are exfiltrated from the repo or built assets.',
    impact: 'Account takeover and downstream data breach.',
    mitigation: 'Move secrets to a vault, rotate exposed keys, and add pre-commit scanning.',
    match: (issue) => /credential|secret|token|key/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'JWT algorithm confusion (alg:none)',
    attackVector: 'Weak token verification accepts attacker-controlled JWT headers.',
    impact: 'Authentication bypass and privilege escalation.',
    mitigation: 'Pin accepted algorithms and use a hardened JWT library configuration.',
    match: (issue) => /jwt|alg:none|algorithm/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'SQL injection via template literal',
    attackVector: 'User input reaches raw SQL string construction.',
    impact: 'Data exfiltration, tampering, and auth bypass in the database.',
    mitigation: 'Use parameterized queries and ORM bindings only.',
    match: (issue) => /sql|query interpolation|raw sql|injection/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'SSRF via user-controlled URL',
    attackVector: 'Attacker points server-side fetch logic at internal services or cloud metadata.',
    impact: 'Internal network access and credential theft.',
    mitigation: 'Allowlist outbound hosts and block private address ranges.',
    match: (issue) => /ssrf|user-controlled url|metadata/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Prototype pollution via Object.assign',
    attackVector: 'Unsafe merges let attacker input poison object prototypes.',
    impact: 'Unexpected property injection, auth bypass, or remote code execution chains.',
    mitigation: 'Use safe merge utilities and upgrade vulnerable packages.',
    match: (issue) => /prototype|pollution|object\.assign|lodash/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Dependency confusion / supply chain',
    attackVector: 'Compromised or stale packages execute malicious code during install or runtime.',
    impact: 'Build compromise, secret theft, or production takeover.',
    mitigation: 'Use lockfiles, review package provenance, and refresh the local vuln database.',
    match: (issue) => /dependency|package|audit|deprecated|drift|supply chain/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Path traversal via user input',
    attackVector: 'Unsanitized file paths escape intended directories.',
    impact: 'Server file disclosure or arbitrary overwrite.',
    mitigation: 'Normalize paths, enforce allowlisted roots, and reject dot-dot segments.',
    match: (issue) => /path traversal|file upload|unsafe file/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'XSS via dangerouslySetInnerHTML',
    attackVector: 'Untrusted HTML reaches client rendering without sanitization.',
    impact: 'Session hijacking and malicious actions in victim browsers.',
    mitigation: 'Avoid raw HTML sinks or sanitize before rendering.',
    match: (issue) => /xss|dangerouslysetinnerhtml|innerhtml/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Privilege escalation via missing auth',
    attackVector: 'Sensitive endpoints execute without reliable authorization checks.',
    impact: 'Attackers gain access to admin or write operations.',
    mitigation: 'Add centralized authN and authZ middleware to every mutating route.',
    match: (issue) => /auth|authorization|access control/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Env file exposure via git',
    attackVector: 'Tracked env files expose deployment secrets to collaborators and forks.',
    impact: 'Credential leakage and environment takeover.',
    mitigation: 'Remove env files from git, rotate values, and use secret managers.',
    match: (issue) => /env|tracked|git/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'ReDoS via vulnerable regex libs',
    attackVector: 'Vulnerable libraries or unsafe regex patterns allow input-driven CPU exhaustion.',
    impact: 'Request timeouts and service degradation.',
    mitigation: 'Patch regex-related packages and review unbounded patterns.',
    match: (issue) => /regex|redos|loop|blocking/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Circular dependency exploit',
    attackVector: 'Cycle-heavy modules initialize in partial states and can bypass expected guards.',
    impact: 'Broken startup order and inconsistent security controls.',
    mitigation: 'Break cycles with interfaces and smaller boundary modules.',
    match: (issue) => /circular|cycle/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'DoS via unthrottled endpoint',
    attackVector: 'Open or weakly protected endpoints are abused with high request volume.',
    impact: 'Availability loss and queue saturation.',
    mitigation: 'Add throttling, caching, timeouts, and async offloading.',
    match: (issue) => /rate|throttle|blocking|sync api|loop/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Memory exhaustion via unbounded Map',
    attackVector: 'Listeners, timers, or collections grow without cleanup.',
    impact: 'Heap growth, restarts, and degraded latency.',
    mitigation: 'Bound caches, remove listeners, and clear timers.',
    match: (issue) => /memory|listener|interval|map|promise/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Command injection via execSync + user input',
    attackVector: 'User-controlled strings reach shell execution primitives.',
    impact: 'Remote command execution on the host.',
    mitigation: 'Avoid shell invocation or pass trusted arguments only.',
    match: (issue) => /command|execsync|child_process|shell/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Broken object-level authorization (IDOR)',
    attackVector: 'Clients change IDs in URLs or bodies and access other tenants’ records.',
    impact: 'Data breach across customers; regulatory exposure.',
    mitigation: 'Authorize every read/write against the actor’s tenant; never trust IDs alone.',
    match: (issue) => /idor|object level|authorization|access control/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Mass assignment / unsafe DTO binding',
    attackVector: 'Request bodies populate privileged fields (e.g. role, balance) without an allowlist.',
    impact: 'Privilege escalation and financial tampering.',
    mitigation: 'Use explicit DTOs with allowlists; forbid spreading `req.body` into persistence models.',
    match: (issue) => /mass assignment|dto|role|privilege/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Insecure deserialization',
    attackVector: 'Untrusted serialized blobs are unmarshalled into executable object graphs.',
    impact: 'Remote code execution on application workers.',
    mitigation: 'Use safe JSON parsing only; never `eval`/`Function` on serialized input.',
    match: (issue) => /deserial|pickle|yaml\.load|serialize/i.test(`${issue.title} ${issue.description}`),
  },
  {
    name: 'Open redirect / unsafe forward',
    attackVector: 'Login or checkout flows redirect to attacker-controlled URLs after auth.',
    impact: 'Phishing and token theft on a trusted domain.',
    mitigation: 'Allowlist redirect targets or use relative paths with strict validation.',
    match: (issue) => /redirect|open url|returnurl|next=/i.test(`${issue.title} ${issue.description}`),
  },
];

function pickFinding(issues: readonly Issue[], match: (issue: Issue) => boolean): Issue | undefined {
  return [...issues]
    .filter(match)
    .sort((left, right) => severityWeight(right.severity) - severityWeight(left.severity))[0];
}

function buildOwaspPerCategoryDetailLines(result: ScanResult): string[] {
  const allIssues = effectiveIssues(result);
  const lines: string[] = [
    '## OWASP per-category highlights (top 5)',
    '',
    '_Expands each A0x row from the summary table with representative trusted findings._',
    '',
  ];
  const owaspCodes = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'] as const;
  for (const code of owaspCodes) {
    const top = topOwaspIssuesForCode(allIssues, code, 5);
    lines.push(`### ${code}`, '');
    if (top.length === 0) {
      lines.push('_No mapped findings._', '');
      continue;
    }
    lines.push('| Severity | Engine | Finding | File |', '| --- | --- | --- | --- |');
    for (const issue of top) {
      lines.push(
        `| ${issue.severity} | ${issue.engine} | ${issue.title.replaceAll('|', '\\|')} | \`${rel(result.cwd, issue.file)}\` |`,
      );
    }
    lines.push('');
  }
  return lines;
}

function buildHotspotMarkdownTable(result: ScanResult): string[] {
  const lines: string[] = [
    '## Priority hotspots (cross-engine)',
    '',
    '_Severity-weighted ranking for remediation planning (trusted, deduped)._',
    '',
    '| Rank | Severity | Engine | Location | Finding | Root cause | Fix | Verify | Attack chain |',
    '| ---: | --- | --- | --- | --- | --- | --- | --- | --- |',
  ];
  for (const hotspot of result.hotspots) {
    const rc = (hotspot.rootCause ?? hotspot.impact).replaceAll('|', '\\|').slice(0, 120);
    const vx = (hotspot.verifyStep ?? 'Re-run scan and targeted tests.').replaceAll('|', '\\|').slice(0, 100);
    const ac = (hotspot.attackChain ?? '—').replaceAll('|', '\\|').slice(0, 90);
    lines.push(
      `| ${String(hotspot.rank)} | ${hotspot.severity} | ${hotspot.engine} | \`${rel(result.cwd, hotspot.file)}:${String(hotspot.line)}\` | ${hotspot.title.replaceAll('|', '\\|')} | ${rc} | ${hotspot.fixHint.replaceAll('|', '\\|')} | ${vx} | ${ac} |`,
    );
  }
  if (result.hotspots.length === 0) {
    lines.push('| 1 | _none_ | _none_ | _none_ | _none_ | _none_ | _none_ | _none_ | _none_ |');
  }
  lines.push('');
  return lines;
}

function buildAttackScenariosMarkdownLines(result: ScanResult): string[] {
  const allIssues = effectiveIssues(result);
  const lines: string[] = [
    '## Threat modeling scenarios',
    '',
    '_STRIDE-style narratives. Each scenario links the strongest matching **trusted** finding when one exists._',
    '',
  ];
  ATTACK_SCENARIO_DEFS.forEach((scenario, index) => {
    const finding = pickFinding(allIssues, scenario.match);
    const sink = finding
      ? `Sink at \`${rel(result.cwd, finding.file)}:${String(finding.line)}\``
      : 'Sink not matched in this scan';
    const affected = finding
      ? `\`${rel(result.cwd, finding.file)}:${String(finding.line)}\``
      : '_No direct finding matched in this scan_';
    const linked = finding ? `${finding.severity} — ${finding.title.replaceAll('|', '\\|')}` : '—';
    lines.push(`### ${String(index + 1)}. ${scenario.name}`, '');
    lines.push('| Aspect | Detail |');
    lines.push('| --- | --- |');
    lines.push(`| Attack vector | ${scenario.attackVector.replaceAll('|', '\\|')} |`);
    lines.push(`| Attack chain | **untrusted input** → **application logic** → **${sink}** |`);
    lines.push(`| Affected | ${affected} |`);
    lines.push(`| Impact | ${scenario.impact.replaceAll('|', '\\|')} |`);
    lines.push(`| Mitigation | ${scenario.mitigation.replaceAll('|', '\\|')} |`);
    lines.push(`| Linked finding | ${linked} |`);
    lines.push('');
  });
  return lines;
}

function buildAst(result: ScanResult): string {
  const all = [...result.ast.functions];
  const sorted = all.sort(
    (left, right) => right.complexity - left.complexity || right.maxNesting - left.maxNesting,
  );
  const rows = sorted.slice(0, 25);
  const fileCount = new Set(all.map((f) => f.file)).size;
  const meanAll =
    all.length > 0 ? (all.reduce((acc, f) => acc + f.complexity, 0) / all.length).toFixed(1) : '0';
  const meanTop =
    rows.length > 0 ? (rows.reduce((acc, f) => acc + f.complexity, 0) / rows.length).toFixed(1) : '0';
  const maxNest = rows.length > 0 ? String(Math.max(...rows.map((f) => f.maxNesting))) : '0';
  const lines = [
    reportDocumentHeader(
      result,
      'AST complexity review',
      '_Cyclomatic complexity and nesting from the AST pass — use for refactor targeting and test prioritization._',
    ),
    '## Scan coverage',
    '',
    '| Metric | Value |',
    '| --- | ---: |',
    `| Functions analyzed | ${String(all.length)} |`,
    `| Distinct files with ≥1 function | ${String(fileCount)} |`,
    `| Mean complexity (all functions) | ${meanAll} |`,
    `| Mean complexity (top ${String(rows.length)} below) | ${meanTop} |`,
    `| Max nesting (in top ${String(rows.length)}) | ${maxNest} |`,
    '',
    '_Complexity here is a McCabe-style cyclomatic count from the scanner, not ESLint’s rule set._',
    '',
    `## Top ${String(rows.length === 0 ? 0 : rows.length)} most complex functions`,
    '',
    '| File | Function | Complexity | Cognitive≈ | Max Nesting | Lines |',
    '| --- | --- | ---: | ---: | ---: | ---: |',
  ];
  for (const fn of rows) {
    const cognitive = fn.complexity + fn.maxNesting * 2;
    lines.push(
      `| \`${rel(result.cwd, fn.file)}:${String(fn.line)}\` | ${fn.name} | ${String(fn.complexity)} | ${String(cognitive)} | ${String(fn.maxNesting)} | ${String(fn.lineCount)} |`,
    );
  }
  if (rows.length === 0) {
    lines.push('| _none_ | _none_ | 0 | 0 | 0 | 0 |');
  }
  lines.push(
    '_**Cognitive≈** is `complexity + 2 × maxNesting` (proxy until native cognitive metrics ship). Git churn weighting can be layered externally via `git log --follow` on hot files._',
    '',
  );
  return finalizeReport(result, lines.join('\n'));
}

function buildTest(result: ScanResult): string {
  const missing = result.tests.uncoveredEntryHints.slice(0, 20);
  const detection = result.tests.testDetection;
  const detectionLine =
    detection !== undefined
      ? `Globs used: ${detection.globs.map((g) => `\`${g}\``).join(', ')} · Ignore: ${detection.ignore
          .map((g) => `\`${g}\``)
          .join(', ')}.`
      : 'Globs used: defaults only (`**/*.{test,spec}.*`, `**/__tests__/**`).';
  const matchLine =
    detection !== undefined && detection.matchedSample.length > 0
      ? `Sample matched files: ${detection.matchedSample.map((p) => `\`${p}\``).join(', ')}`
      : 'Sample matched files: _none_';
  const lines = [
    reportDocumentHeader(result, 'Test coverage review', '_Test file ratio, missing entry targets, and test-engine output._'),
    '## How test files are detected',
    '',
    '_Files are counted with **fast-glob** from the project root. Defaults: `**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}`, `**/__tests__/**/*.{ts,tsx,js,jsx,mjs,cjs}` (always ignoring `node_modules`, `dist`, `.next`). Add more globs via `testFileGlobs` in `project-inspector.config.json` (e.g. `**/*.e2e.ts`, `**/tests/**/*.ts` for Playwright). Alternate runners (RSpec, pytest) are **not** counted — only paths matching these patterns._',
    '',
    detectionLine,
    matchLine,
    '',
    '## Coverage Heuristics',
    '',
    '| Metric | Value |',
    '| --- | ---: |',
    `| Test files | ${String(result.tests.testFileCount)} |`,
    `| Source files | ${String(result.tests.sourceFileCount)} |`,
    `| Test ratio | ${String(result.tests.ratioApprox)} |`,
    '',
    ...(result.tests.lcovSummary !== undefined
      ? [
          '## Line coverage (LCOV)',
          '',
          '_Ingested from `coverage/lcov.info` or `coverage/lcov.dat` when present after a test run._',
          '',
          '| Metric | Value |',
          '| --- | ---: |',
          `| Lines found | ${String(result.tests.lcovSummary.linesFound)} |`,
          `| Lines hit | ${String(result.tests.lcovSummary.linesHit)} |`,
          `| Approx. line % | ${String(result.tests.lcovSummary.percentApprox)}% |`,
          `| Files in LCOV | ${String(result.tests.lcovSummary.filesWithCoverage)} |`,
          '',
        ]
      : []),
    '## Missing Test Targets',
    '',
    ...(missing.length === 0 ? ['_No obvious missing entry-point tests detected._'] : missing.map((file) => `- \`${file}\``)),
    '',
    renderBoundedIssuesSection('Test Findings', result.tests.issues, { findingIdPrefix: 'TEST' }),
  ];
  return finalizeReport(result, lines.join('\n'));
}

function buildActionPlan(result: ScanResult, owners: readonly CodeOwnersRule[]): string {
  const trusted = effectiveIssues(result);
  const top = [...trusted]
    .sort((a, b) => actionRank(b) - actionRank(a) || severityWeight(b.severity) - severityWeight(a.severity))
    .slice(0, 5);
  const lines = [
    reportDocumentHeader(
      result,
      'What should I do now?',
      '_Top 5 prioritized fixes with owner, ETA, and business impact for immediate execution._',
    ),
    '## Top 5 actions',
    '',
    '| Issue | Priority | Owner | ETA | Impact area | Status |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  if (top.length === 0) {
    lines.push('| _No trusted findings_ | P3 | Unassigned | — | Core service | Done |');
  } else {
    for (const issue of top) {
      const owner = ownerForPath(owners, rel(result.cwd, issue.file)) ?? 'Unassigned';
      const biz = mapBusinessImpact(issue);
      lines.push(
        `| ${issue.title.replaceAll('|', '\\|')} | ${priorityLabel(issue)} | ${owner.replaceAll('|', '\\|')} | ${estimateEta(issue)} | ${biz.area} | Needs triage |`,
      );
    }
  }
  lines.push(
    '',
    '## Notes',
    '',
    '- Status flow: `Needs triage` -> `Planned` -> `In progress` -> `Done`.',
    '- If a finding is intentional (e.g. public route), suppress with owner + reason in `project-inspector.config.json`.',
    '',
    '## Copy-paste PR template',
    '',
    '```markdown',
    '## Inspector follow-up',
    '',
    '- [ ] Linked issue IDs from action-plan',
    '- [ ] Re-ran `project-inspector check` locally',
    '- [ ] Updated baseline if suppressions added (`--save-baseline`)',
    '```',
    '',
  );
  return finalizeReport(result, lines.join('\n'));
}

function buildForUsers(result: ScanResult): string {
  const trusted = effectiveIssues(result);
  const critical = trusted.filter((i) => i.severity === 'CRITICAL').length;
  const high = trusted.filter((i) => i.severity === 'HIGH').length;
  const baseline = result.baselineComparison;
  const top = [...trusted]
    .sort((a, b) => actionRank(b) - actionRank(a))
    .slice(0, 5)
    .map((i) => {
      const biz = mapBusinessImpact(i);
      return `- **${i.severity}** ${i.title} -> ${biz.statement}`;
    });
  const lines = [
    reportDocumentHeader(
      result,
      'For product and operations teams',
      '_Plain-language view of current risk and what teams should do this week._',
    ),
    '## What this means',
    '',
    `- We found **${String(critical)} critical** and **${String(high)} high** trusted issues.`,
    '- Trusted means duplicates/noise were reduced before scoring.',
    '- Use `action-plan.md` for owner + ETA tracking.',
    '',
    '## What can break',
    '',
    ...(top.length > 0 ? top : ['- No high-priority breakage scenarios detected in trusted findings.']),
    '',
    '## Trend from last baseline',
    '',
    ...(baseline !== undefined
      ? [
          `- New issues: **${String(baseline.newCount)}**`,
          `- Resolved issues: **${String(baseline.resolvedCount)}**`,
          `- Unchanged issues: **${String(baseline.unchangedCount)}**`,
        ]
      : ['- Baseline not available yet. Run with `--save-baseline` to enable trend tracking.']),
    '',
    '## How to reduce false alarms',
    '',
    '- Mark intentional public endpoints using `intentionalPublicRouteGlobs` in `project-inspector.config.json`.',
    '- Keep suppressions narrow, owned, and documented with reason.',
    '',
  ];
  return finalizeReport(result, lines.join('\n'));
}

function buildDatabase(result: ScanResult): string {
  const dbTrusted = effectiveIssues(result).filter((i) => i.engine === 'database');
  const hints = result.database.intelligence?.indexingHints ?? [];
  const lines = [
    reportDocumentHeader(
      result,
      'Database & SQL review',
      '_ORM/SQL trusted findings and indexing hints; see Architecture for ER diagrams._',
    ),
    '## SQL & ORM risks (trusted)',
    '',
    ...renderIssueTable(dbTrusted, result.cwd),
    '',
    '## ER & schema graph',
    '',
    '_Full Mermaid ER and model table live under **Architecture → Database schema (ER + summary)**._',
    '',
    '## Indexing hints (parsed / heuristic)',
    '',
    ...(hints.length > 0 ? hints.map((h) => `- ${h}`) : ['_No @@index hints parsed — review FKs and filter columns manually._']),
    '',
  ];
  return finalizeReport(result, lines.join('\n'));
}

async function writeMarkdownFile(outDir: string, filename: string, body: string): Promise<void> {
  await writeFile(join(outDir, filename), enforceMarkdownLineCap(body, filename), 'utf8');
}

function reportBuilders(result: ScanResult): Readonly<Record<ReportSection, () => string>> {
  return {
    summary: () => buildSummary(result),
    'production-decision': () => buildProductionDecisionDoc(result),
    security: () => buildSecurity(result),
    dependencies: () => buildDependencies(result),
    api: () => buildApi(result),
    architecture: () => buildArchitecture(result),
    performance: () => buildPerformance(result),
    ast: () => buildAst(result),
    test: () => buildTest(result),
    database: () => buildDatabase(result),
  };
}

export async function writeScanReports(result: ScanResult, outDir: string): Promise<void> {
  await writeScanReportsPartial(new Set<ReportSection>(ALL_REPORT_SECTIONS), result, outDir);
}

/**
 * Machine-oriented bundle: `decision.json`, `scores.json`, `results.sarif`, `index.html`.
 * Safe to call on cache hits when Markdown sections are skipped.
 */
export async function writeScanArtifacts(result: ScanResult, outDir: string): Promise<void> {
  await mkdir(outDir, { recursive: true });
  const owners = await loadCodeOwnersRules(result.cwd);
  const trusted = effectiveIssues(result);
  const metaSeg = {
    testFileCount: result.tests.testFileCount,
    sourceFileCount: result.tests.sourceFileCount,
  };
  if (result.productionDecision !== undefined) {
    await writeFile(
      join(outDir, 'decision.json'),
      `${JSON.stringify({ version: 1, ...result.productionDecision }, null, 2)}\n`,
      'utf8',
    );
  }
  await writeFile(
    join(outDir, 'scores.json'),
    `${JSON.stringify(
      {
        security: result.scores.security,
        performance: result.scores.performance,
        codeQuality: result.scores.codeQuality,
        compliance: result.scores.compliance,
        tests: result.scores.tests,
        readiness: result.scores.productionReadiness,
        scannedAt: result.finishedAt,
        scanMode: result.mode,
        online: result.online,
        scoreDiagnostics: result.scoreDiagnostics,
        segmentRisk: segmentRiskSummary(result),
        segmentScores: computeSegmentScores(result.cwd, trusted, metaSeg),
        baselineHistory: result.baselineHistory ?? [],
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
  await writeSarifReport(result, outDir);
  await copyDecisionSchemaToReport(outDir);
  await writeMarkdownFile(outDir, 'action-plan.md', buildActionPlan(result, owners));
  await writeMarkdownFile(outDir, 'for-users.md', buildForUsers(result));
  const baselineForPr = await loadBaselineTrusted(outDir);
  const baselineFp =
    baselineForPr !== undefined ? new Set<string>(baselineForPr.fingerprints) : undefined;
  const scopeSet =
    result.prCommentScopePaths !== undefined && result.prCommentScopePaths.length > 0
      ? new Set(result.prCommentScopePaths)
      : undefined;
  await writeMarkdownFile(
    outDir,
    'pr-comment.md',
    renderPrCommentMarkdown(result, {
      ...(baselineFp !== undefined ? { baselineFingerprints: baselineFp } : {}),
      ...(scopeSet !== undefined ? { scopeRelPaths: scopeSet } : {}),
    }),
  );

  await writeCycloneDxSbom(result.cwd, join(outDir, 'sbom.cdx.json')).catch(() => false);
  try {
    const openapiDoc = buildOpenApi31FromRoutes(result.api.routes, 'Detected HTTP routes', '1.0.0');
    await writeFile(join(outDir, 'openapi.json'), `${JSON.stringify(openapiDoc, null, 2)}\n`, 'utf8');
  } catch {
    /* optional */
  }
  await writeOsvSummary(result.cwd, outDir, !result.online);
  try {
    const cfg = await loadInspectorConfig(result.cwd);
    await writeFile(
      join(outDir, 'governance-suppressions.json'),
      `${JSON.stringify(
        { version: 1, suppressions: cfg.governanceSuppressions ?? [], exportedAt: result.finishedAt },
        null,
        2,
      )}\n`,
      'utf8',
    );
    await appendFile(
      join(outDir, 'governance-audit.jsonl'),
      `${JSON.stringify({
        ts: result.finishedAt,
        suppressionsActive: (cfg.governanceSuppressions ?? []).length,
        scanMode: result.mode,
        readiness: result.scores.productionReadiness,
      })}\n`,
      'utf8',
    );
  } catch {
    /* optional */
  }

  await writeReportIndexHtml(result, outDir);
}

export async function writeScanReportsPartial(
  changed: ReadonlySet<string>,
  result: ScanResult,
  outDir: string,
): Promise<void> {
  await mkdir(outDir, { recursive: true });
  const builders = reportBuilders(result);
  for (const section of ALL_REPORT_SECTIONS) {
    if (!changed.has(section)) {
      continue;
    }
    await writeMarkdownFile(outDir, REPORT_FILENAMES[section], builders[section]());
  }
  await Promise.all(
    LEGACY_MARKDOWN_REPORT_FILES.map(async (name) => {
      try {
        await unlink(join(outDir, name));
      } catch {
        /* ignore missing legacy files */
      }
    }),
  );
  await writeScanArtifacts(result, outDir);
}
