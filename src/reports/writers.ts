import { mkdir, writeFile } from 'node:fs/promises';
import { join, normalize, relative } from 'node:path';

import { loadBaselineTrusted } from '../core/baseline.js';
import { loadInspectorConfig } from '../core/inspector-config.js';
import { gatherAllIssues } from '../core/issue-collect.js';
import {
  computeSegmentScores,
} from '../core/scoring-engine.js';
import type { ApiRouteInfo, Issue, ScanResult } from '../core/types.js';
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

function finalizeReport(result: ScanResult, markdownBody: string): string {
  const trimmed = markdownBody.replace(/\s+$/, '');
  return `${trimmed}\n\n${reportClosingMarkdown(result)}`;
}

export type ReportSection = 'api' | 'architecture' | 'database';

export const ALL_REPORT_SECTIONS: readonly ReportSection[] = [
  'api',
  'architecture',
  'database',
] as const;

const REPORT_FILENAMES: Readonly<Record<ReportSection, string>> = {
  api: 'api.md',
  architecture: 'architecture.md',
  database: 'database.md',
};


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

function formatRouteExamples(routes: readonly ApiRouteInfo[], predicate: (r: ApiRouteInfo) => boolean, max: number): string {
  const picked = routes.filter(predicate).slice(0, max);
  if (picked.length === 0) {
    return '—';
  }
  return picked.map((r) => `${r.method} \`${r.pathPattern}\``).join(', ');
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
    api: () => buildApi(result),
    architecture: () => buildArchitecture(result),
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
  await writeMarkdownFile(outDir, 'action-plan.md', buildActionPlan(result, owners));
  const baselineForPr = await loadBaselineTrusted(outDir);
  const baselineFp =
    baselineForPr !== undefined ? new Set<string>(baselineForPr.fingerprints) : undefined;
  const scopeSet =
    result.prCommentScopePaths !== undefined && result.prCommentScopePaths.length > 0
      ? new Set(result.prCommentScopePaths)
      : undefined;
  await writeMarkdownFile(
    outDir,
    'audit-summary.md',
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
  await writeScanArtifacts(result, outDir);
}
