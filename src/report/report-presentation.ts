import { basename } from 'node:path';

import type { ScanResult } from '../core/types.js';

/** Human-facing project name: workspace project when unambiguous, else repo folder name. */
export function resolveProjectDisplayName(result: ScanResult): string {
  const projects = result.profile?.projects;
  if (projects?.length === 1) {
    const sole = projects[0];
    if (sole !== undefined) {
      const n = sole.name.trim();
      if (n.length > 0) {
        return n;
      }
    }
  }
  return basename(result.cwd);
}

export function formatIsoForReport(iso: string): string {
  const d = Date.parse(iso);
  if (Number.isNaN(d)) {
    return iso;
  }
  return `${new Date(d).toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

/**
 * Standard document front-matter: title, tagline, horizontal rule, metadata table, rule.
 * Matches the style of formal security / readiness review PDFs (executive report layout).
 */
export function reportDocumentHeader(result: ScanResult, documentTitle: string, tagline: string): string {
  const project = resolveProjectDisplayName(result).replaceAll('|', '\\|');
  const folder = basename(result.cwd).replaceAll('|', '\\|');
  const framework = (result.profile?.primaryFramework ?? 'unknown').replaceAll('|', '\\|');
  const modeBits = [
    result.mode,
    result.incremental ? 'incremental' : 'full workspace',
    result.online ? 'online checks enabled' : 'offline / no network audit',
  ].join(' · ');
  return [
    `# ${documentTitle}`,
    '',
    tagline,
    '',
    '---',
    '',
    '| Field | Value |',
    '| --- | --- |',
    `| **Project** | ${project} |`,
    `| **Workspace folder** | \`${folder}\` |`,
    `| **Scan completed** | ${formatIsoForReport(result.finishedAt)} |`,
    `| **Scan mode** | ${modeBits.replaceAll('|', '\\|')} |`,
    `| **Primary stack (heuristic)** | ${framework} |`,
    '| **Reviewer** | project-inspector (deterministic static analysis) |',
    '| **Scope** | Sources under workspace root; respects `project-inspector.config.json` and the trusted-issue pipeline |',
    '',
    '---',
    '',
  ].join('\n');
}

/** Closing sections appended to every markdown report for a consistent “official report” finish. */
export function reportClosingMarkdown(result: ScanResult): string {
  return [
    '---',
    '',
    '## Methodology',
    '',
    '1. **Inventory** — Classify files (controllers, services, entities, tests, etc.) and detect primary frameworks.',
    '2. **Engines** — Run static analyzers (AST, security, API surface, dependencies, database heuristics, compliance tags, …) per scan mode.',
    '3. **Trust layer** — Apply suppressions, path ignores, optional low-confidence drops, and cross-file deduplication for scores and human-facing tables.',
    '4. **Validation** — Confirm each finding in CI, staging, and code review; static rules produce both true positives and false positives.',
    '',
    `*Generated at ${formatIsoForReport(result.finishedAt)}. Re-run \`project-inspector scan\` after meaningful code or dependency changes.*`,
    '',
  ].join('\n');
}
