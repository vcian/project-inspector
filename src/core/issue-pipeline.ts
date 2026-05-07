import { relative } from 'node:path';

import type { GovernanceSuppression, InspectorConfig } from './inspector-config.js';
import type { Issue } from './types.js';

function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.replaceAll('\\', '/').replaceAll(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withStars = normalized
    .replaceAll(/\*\*/g, '§DOUBLE§')
    .replaceAll('*', '[^/]*')
    .replaceAll('§DOUBLE§', '.*');
  return new RegExp(`^${withStars}$`, 'i');
}

function pathIgnored(relPosix: string, globs: readonly string[]): boolean {
  for (const g of globs) {
    if (globToRegExp(g).test(relPosix)) {
      return true;
    }
  }
  return false;
}

function governanceMatches(issue: Issue, cwd: string, g: GovernanceSuppression): boolean {
  const exp = Date.parse(g.expiresAt);
  if (!Number.isFinite(exp) || exp <= Date.now()) {
    return false;
  }
  if (g.issueId !== undefined && g.issueId.length > 0 && issue.id === g.issueId) {
    return true;
  }
  const rel = relative(cwd, issue.file).replaceAll('\\', '/');
  if (g.pathGlob !== undefined && g.pathGlob.length > 0 && globToRegExp(g.pathGlob).test(rel)) {
    if (g.titleSubstring !== undefined && g.titleSubstring.length > 0) {
      return issue.title.toLowerCase().includes(g.titleSubstring.toLowerCase());
    }
    return true;
  }
  if (g.titleSubstring !== undefined && g.titleSubstring.length > 0) {
    return issue.title.toLowerCase().includes(g.titleSubstring.toLowerCase());
  }
  return false;
}

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

/**
 * Filters, suppresses, optionally drops low-confidence items, and deduplicates
 * issues for scoring, gates, and human-facing reports.
 */
export function applyIssuePipeline(
  issues: readonly Issue[],
  config: InspectorConfig,
  cwd: string,
): Issue[] {
  const suppressedIds = new Set(config.suppressIssueIds.map((s) => s.toLowerCase()));
  const titleSubs = config.suppressTitleSubstrings.map((s) => s.toLowerCase());

  const gov = config.governanceSuppressions ?? [];
  const filtered: Issue[] = [];
  for (const issue of issues) {
    if (gov.some((g) => governanceMatches(issue, cwd, g))) {
      continue;
    }
    if (config.excludeLowConfidence && issue.confidence === 'low') {
      continue;
    }
    if (suppressedIds.has(issue.id.toLowerCase())) {
      continue;
    }
    const titleLower = issue.title.toLowerCase();
    if (titleSubs.some((sub) => sub.length > 0 && titleLower.includes(sub))) {
      continue;
    }
    const rel = relative(cwd, issue.file).replaceAll('\\', '/');
    if (pathIgnored(rel, config.ignorePathGlobs)) {
      continue;
    }
    filtered.push(issue);
  }

  const dedup = new Map<string, Issue>();
  for (const issue of filtered) {
    const key = `${issue.engine}\0${issue.title}\0${issue.file}`;
    const prev = dedup.get(key);
    if (prev === undefined || severityRank(issue.severity) > severityRank(prev.severity)) {
      dedup.set(key, issue);
    }
  }
  return [...dedup.values()];
}
