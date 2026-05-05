import type { Issue, ScanResult } from '../core/types.js';

const PATTERNS: readonly RegExp[] = [
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/gi,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/gi,
  /\bsk_live_[A-Za-z0-9]{16,}\b/gi,
  /\bBearer\s+[A-Za-z0-9._-]{20,}\b/gi,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT-like
];

/**
 * Never echo raw secret-shaped material in markdown reports.
 */
export function redactForReport(issue: Issue): string | undefined {
  if (issue.code === undefined) {
    return undefined;
  }
  let s = issue.code;
  if (issue.engine === 'security') {
    for (const re of PATTERNS) {
      re.lastIndex = 0;
      s = s.replace(re, '[REDACTED]');
    }
    s = s.replace(/[A-Za-z0-9+/]{32,}={0,2}/g, '[REDACTED_TOKEN]');
  }
  const max = 220;
  if (s.length > max) {
    return `${s.slice(0, max)}…`;
  }
  return s;
}

function redactIssueForStorage(issue: Issue): Issue {
  if (issue.code === undefined) {
    return issue;
  }
  const red = redactForReport(issue);
  if (red === undefined) {
    // Strip optional `code` field (exactOptionalPropertyTypes: omit property, do not set undefined).
    // eslint-disable-next-line @typescript-eslint/no-unused-vars -- destructuring removes `code`
    const { code, ...rest } = issue;
    return rest;
  }
  return { ...issue, code: red };
}

function mapIssues(issues: readonly Issue[]): Issue[] {
  return issues.map(redactIssueForStorage);
}

/** Redact `issue.code` blobs before persisting merged JSON (reports already use `redactForReport`). */
export function redactScanResultForStorage(result: ScanResult): ScanResult {
  return {
    ...result,
    ast: { ...result.ast, issues: mapIssues(result.ast.issues) },
    security: { ...result.security, issues: mapIssues(result.security.issues) },
    dependency: { ...result.dependency, issues: mapIssues(result.dependency.issues) },
    outdated: { ...result.outdated, issues: mapIssues(result.outdated.issues) },
    tests: { ...result.tests, issues: mapIssues(result.tests.issues) },
    database: { ...result.database, issues: mapIssues(result.database.issues) },
    api: { ...result.api, issues: mapIssues(result.api.issues) },
    env: { ...result.env, issues: mapIssues(result.env.issues) },
    architecture: { ...result.architecture, issues: mapIssues(result.architecture.issues) },
    performance: { ...result.performance, issues: mapIssues(result.performance.issues) },
    memory: { ...result.memory, issues: mapIssues(result.memory.issues) },
    codeSmell: { ...result.codeSmell, issues: mapIssues(result.codeSmell.issues) },
    migration: { ...result.migration, issues: mapIssues(result.migration.issues) },
    inventory: { ...result.inventory, issues: mapIssues(result.inventory.issues) },
    lint: { ...result.lint, issues: mapIssues(result.lint.issues) },
    ...(result.trustedIssues !== undefined ? { trustedIssues: mapIssues(result.trustedIssues) } : {}),
  };
}
