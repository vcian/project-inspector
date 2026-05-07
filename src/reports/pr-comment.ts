import { normalize, relative, resolve } from 'node:path';

import { fingerprintTrustedIssue } from '../core/baseline.js';
import type { Issue, ScanResult } from '../core/types.js';
import { sortIssuesBySeverity } from '../report/markdown.js';

export interface PrCommentOptions {
  /** When set, only issues in these repo-relative paths (forward slashes) appear in the scoped section. */
  readonly scopeRelPaths?: ReadonlySet<string>;
  /** Fingerprints from last `--save-baseline`; issues not in set are "new". */
  readonly baselineFingerprints?: ReadonlySet<string>;
  /** Max characters for GitHub comment body safety (default 65536). */
  readonly maxChars?: number;
}

function relNorm(cwd: string, file: string): string {
  return relative(cwd, file).replaceAll('\\', '/');
}

function inScope(cwd: string, issue: Issue, scope: ReadonlySet<string> | undefined): boolean {
  if (scope === undefined || scope.size === 0) {
    return true;
  }
  const r = relNorm(cwd, issue.file);
  for (const p of scope) {
    const pat = p.replaceAll('\\', '/').replace(/^\/+/, '');
    if (r === pat || r.startsWith(`${pat}/`)) {
      return true;
    }
  }
  return false;
}

function classifyNew(
  cwd: string,
  issue: Issue,
  baseline: ReadonlySet<string> | undefined,
): 'new' | 'existing' | 'unknown' {
  if (baseline === undefined || baseline.size === 0) {
    return 'unknown';
  }
  const fp = fingerprintTrustedIssue(cwd, issue);
  return baseline.has(fp) ? 'existing' : 'new';
}

/**
 * GitHub-flavored Markdown suitable for a PR comment or job summary.
 * Groups by file; labels each finding as new vs existing when baseline is available.
 */
export function renderPrCommentMarkdown(result: ScanResult, opts: PrCommentOptions): string {
  const cwd = result.cwd;
  const trusted = result.trustedIssues !== undefined ? [...result.trustedIssues] : [];
  const sorted = sortIssuesBySeverity(trusted);
  const maxChars = opts.maxChars ?? 65_000;

  const lines: string[] = [
    '## project-inspector — PR review bundle',
    '',
    `- **Readiness:** ${String(result.scores.productionReadiness)}/100`,
    `- **Gate:** ${result.productionDecision?.gateOk === true ? 'PASS' : result.productionDecision?.gateOk === false ? 'FAIL' : 'n/a'}`,
    `- **Trusted findings:** ${String(trusted.length)}`,
    '',
  ];

  if (opts.baselineFingerprints !== undefined && opts.baselineFingerprints.size > 0) {
    let newC = 0;
    let existC = 0;
    for (const i of sorted) {
      const c = classifyNew(cwd, i, opts.baselineFingerprints);
      if (c === 'new') {
        newC += 1;
      } else if (c === 'existing') {
        existC += 1;
      }
    }
    lines.push(`- **New vs baseline:** ${String(newC)} new, ${String(existC)} unchanged fingerprints`, '');
  } else {
    lines.push('_Run with a prior `--save-baseline` snapshot to label **new** vs **existing** findings._', '');
  }

  if (opts.scopeRelPaths !== undefined && opts.scopeRelPaths.size > 0) {
    lines.push(
      '### Scoped to changed paths',
      '',
      `Only paths matching: ${[...opts.scopeRelPaths].map((p) => `\`${p}\``).join(', ')}`,
      '',
    );
  }

  const scoped = sorted.filter((i) => inScope(cwd, i, opts.scopeRelPaths));
  const byFile = new Map<string, Issue[]>();
  for (const issue of scoped) {
    const key = relNorm(cwd, issue.file);
    const arr = byFile.get(key) ?? [];
    arr.push(issue);
    byFile.set(key, arr);
  }

  const files = [...byFile.keys()].sort();
  for (const file of files) {
    const issues = byFile.get(file) ?? [];
    lines.push(`### \`${file}\``, '');
    for (const issue of issues) {
      const cls = classifyNew(cwd, issue, opts.baselineFingerprints);
      const badge =
        cls === 'new' ? '🆕 **new**' : cls === 'existing' ? '↩️ existing' : '❔ unclassified';
      lines.push(
        `- ${badge} · **${issue.severity}** · \`${issue.engine}\` — ${issue.title}`,
        `  - Line ${String(issue.line)}: ${issue.description.slice(0, 280)}${issue.description.length > 280 ? '…' : ''}`,
        `  - Fix: ${issue.fix.slice(0, 200)}${issue.fix.length > 200 ? '…' : ''}`,
        '',
      );
    }
  }

  if (scoped.length === 0 && trusted.length > 0) {
    lines.push('_No trusted issues matched the PR scope paths; see full `security.md` or `index.html`._', '');
  }

  let body = lines.join('\n');
  if (body.length > maxChars) {
    body = `${body.slice(0, maxChars - 200)}\n\n_…truncated for size; see report bundle._\n`;
  }
  return body;
}

/** Parse comma-separated or newline-separated paths from env-style string. */
export function parsePrScopePaths(raw: string | undefined, _cwd: string): ReadonlySet<string> | undefined {
  if (raw === undefined || raw.trim().length === 0) {
    return undefined;
  }
  const parts = raw
    .split(/[\n,]/u)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (parts.length === 0) {
    return undefined;
  }
  const out = new Set<string>();
  for (const p of parts) {
    const n = normalize(p).replaceAll('\\', '/');
    out.add(n.replace(/^\/+/, ''));
  }
  return out;
}

export async function loadPrScopeFromFile(
  filePath: string,
  cwd: string,
): Promise<ReadonlySet<string> | undefined> {
  const { readFile } = await import('node:fs/promises');
  try {
    const text = await readFile(filePath, 'utf8');
    return parsePrScopePaths(text, cwd);
  } catch {
    return undefined;
  }
}

/** Resolve PR scope from `--pr-scope-file` or `PROJECT_INSPECTOR_PR_SCOPE`. */
export async function resolvePrCommentScope(
  options: { readonly prScopeFile?: string },
  cwd: string,
): Promise<readonly string[] | undefined> {
  if (options.prScopeFile !== undefined && options.prScopeFile.trim().length > 0) {
    const abs = resolve(cwd, options.prScopeFile.trim());
    const s = await loadPrScopeFromFile(abs, cwd);
    if (s !== undefined && s.size > 0) {
      return [...s];
    }
  }
  const env = process.env.PROJECT_INSPECTOR_PR_SCOPE;
  const s = parsePrScopePaths(env, cwd);
  if (s !== undefined && s.size > 0) {
    return [...s];
  }
  return undefined;
}
