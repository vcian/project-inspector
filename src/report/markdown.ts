import type { Issue } from '../core/types.js';

import { redactForReport } from './redact-evidence.js';

const SEVERITY_ORDER: Record<Issue['severity'], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export function sortIssuesBySeverity(issues: readonly Issue[]): Issue[] {
  return [...issues].sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sev !== 0) {
      return sev;
    }
    return a.file.localeCompare(b.file) || a.line - b.line;
  });
}

function shortLoc(file: string, line: number): string {
  const base = file.split(/[/\\]/).slice(-3).join('/');
  return `${base}:${String(line)}`;
}

/** Short label for compact tables (issue list / HTML). */
export function issueConfidenceCell(issue: Issue): string {
  return issue.confidence ?? '—';
}

function confidenceScoreText(confidence: Issue['confidence'] | undefined): string {
  if (confidence === 'high') {
    return '9/10 (high)';
  }
  if (confidence === 'medium') {
    return '6/10 (medium)';
  }
  if (confidence === 'low') {
    return '3/10 (low)';
  }
  return '—';
}

export function renderIssueMarkdown(issue: Issue): string {
  const loc = `${issue.file}:${String(issue.line)}`;
  const lines = [
    `### ${issue.title}`,
    '',
    '| Field | Value |',
    '| --- | --- |',
    `| **Severity** | **${issue.severity}** |`,
    `| **Location** | \`${loc}\` |`,
    `| **Engine** | \`${issue.engine}\` |`,
  ];

  if (issue.framework !== undefined) {
    lines.push(`| **Framework** | \`${issue.framework}\` |`);
  }
  if (issue.category !== undefined) {
    lines.push(`| **Category** | \`${issue.category}\` |`);
  }
  lines.push(`| **Confidence** | ${confidenceScoreText(issue.confidence)} |`);
  if (issue.count !== undefined && issue.count > 1) {
    const range =
      issue.firstLine !== undefined && issue.lastLine !== undefined && issue.firstLine !== issue.lastLine
        ? ` (lines ${String(issue.firstLine)}–${String(issue.lastLine)})`
        : '';
    lines.push(`| **Occurrences in file** | ${String(issue.count)}${range} |`);
  }
  lines.push('');

  lines.push('#### Description', '', issue.description, '');

  if (issue.whyItMatters !== undefined && issue.whyItMatters.length > 0) {
    lines.push('#### Why it matters', '', issue.whyItMatters, '');
  }

  lines.push('#### Risk / impact', '', issue.impact, '');

  if (issue.whyItBlocks !== undefined && issue.whyItBlocks.length > 0) {
    lines.push('#### Performance note', '', issue.whyItBlocks, '');
  }

  lines.push('#### Remediation', '', issue.fix, '');

  if (issue.compliance !== undefined && issue.compliance.length > 0) {
    lines.push(
      '#### Compliance mapping',
      '',
      ...issue.compliance.flatMap((c) => [`- **${c.framework}** — \`${c.ruleId}\`: ${c.ruleName}`]),
      '',
    );
  }

  const snippet = issue.codeSnippet;
  if (snippet !== undefined && snippet.length > 0) {
    const clipped = clipSnippet(snippet);
    lines.push('#### Affected code', '', '```text', clipped, '```', '');
  } else {
    const safeCode = redactForReport(issue);
    if (safeCode !== undefined) {
      lines.push('#### Evidence (truncated, redacted)', '', '```text', safeCode, '```', '');
    }
  }

  return lines.join('\n');
}

/** Legacy renderer — kept for backward-compat callers. Prefer `renderBoundedIssuesSection`. */
export function renderIssuesSection(title: string, issues: readonly Issue[]): string {
  return renderBoundedIssuesSection(title, issues, { topExamplesPerGroup: 3, maxGroups: 40 });
}

export interface BoundedSectionOptions {
  /** How many example occurrences to print per (engine, title) group. Default 3. */
  readonly topExamplesPerGroup?: number;
  /** Hard ceiling on number of distinct groups to render. Default 40. */
  readonly maxGroups?: number;
  /** Optional intro paragraph printed under the section heading. */
  readonly intro?: string;
  /** When true, always render every group severity summary row even with 0 matches. */
  readonly alwaysShowSeverityTable?: boolean;
  /** Prefix for numbered findings in headings (e.g. `FINDING` → `FINDING-1`). Default `FINDING`. */
  readonly findingIdPrefix?: string;
}

interface IssueGroup {
  readonly key: string;
  readonly title: string;
  readonly engine: string;
  readonly severity: Issue['severity'];
  readonly items: Issue[];
  readonly totalCount: number;
}

function groupIssues(issues: readonly Issue[]): IssueGroup[] {
  const map = new Map<string, IssueGroup>();
  for (const issue of issues) {
    const key = `${issue.engine}::${issue.title}::${issue.severity}`;
    const prev = map.get(key);
    if (prev === undefined) {
      map.set(key, {
        key,
        title: issue.title,
        engine: issue.engine,
        severity: issue.severity,
        items: [issue],
        totalCount: issue.count ?? 1,
      });
    } else {
      prev.items.push(issue);
      const updated: IssueGroup = {
        ...prev,
        totalCount: prev.totalCount + (issue.count ?? 1),
      };
      map.set(key, updated);
    }
  }
  const groups = [...map.values()];
  groups.sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sev !== 0) {
      return sev;
    }
    return b.items.length - a.items.length;
  });
  return groups;
}

function clipSnippet(snippet: string): string {
  const MAX_LINES = 6;
  const MAX_LINE_LEN = 160;
  const lines = snippet.split(/\r?\n/).slice(0, MAX_LINES);
  return lines.map((l) => (l.length > MAX_LINE_LEN ? `${l.slice(0, MAX_LINE_LEN)}…` : l)).join('\n');
}

function renderGroupBlock(
  group: IssueGroup,
  topExamples: number,
  findingIndex: number,
  findingIdPrefix: string,
): string {
  const head = group.items[0];
  if (head === undefined) {
    return '';
  }

  const out: string[] = [];
  const fid = `${findingIdPrefix}-${String(findingIndex)}`;
  out.push(`### \`${fid}\`: ${group.title}`);
  out.push('');
  out.push('| Field | Value |');
  out.push('| --- | --- |');
  out.push(`| **Severity** | **${group.severity}** |`);
  out.push(`| **Engine** | \`${group.engine}\` |`);
  out.push(`| **Category** | ${head.category !== undefined ? `\`${head.category}\`` : '—'} |`);
  out.push(`| **Confidence** | ${confidenceScoreText(head.confidence)} |`);
  out.push(`| **Files affected** | ${String(new Set(group.items.map((i) => i.file)).size)} |`);
  out.push(`| **Total matches** | ${String(group.totalCount)} |`);
  if (head.framework !== undefined) {
    out.push(`| **Framework** | \`${head.framework}\` |`);
  }
  out.push('');

  out.push('#### Description');
  out.push('');
  out.push(head.description);
  out.push('');

  if (head.whyItMatters !== undefined && head.whyItMatters.length > 0) {
    out.push('#### Why it matters');
    out.push('');
    out.push(head.whyItMatters);
    out.push('');
  }

  out.push('#### Risk / impact');
  out.push('');
  out.push(head.impact);
  out.push('');

  out.push('#### Triage (why / fix / verify)');
  out.push('');
  out.push(
    `- **Why it matters:** ${head.whyItMatters ?? head.description.slice(0, 200)}${head.description.length > 200 ? '…' : ''}`,
  );
  out.push(`- **Fix:** ${head.fix.slice(0, 220)}${head.fix.length > 220 ? '…' : ''}`);
  out.push('- **Verify:** Re-run `project-inspector check`; add or extend tests touching this path.');
  out.push('');

  if (head.whyItBlocks !== undefined && head.whyItBlocks.length > 0) {
    out.push('#### Performance note');
    out.push('');
    out.push(head.whyItBlocks);
    out.push('');
  }

  out.push('#### Remediation');
  out.push('');
  out.push(head.fix);
  out.push('');

  if (head.compliance !== undefined && head.compliance.length > 0) {
    out.push('#### Compliance mapping');
    out.push('');
    for (const c of head.compliance) {
      out.push(`- **${c.framework}** — \`${c.ruleId}\`: ${c.ruleName}`);
    }
    out.push('');
  }

  const examples = group.items.slice(0, Math.max(1, topExamples));
  out.push('#### Affected locations');
  out.push('');
  out.push('| Severity | Confidence | Location | Detail |');
  out.push('| --- | --- | --- | --- |');
  for (const ex of examples) {
    const detail = ex.count !== undefined && ex.count > 1 ? `${String(ex.count)}× in file` : '';
    out.push(
      `| ${ex.severity} | ${issueConfidenceCell(ex)} | \`${shortLoc(ex.file, ex.line)}\` | ${detail} |`,
    );
  }
  out.push('');

  const withSnippet = examples.find((e) => typeof e.codeSnippet === 'string' && e.codeSnippet.length > 0);
  if (withSnippet?.codeSnippet !== undefined) {
    out.push('```text');
    out.push(`// ${shortLoc(withSnippet.file, withSnippet.line)}`);
    out.push(clipSnippet(withSnippet.codeSnippet));
    out.push('```');
    out.push('');
  }

  if (group.items.length > examples.length) {
    out.push(`_...and ${String(group.items.length - examples.length)} more occurrence(s) omitted from the markdown summary._`);
    out.push('');
  }

  return out.join('\n');
}

function severitySummary(issues: readonly Issue[]): string {
  const counts: Record<Issue['severity'], number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const i of issues) {
    counts[i.severity] += 1;
  }
  return [
    '| Severity | Count |',
    '| --- | ---: |',
    `| CRITICAL | ${String(counts.CRITICAL)} |`,
    `| HIGH | ${String(counts.HIGH)} |`,
    `| MEDIUM | ${String(counts.MEDIUM)} |`,
    `| LOW | ${String(counts.LOW)} |`,
  ].join('\n');
}

/**
 * Grouped, deduplicated, bounded rendering. Uses (engine, title, severity) groups
 * and prints a fixed number of examples per group with a table + optional code snippet.
 */
export function renderBoundedIssuesSection(
  title: string,
  issues: readonly Issue[],
  opts: BoundedSectionOptions = {},
): string {
  const topExamplesPerGroup = Math.max(1, opts.topExamplesPerGroup ?? 3);
  const maxGroups = Math.max(1, opts.maxGroups ?? 40);

  const header: string[] = [
    `## ${title}`,
    '',
    `Total issues in this section: **${String(issues.length)}**`,
    '',
  ];

  if (opts.intro !== undefined && opts.intro.length > 0) {
    header.push(opts.intro, '');
  }

  if (issues.length === 0) {
    if (opts.alwaysShowSeverityTable === true) {
      header.push(severitySummary(issues), '');
    }
    header.push('_No issues detected in this category._', '');
    return header.join('\n');
  }

  header.push(severitySummary(issues), '');

  const groups = groupIssues(issues);
  const visible = groups.slice(0, maxGroups);
  const hidden = groups.length - visible.length;
  const findingPrefix = opts.findingIdPrefix ?? 'FINDING';

  const body: string[] = [];
  for (let gi = 0; gi < visible.length; gi += 1) {
    const g = visible[gi];
    if (g === undefined) {
      continue;
    }
    body.push(renderGroupBlock(g, topExamplesPerGroup, gi + 1, findingPrefix));
  }
  if (hidden > 0) {
    body.push(`_${String(hidden)} additional issue group(s) omitted from the markdown summary._`);
    body.push('');
  }

  return [...header, ...body].join('\n');
}

const MD_HARD_LINE_CAP = 1500;

/**
 * Hard-cap markdown so huge reports never become unreadable.
 */
export function enforceMarkdownLineCap(md: string, sourceName?: string): string {
  const lines = md.split(/\r?\n/);
  if (lines.length <= MD_HARD_LINE_CAP) {
    return md;
  }
  const kept = lines.slice(0, MD_HARD_LINE_CAP);
  kept.push('');
  kept.push('---');
  kept.push('');
  kept.push(
    `_Report truncated at ${String(MD_HARD_LINE_CAP)} lines (full list was ${String(lines.length)} lines) for \`${sourceName ?? 'this section'}\`._`,
  );
  return kept.join('\n');
}
