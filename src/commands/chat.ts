import { readFile, readdir } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { join, resolve } from 'node:path';

import { ensureScanShape } from '../core/scan-result-shape.js';
import type { Issue, ScanResult } from '../core/types.js';

interface ChatState {
  readonly reports: ReadonlyMap<string, string>;
  readonly result: ScanResult;
}

function tokenize(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9_./-]+/g)
    .filter((token) => token.length >= 2);
}

async function loadReports(reportDir: string): Promise<ReadonlyMap<string, string>> {
  const corpus = new Map<string, string>();
  let names: readonly string[] = [];
  try {
    names = await readdir(reportDir);
  } catch {
    return corpus;
  }

  for (const name of names) {
    if (!name.endsWith('.md')) {
      continue;
    }
    try {
      corpus.set(name, await readFile(join(reportDir, name), 'utf8'));
    } catch {
      // ignore unreadable files
    }
  }

  return corpus;
}

async function loadMergedScan(reportDir: string): Promise<ScanResult | null> {
  try {
    const raw = await readFile(join(reportDir, '.cache', 'merged-scan.json'), 'utf8');
    return ensureScanShape(JSON.parse(raw) as ScanResult);
  } catch {
    return null;
  }
}

function scoreIssue(issue: Issue, tokens: readonly string[]): number {
  const haystack = `${issue.engine} ${issue.severity} ${issue.title} ${issue.description} ${issue.fix} ${issue.file}`.toLowerCase();
  let score = 0;
  for (const token of tokens) {
    if (haystack.includes(token)) {
      score += 5;
    }
  }
  score += issue.severity === 'CRITICAL' ? 4 : issue.severity === 'HIGH' ? 3 : issue.severity === 'MEDIUM' ? 2 : 1;
  return score;
}

function allIssues(result: ScanResult): Issue[] {
  return [
    ...result.ast.issues,
    ...result.security.issues,
    ...result.dependency.issues,
    ...result.outdated.issues,
    ...result.api.issues,
    ...result.env.issues,
    ...result.architecture.issues,
    ...result.performance.issues,
    ...result.memory.issues,
    ...result.codeSmell.issues,
    ...result.migration.issues,
    ...result.tests.issues,
    ...result.database.issues,
    ...result.inventory.issues,
    ...result.lint.issues,
  ];
}

function renderIssue(issue: Issue, cwd: string): string {
  const file = issue.file.startsWith(cwd) ? issue.file.slice(cwd.length + 1).replaceAll('\\', '/') : issue.file;
  return `- [${issue.severity}] ${issue.engine} ${issue.title} (${file}:${String(issue.line)})\n  Fix: ${issue.fix}`;
}

function renderHelp(): string {
  return [
    'Commands:',
    ':help                Show commands',
    ':quit                Exit chat',
    ':scores              Show current scores',
    ':hotspots            Show top hotspots',
    ':issues <engine>     List issues for one engine',
    '',
    'Any other text runs an offline keyword match against merged-scan.json and the markdown report corpus.',
  ].join('\n');
}

function renderScores(result: ScanResult): string {
  return [
    `Security: ${String(result.scores.security)}`,
    `Performance: ${String(result.scores.performance)}`,
    `Code Quality: ${String(result.scores.codeQuality)}`,
    `Compliance: ${String(result.scores.compliance)}`,
    `Tests: ${String(result.scores.tests)}`,
    `Production Readiness: ${String(result.scores.productionReadiness)}`,
  ].join('\n');
}

function renderHotspots(result: ScanResult): string {
  if (result.hotspots.length === 0) {
    return 'No hotspots available. Run a scan first.';
  }
  return result.hotspots
    .slice(0, 10)
    .map(
      (hotspot) =>
        `${String(hotspot.rank)}. [${hotspot.severity}] ${hotspot.engine} ${hotspot.title} (${hotspot.file}:${String(hotspot.line)})`,
    )
    .join('\n');
}

function renderIssuesByEngine(result: ScanResult, engine: string): string {
  const matches = allIssues(result).filter((issue) => issue.engine.toLowerCase() === engine.toLowerCase());
  if (matches.length === 0) {
    return `No issues found for engine "${engine}".`;
  }
  return matches.slice(0, 20).map((issue) => renderIssue(issue, result.cwd)).join('\n');
}

function reportMatches(reports: ReadonlyMap<string, string>, tokens: readonly string[]): string[] {
  return [...reports.entries()]
    .map(([name, content]) => {
      const lower = content.toLowerCase();
      const score = tokens.reduce((sum, token) => sum + (lower.includes(token) ? 1 : 0), 0);
      return { name, content, score };
    })
    .filter((entry) => entry.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, 2)
    .map((entry) => {
      const lower = entry.content.toLowerCase();
      const firstToken = tokens[0] ?? '';
      const index = firstToken.length > 0 ? lower.indexOf(firstToken) : 0;
      const start = Math.max(0, index - 120);
      return `# ${entry.name}\n${entry.content.slice(start, start + 500).trim()}`;
    });
}

function search(state: ChatState, query: string): string {
  const tokens = tokenize(query);
  if (tokens.length === 0) {
    return 'Enter a search query or use :help.';
  }

  const rankedIssues = allIssues(state.result)
    .map((issue) => ({ issue, score: scoreIssue(issue, tokens) }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => right.score - left.score)
    .slice(0, 5)
    .map((entry) => renderIssue(entry.issue, state.result.cwd));

  const matchedReports = reportMatches(state.reports, tokens);

  if (rankedIssues.length === 0 && matchedReports.length === 0) {
    return 'No matching findings were found in the current offline report corpus.';
  }

  const lines: string[] = [];
  if (rankedIssues.length > 0) {
    lines.push('Issue matches:', ...rankedIssues, '');
  }
  if (matchedReports.length > 0) {
    lines.push('Report matches:', ...matchedReports);
  }
  return lines.join('\n');
}

export async function runChatCommand(projectPath: string): Promise<void> {
  const root = resolve(projectPath);
  const reportDir = join(root, 'project-report');
  const [reports, result] = await Promise.all([loadReports(reportDir), loadMergedScan(reportDir)]);

  if (reports.size === 0 || result === null) {
    output.write(`No project-report data found in ${reportDir}. Run "project-inspector scan" first.\n`);
    return;
  }

  const state: ChatState = { reports, result };
  output.write('Offline report chat ready. Type :help for commands.\n');

  const rl = createInterface({ input, output });
  try {
    for (;;) {
      const line = (await rl.question('project-inspector> ')).trim();
      if (line === ':quit') {
        break;
      }
      if (line === ':help') {
        output.write(`${renderHelp()}\n`);
        continue;
      }
      if (line === ':scores') {
        output.write(`${renderScores(state.result)}\n`);
        continue;
      }
      if (line === ':hotspots') {
        output.write(`${renderHotspots(state.result)}\n`);
        continue;
      }
      if (line.startsWith(':issues ')) {
        output.write(`${renderIssuesByEngine(state.result, line.slice(8).trim())}\n`);
        continue;
      }
      output.write(`${search(state, line)}\n`);
    }
  } finally {
    rl.close();
  }
}
