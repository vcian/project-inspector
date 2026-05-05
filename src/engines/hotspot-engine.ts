import type { HotspotItem, Issue } from '../core/types.js';

const SEVERITY_ORDER: Record<Issue['severity'], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function centralityScore(file: string, fileFrequency: ReadonlyMap<string, number>): number {
  const freq = fileFrequency.get(file) ?? 1;
  const depth = file.split(/[/\\]/).length;
  let score = Math.min(20, freq * 2);
  if (/(^|[/\\])(src[/\\]index\.(t|j)s|main\.(t|j)s|app\.(t|j)s|server\.(t|j)s)$/.test(file)) {
    score += 8;
  }
  if (/(controller|service|router|middleware|auth)/i.test(file)) {
    score += 4;
  }
  score += Math.max(0, 12 - depth);
  return score;
}

export function computeHotspots(issues: readonly Issue[], limit = 10): readonly HotspotItem[] {
  const fileFrequency = new Map<string, number>();
  for (const i of issues) {
    fileFrequency.set(i.file, (fileFrequency.get(i.file) ?? 0) + 1);
  }

  const ranked = [...issues].map((i) => {
    const sev = SEVERITY_ORDER[i.severity];
    const cent = centralityScore(i.file, fileFrequency);
    const impactLen = i.impact.length;
    const score = sev * 1000 + cent * 10 + Math.min(200, impactLen);
    return { issue: i, score };
  });

  ranked.sort((a, b) => b.score - a.score);

  const out: HotspotItem[] = [];
  const seen = new Set<string>();
  for (const { issue } of ranked) {
    const key = `${issue.engine}:${issue.title}:${issue.file}:${String(issue.line)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push({
      rank: out.length + 1,
      severity: issue.severity,
      title: issue.title,
      file: issue.file,
      line: issue.line,
      engine: issue.engine,
      impact: issue.impact,
      fixHint: issue.fix,
    });
    if (out.length >= limit) {
      break;
    }
  }
  return out;
}
