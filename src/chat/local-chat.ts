import { readFile, readdir } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { join, resolve } from 'node:path';

interface ReportCorpus {
  readonly files: ReadonlyMap<string, string>;
}

async function loadReportCorpus(reportDir: string): Promise<ReportCorpus> {
  const files = new Map<string, string>();
  let names: string[] = [];
  try {
    names = await readdir(reportDir);
  } catch {
    return { files };
  }

  for (const name of names) {
    if (!name.endsWith('.md')) {
      continue;
    }
    const abs = join(reportDir, name);
    try {
      files.set(name, await readFile(abs, 'utf8'));
    } catch {
      // ignore unreadable
    }
  }

  return { files };
}

function naiveAnswer(question: string, corpus: ReportCorpus): string {
  const q = question.trim().toLowerCase();
  if (q.length === 0) {
    return 'Ask a question about the generated reports.';
  }

  if (q.includes('summary') || q.includes('overview')) {
    const s = corpus.files.get('summary.md');
    return s ? s.slice(0, 4000) : 'Not found in analysis';
  }

  if (q.includes('security') || q.includes('vuln') || q.includes('secret')) {
    const s = corpus.files.get('security.md');
    return s ? s.slice(0, 8000) : 'Not found in analysis';
  }

  if (q.includes('architecture') || q.includes('module') || q.includes('circular')) {
    const s = corpus.files.get('architecture.md');
    return s ? s.slice(0, 8000) : 'Not found in analysis';
  }

  if (q.includes('compliance') || q.includes('owasp') || q.includes('gdpr') || q.includes('hipaa')) {
    const s = corpus.files.get('compliance.md');
    return s ? s.slice(0, 12000) : 'Not found in analysis';
  }

  if (q.includes('score') || q.includes('readiness') || q.includes('production')) {
    const s = corpus.files.get('summary.md');
    return s ? s.slice(0, 6000) : 'Not found in analysis';
  }

  // Keyword grep across corpus (deterministic, bounded)
  const hits: string[] = [];
  for (const [name, content] of corpus.files.entries()) {
    const lower = content.toLowerCase();
    const tokens = q.split(/[^a-z0-9_./-]+/g).filter((t) => t.length >= 4);
    const matched = tokens.some((t) => lower.includes(t));
    if (matched) {
      const idx = lower.indexOf(tokens[0] ?? '');
      const start = Math.max(0, idx === -1 ? 0 : idx - 200);
      hits.push(`### Match in ${name}\n\n${content.slice(start, start + 1200)}`);
    }
    if (hits.length >= 3) {
      break;
    }
  }

  if (hits.length === 0) {
    return 'Not found in analysis';
  }

  return hits.join('\n\n---\n\n');
}

export async function runLocalChat(cwd: string): Promise<void> {
  const reportDir = resolve(cwd, 'project-report');
  const corpus = await loadReportCorpus(reportDir);

  if (corpus.files.size === 0) {
    output.write(
      `No markdown reports found in ${reportDir}. Run:\n\n  project-inspector scan\n\n`,
    );
    return;
  }

  output.write(
    `Loaded ${String(corpus.files.size)} report(s). Answers use deterministic keyword search over the reports (offline). Type exit to quit.\n\n`,
  );

  const rl = createInterface({ input, output });
  try {
    for (;;) {
      const q = await rl.question('> ');
      if (['exit', 'quit', ':q'].includes(q.trim().toLowerCase())) {
        break;
      }
      const a = naiveAnswer(q, corpus);
      output.write(`\n${a}\n\n`);
    }
  } finally {
    rl.close();
  }
}
