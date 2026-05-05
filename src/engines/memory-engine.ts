import { readFile } from 'node:fs/promises';
import { normalize } from 'node:path';

import type { Issue, MemoryScanResult } from '../core/types.js';
import type { FileFilterOptions } from '../core/engine-options.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { runPool } from '../utils/async-pool.js';

function mkIssue(
  id: string,
  severity: Issue['severity'],
  title: string,
  file: string,
  line: number,
  description: string,
  impact: string,
  fix: string,
  extra: Partial<Issue> = {},
): Issue {
  return {
    id: `memory:${id}:${file}:${String(line)}`,
    engine: 'memory',
    severity,
    title,
    file,
    line,
    description,
    impact,
    fix,
    category: 'memory',
    confidence: 'medium',
    whyItMatters: 'Leaks in long-running Node processes manifest as OOM crashes hours later.',
    ...extra,
  };
}

async function scanFile(
  path: string,
  getSourceText?: (normalizedAbs: string) => string | undefined,
): Promise<Issue[]> {
  const issues: Issue[] = [];
  let text: string | undefined = getSourceText?.(normalize(path));
  if (text === undefined) {
    try {
      text = await readFile(path, 'utf8');
    } catch {
      return issues;
    }
  }
  const lines = text.split(/\r?\n/);

  const hasSetInterval = /\bsetInterval\s*\(/.test(text);
  const hasClearInterval = /\bclearInterval\s*\(/.test(text);
  if (hasSetInterval && !hasClearInterval) {
    const idx = lines.findIndex((l) => /\bsetInterval\s*\(/.test(l));
    issues.push(
      mkIssue(
        'setInterval-no-clear',
        'MEDIUM',
        'setInterval without clearInterval in same file',
        path,
        idx >= 0 ? idx + 1 : 1,
        'Timers can keep the process alive and accumulate closure retention.',
        'Memory growth and background work after shutdown.',
        'Store timer handles; clear on teardown; prefer cron/worker for periodic work.',
        { whyItBlocks: 'Forgotten intervals pin closures and prevent GC of large captured objects.' },
      ),
    );
  }

  if (/\baddListener\s*\(|\b\.on\s*\(\s*['"]/.test(text) && !/\b(removeListener|off|removeAllListeners)\s*\(/.test(text)) {
    const idx = lines.findIndex((l) => /\baddListener\s*\(|\b\.on\s*\(\s*['"]/.test(l));
    issues.push(
      mkIssue(
        'event-listener-no-remove',
        'LOW',
        'Event listener registered without matching removal',
        path,
        idx >= 0 ? idx + 1 : 1,
        'Long-lived emitters retain listener closures if they are never detached.',
        'Gradual memory growth in hot-reload, reconnect, or test loops.',
        'Remove listeners on teardown; prefer AbortSignal / once where possible.',
      ),
    );
  }

  // Global cache without bound.
  const unboundedCache = /\b(?:const|let|var)\s+\w+\s*=\s*new\s+(?:Map|Set)\s*\(/.test(text) && !/\b(?:LRU|lru-cache|delete\s*\(|clear\s*\()/.test(text);
  if (unboundedCache) {
    const idx = lines.findIndex((l) => /\bnew\s+(?:Map|Set)\s*\(/.test(l));
    issues.push(
      mkIssue(
        'unbounded-cache',
        'MEDIUM',
        'Module-level Map/Set cache without eviction',
        path,
        idx >= 0 ? idx + 1 : 1,
        'A module-scoped Map/Set is retained for process lifetime and can grow without bound.',
        'Linear memory growth per unique key until OOM.',
        'Use lru-cache with max size/TTL; or delete/clear on a schedule.',
        { whyItBlocks: 'Unbounded caches are the #1 cause of mystery OOM in Node services.' },
      ),
    );
  }

  // Buffer accumulation.
  if (/\bBuffer\.concat\s*\(/.test(text) && /push\s*\(\s*chunk\s*\)/.test(text)) {
    const idx = lines.findIndex((l) => /push\s*\(\s*chunk\s*\)/.test(l));
    issues.push(
      mkIssue(
        'buffer-accumulate',
        'MEDIUM',
        'Buffering an entire stream in memory',
        path,
        idx >= 0 ? idx + 1 : 1,
        'Pushing chunks into an array and calling Buffer.concat allocates the whole payload in RAM.',
        'One large upload can OOM the process.',
        'Stream to disk / S3 directly, or enforce a max body size.',
      ),
    );
  }

  // Missing close on `createReadStream` / DB client.
  if (/\bcreateReadStream\s*\(/.test(text) && !/\.(close|destroy|end)\s*\(/.test(text)) {
    const idx = lines.findIndex((l) => /\bcreateReadStream\s*\(/.test(l));
    issues.push(
      mkIssue(
        'stream-no-close',
        'MEDIUM',
        'Read stream opened without explicit close/destroy',
        path,
        idx >= 0 ? idx + 1 : 1,
        'fs.createReadStream without an end/close keeps a file descriptor until GC.',
        'Slow file-descriptor leak under concurrent load.',
        'Pipe to consumer, await pipeline, or explicitly destroy on error.',
      ),
    );
  }

  // require.cache tampering (classic leak pattern in long-running processes).
  if (/require\.cache\s*\[/.test(text)) {
    const idx = lines.findIndex((l) => /require\.cache\s*\[/.test(l));
    issues.push(
      mkIssue(
        'require-cache-tamper',
        'LOW',
        'Direct mutation of require.cache',
        path,
        idx >= 0 ? idx + 1 : 1,
        'Manual require.cache manipulation is fragile and often leaks detached module instances.',
        'Subtle memory and state leaks in long-lived processes.',
        'Avoid mutating require.cache in production code; use dynamic import or module resolution hooks.',
      ),
    );
  }

  // Global variable accumulation.
  if (/\bglobal\.[A-Za-z0-9_]+\s*=\s*/.test(text)) {
    const idx = lines.findIndex((l) => /\bglobal\.[A-Za-z0-9_]+\s*=\s*/.test(l));
    issues.push(
      mkIssue(
        'global-assignment',
        'LOW',
        'Writing to Node global object',
        path,
        idx >= 0 ? idx + 1 : 1,
        'Attaching state to `global` persists across requests and retains closures.',
        'Memory leaks and test pollution.',
        'Encapsulate state in a module singleton or an explicit service.',
      ),
    );
  }

  return issues;
}

export interface MemoryEngineOptions extends FileFilterOptions {
  readonly pathsOverride?: ReadonlySet<string>;
}

export async function runMemoryEngine(
  cwd: string,
  concurrency: number,
  options?: MemoryEngineOptions,
): Promise<MemoryScanResult> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  let scoped = normalizedAll;
  if (options?.fileFilter) {
    scoped = scoped.filter((f) => options.fileFilter?.has(f));
  }
  const pathsOverride = options?.pathsOverride;
  if (pathsOverride) {
    scoped = scoped.filter((f) => pathsOverride.has(f));
  }
  const filtered = Boolean(options?.fileFilter || pathsOverride);
  if (filtered && scoped.length === 0) {
    return { issues: [] };
  }
  const targets = filtered ? scoped : normalizedAll;
  const getText = options?.getSourceText;
  const chunks = await runPool(targets, concurrency, (f) => scanFile(f, getText));
  return { issues: chunks.flat() };
}
