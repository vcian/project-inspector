import { readFile } from 'node:fs/promises';
import { normalize } from 'node:path';

import type { FileFilterOptions } from '../core/engine-options.js';
import type { Issue, PerformanceScanResult } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { runPool } from '../utils/async-pool.js';

interface PerfRule {
  readonly id: string;
  readonly title: string;
  readonly severity: Issue['severity'];
  readonly regex: RegExp;
  readonly description: string;
  readonly impact: string;
  readonly fix: string;
  readonly whyItBlocks?: string;
  readonly excludeFile?: (path: string) => boolean;
}

function shouldSkipRuleLine(line: string): boolean {
  // Prevent self-matches on inline regex rule declarations.
  return line.trim().startsWith('regex:');
}

function isEngineRuleSource(path: string): boolean {
  const normalized = path.replaceAll('\\', '/').toLowerCase();
  return normalized.endsWith('/src/engines/performance-engine.ts') || normalized.endsWith('/src/engines/security-engine.ts');
}

function isLikelyStartup(path: string): boolean {
  const n = path.replaceAll('\\', '/').toLowerCase();
  return (
    n.endsWith('/main.ts') ||
    n.endsWith('/main.js') ||
    n.endsWith('/server.ts') ||
    n.endsWith('/bootstrap.ts') ||
    n.includes('/config/') ||
    /(^|[\\/])scripts[\\/]/.test(n)
  );
}

const PERF_RULES: readonly PerfRule[] = [
  {
    id: 'sync-fs',
    title: 'Synchronous filesystem API in hot code',
    severity: 'MEDIUM',
    regex: /\b(readFileSync|writeFileSync|readdirSync|statSync|existsSync|lstatSync|renameSync|unlinkSync|mkdirSync|rmSync|rmdirSync)\s*\(/,
    description: 'Synchronous fs APIs block the Node.js event loop.',
    impact: 'Latency spikes under load; poor tail latencies; missed SLAs.',
    fix: 'Use fs/promises async APIs or offload to a worker.',
    whyItBlocks: 'Every sync fs call halts the single event-loop thread for the full IO duration.',
    excludeFile: (p) => isLikelyStartup(p),
  },
  {
    id: 'sync-child-process',
    title: 'Synchronous child_process execution',
    severity: 'HIGH',
    regex: /\b(execSync|execFileSync|spawnSync)\s*\(/,
    description: 'Blocking child_process call in the main thread.',
    impact: 'Each call freezes every request until the process ends.',
    fix: 'Use exec/spawn with async promises; for CPU work, use worker_threads.',
    whyItBlocks: 'A shell subprocess can easily take seconds and blocks the entire event loop.',
  },
  {
    id: 'json-parse-huge',
    title: 'Unbounded JSON.parse on external data',
    severity: 'MEDIUM',
    regex: /JSON\.parse\s*\(\s*(?:req\.body|request\.body|response\.body|await\s+res\.text)/,
    description: 'JSON.parse on untrusted payloads with no size limit.',
    impact: 'DoS via huge payloads; event loop stall; out-of-memory.',
    fix: 'Use body-size limits (express `limit`, Fastify `bodyLimit`) and streaming JSON parsers for large docs.',
    whyItBlocks: 'JSON parsing runs on the main thread and scales with payload size.',
  },
  {
    id: 'sync-crypto',
    title: 'Synchronous CPU-heavy crypto on main thread',
    severity: 'HIGH',
    regex: /\b(?:pbkdf2Sync|scryptSync|randomBytes)\s*\(/,
    description: 'Synchronous bcrypt/pbkdf2/scrypt variants block the event loop.',
    impact: 'Multi-hundred-ms stalls per request under even small concurrency.',
    fix: 'Use the async variants (`pbkdf2`, `scrypt`, `randomBytes(size, cb)`) or argon2/bcrypt async.',
    whyItBlocks: 'Hashing algorithms by design consume 50-200 ms of CPU; blocking stalls every other request.',
  },
  {
    id: 'bcrypt-sync',
    title: 'bcrypt sync API used on the main thread',
    severity: 'HIGH',
    regex: /\bbcrypt(?:js)?\.hashSync\s*\(|\bbcrypt(?:js)?\.compareSync\s*\(/,
    description: 'bcrypt sync calls block the event loop per request.',
    impact: 'Throughput collapse under auth load; easy DoS.',
    fix: 'Use bcrypt.hash / bcrypt.compare (async) everywhere; prefer argon2 for new systems.',
    whyItBlocks: 'bcrypt is intentionally slow — sync variants stall the whole Node process.',
  },
  {
    id: 'await-in-loop',
    title: 'Sequential await inside a loop (possible N+1)',
    severity: 'MEDIUM',
    regex: /for\s*\([^)]*\)\s*\{[^}]{0,200}await\s+/,
    description: 'await inside a for/while loop serializes IO calls.',
    impact: 'Linear latency growth with N; easy source of N+1 queries.',
    fix: 'Collect promises and `await Promise.all(...)` — or batch-load in a single query.',
    whyItBlocks: 'Serialized awaits add up each roundtrip; 100 items × 10ms = 1s of tail latency.',
  },
  {
    id: 'nested-loops',
    title: 'Nested for-loops with mutable accumulator',
    severity: 'LOW',
    regex: /for\s*\([^)]*\)\s*\{[^}]{0,200}for\s*\([^)]*\)\s*\{/,
    description: 'Nested loops often indicate O(n²) behavior.',
    impact: 'CPU hotspots under larger inputs; tail-latency growth.',
    fix: 'Switch to Map/Set lookups or a single pass; consider pagination.',
    whyItBlocks: 'Quadratic work blocks the event loop proportionally to input size.',
  },
  {
    id: 'catastrophic-regex',
    title: 'Catastrophic backtracking regex pattern',
    severity: 'HIGH',
    regex: /new\s+RegExp\s*\([^)]*(\(\.\*\)\+|\(\.\+\)\+|\([^)]+\+\)\+)/,
    description: 'RegExp contains nested quantifiers that can blow up on crafted input.',
    impact: 'ReDoS — a single request can pin a CPU core for minutes.',
    fix: 'Rewrite with possessive / linear patterns; prefer explicit parsers.',
    whyItBlocks: 'Regex engines use the main thread; ReDoS is a classic DoS primitive for Node.',
  },
  {
    id: 'large-inline-array',
    title: 'Very large inline array literal',
    severity: 'LOW',
    regex: /=\s*\[(?:[^\]\n]{0,10},){250,}/,
    description: 'Array literal with hundreds of inline entries found.',
    impact: 'Bigger bundle / slower parse; review if this should be lazy-loaded.',
    fix: 'Load static data from JSON/DB; stream or paginate where appropriate.',
    whyItBlocks: 'V8 parses inline literals synchronously at module load.',
  },
];

function mkIssue(
  rule: PerfRule,
  file: string,
  line: number,
  snippet: string,
): Issue {
  return {
    id: `performance:${rule.id}:${file}:${String(line)}`,
    engine: 'performance',
    severity: rule.severity,
    title: rule.title,
    file,
    line,
    description: rule.description,
    impact: rule.impact,
    fix: rule.fix,
    code: snippet.trim().slice(0, 200),
    codeSnippet: snippet.trim().slice(0, 200),
    category: 'performance',
    confidence: 'medium',
    whyItMatters: 'Node.js has a single event loop — blocking = system-wide slowdown.',
    ...(rule.whyItBlocks !== undefined ? { whyItBlocks: rule.whyItBlocks } : {}),
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
  // Line-level rules.
  const lineRules = PERF_RULES.filter((r) => r.id !== 'await-in-loop' && r.id !== 'nested-loops' && r.id !== 'large-inline-array');
  // Track de-dupe per file+rule to one example line.
  const seen = new Map<string, number>();
  const skipSyncCryptoSelfNoise = isEngineRuleSource(path);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (shouldSkipRuleLine(line)) {
      continue;
    }
    for (const rule of lineRules) {
      if (skipSyncCryptoSelfNoise && rule.id === 'sync-crypto') {
        continue;
      }
      if (rule.excludeFile?.(path) === true) {
        continue;
      }
      rule.regex.lastIndex = 0;
      if (rule.regex.test(line)) {
        const key = `${rule.id}:${path}`;
        if (!seen.has(key)) {
          seen.set(key, i + 1);
          issues.push(mkIssue(rule, path, i + 1, line));
        }
      }
    }
  }
  // Multi-line rules.
  for (const rule of PERF_RULES) {
    if (rule.id !== 'await-in-loop' && rule.id !== 'nested-loops' && rule.id !== 'large-inline-array') {
      continue;
    }
    rule.regex.lastIndex = 0;
    const m = rule.regex.exec(text);
    if (m !== null) {
      const offset = m.index;
      const line = text.slice(0, offset).split('\n').length;
      issues.push(mkIssue(rule, path, line, lines[line - 1] ?? ''));
    }
  }
  return issues;
}

export interface PerformanceEngineOptions extends FileFilterOptions {
  readonly pathsOverride?: ReadonlySet<string>;
}

export async function runPerformanceEngine(
  cwd: string,
  concurrency: number,
  options?: PerformanceEngineOptions,
): Promise<PerformanceScanResult> {
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
