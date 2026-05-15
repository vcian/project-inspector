import { readFileSync } from 'node:fs';
import { extname } from 'node:path';

import type { DatabaseAnalysisResult, Issue } from '../core/types.js';

interface DbRule {
  readonly id: string;
  readonly title: string;
  readonly severity: Issue['severity'];
  readonly impact: string;
  readonly fix: string;
  readonly whyItMatters: string;
  readonly test: (line: string) => boolean;
  readonly requiresSqlish?: boolean;
}

const SQLISH = /\b(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM)\b/i;

const RAW_SQL_HINTS: RegExp[] = [
  /\.\bquery\s*\(\s*['"`]/i,
  /\.\bexecute\s*\(\s*['"`]/i,
  /\bsequelize\.query\s*\(/i,
  /\bprisma\.\$queryRaw(?:Unsafe)?\s*\(/i,
  /\bknex\.raw\s*\(/i,
  /\bpg\.query\s*\(\s*['"`]/i,
  /\bmysql\.query\s*\(\s*['"`]/i,
  /\bSELECT\s+.+\s+FROM\s+/i,
  /\bINSERT\s+INTO\s+/i,
  /\bUPDATE\s+.+\s+SET\s+/i,
  /\bDELETE\s+FROM\s+/i,
];

const RULES: readonly DbRule[] = [
  {
    id: 'raw-sql',
    title: 'Raw SQL usage detected',
    severity: 'MEDIUM',
    impact: 'Higher risk of injection or dialect drift without a centralized query layer.',
    fix: 'Prefer an ORM/query builder with parameters; centralize and review any remaining raw SQL.',
    whyItMatters:
      'Raw SQL bypasses automatic parameter escaping, so string drift or user input in the wrong place becomes an injection bug.',
    test: (line) => RAW_SQL_HINTS.some((re) => re.test(line)),
  },
  {
    id: 'sql-template-interp',
    title: 'Possible SQL interpolation in template literal',
    severity: 'HIGH',
    impact: 'SQL injection or privilege escalation if the interpolated value is attacker-controlled.',
    fix: 'Use parameterized APIs ($1 placeholders, Prisma tagged templates, ORM methods).',
    whyItMatters:
      '`${...}` inside a SQL string concatenates values instead of binding them. That is the textbook SQL injection pattern.',
    test: (line) => /\$\{[^}]+\}/.test(line),
    requiresSqlish: true,
  },
  {
    id: 'sql-string-concat',
    title: 'Possible string-concatenated SQL with user input',
    severity: 'HIGH',
    impact: 'SQL injection or privilege escalation when user input reaches the query.',
    fix: 'Use parameterized APIs and prepared statements instead of string concatenation.',
    whyItMatters:
      'Concatenating `req.body` / `req.query` / `params.*` into a SQL string is the canonical SQL injection mistake.',
    test: (line) => /\+\s*(?:req\.|params\.|query\.|body\.)/i.test(line),
    requiresSqlish: true,
  },
  {
    id: 'prisma-queryRawUnsafe',
    title: 'Prisma $queryRawUnsafe — raw SQL without tagged template',
    severity: 'HIGH',
    impact: 'Bypasses Prisma parameter binding; inputs must be escaped manually.',
    fix: 'Use Prisma tagged template `$queryRaw` (with `Prisma.sql`) or `$queryRawTyped` instead.',
    whyItMatters:
      '`$queryRawUnsafe` skips the safe tagged-template API and reverts you to hand-written escaping, which is easy to get wrong.',
    test: (line) => /\$queryRawUnsafe\s*\(/i.test(line),
  },
  {
    id: 'select-star',
    title: 'SELECT * may pull large result sets',
    severity: 'LOW',
    impact: 'Performance and memory pressure under load; schema drift risk.',
    fix: 'Select explicit columns; add pagination/LIMIT and indexes on filter columns.',
    whyItMatters:
      '`SELECT *` loads every column, wastes RAM/bandwidth, and silently adds unbounded data to JSON responses when new columns are added.',
    test: (line) => /\bSELECT\s+\*\s+FROM\b/i.test(line),
  },
];

const ORM_IMPORTS: ReadonlyArray<{ readonly pattern: RegExp; readonly name: string }> = [
  { pattern: /\bfrom\s+['"]mongoose['"]|require\s*\(\s*['"]mongoose['"]\s*\)/, name: 'mongoose' },
  { pattern: /\bfrom\s+['"]@prisma\/client['"]|require\s*\(\s*['"]@prisma\/client['"]\s*\)/, name: 'prisma' },
  { pattern: /\bfrom\s+['"]sequelize['"]|require\s*\(\s*['"]sequelize['"]\s*\)/, name: 'sequelize' },
  { pattern: /\bfrom\s+['"]typeorm['"]|require\s*\(\s*['"]typeorm['"]\s*\)/, name: 'typeorm' },
  { pattern: /\bfrom\s+['"]drizzle-orm['"]|require\s*\(\s*['"]drizzle-orm['"]\s*\)/, name: 'drizzle-orm' },
];

const IGNORED_PATH_RE =
  /(^|[\\/])(?:node_modules|dist|build|coverage|\.next|\.turbo|\.cache|out|public|prisma[\\/]migrations|drizzle[\\/]migrations|migrations|supabase[\\/]migrations|generated|\.prisma)[\\/]/i;

const SUPPORTED_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

function shouldSkipFile(absPath: string): boolean {
  if (!SUPPORTED_EXT.has(extname(absPath).toLowerCase())) {
    return true;
  }
  const withSep = `/${absPath.replaceAll('\\', '/')}`;
  return IGNORED_PATH_RE.test(withSep);
}

function snippetAround(lines: readonly string[], lineIndex: number, context = 1): string {
  const start = Math.max(0, lineIndex - context);
  const end = Math.min(lines.length, lineIndex + context + 1);
  const out: string[] = [];
  for (let i = start; i < end; i += 1) {
    const marker = i === lineIndex ? '>' : ' ';
    out.push(`${marker} ${String(i + 1).padStart(4, ' ')} | ${(lines[i] ?? '').slice(0, 180)}`);
  }
  return out.join('\n');
}

function mkIssue(params: {
  readonly rule: DbRule;
  readonly file: string;
  readonly firstLine: number;
  readonly lastLine: number;
  readonly count: number;
  readonly snippet: string;
}): Issue {
  const { rule, file, firstLine, lastLine, count, snippet } = params;
  const id = `database:${file}:${rule.id}`.replaceAll(/\s+/g, '_');
  return {
    id,
    engine: 'database',
    severity: rule.severity,
    title: rule.title,
    file,
    line: firstLine,
    description:
      count > 1
        ? `Matched ${String(count)} time(s) in this file (lines ${String(firstLine)}–${String(lastLine)}).`
        : `Matched once at line ${String(firstLine)}.`,
    impact: rule.impact,
    fix: rule.fix,
    category: 'database',
    confidence: 'medium',
    whyItMatters: rule.whyItMatters,
    codeSnippet: snippet,
    count,
    firstLine,
    lastLine,
  };
}

export function runDatabaseEngineOnFile(absPath: string, content: string): DatabaseAnalysisResult {
  if (shouldSkipFile(absPath)) {
    return { issues: [], ormSignals: [], rawSqlFileCount: 0 };
  }

  const ormSet = new Set<string>();
  for (const { pattern, name } of ORM_IMPORTS) {
    if (pattern.test(content)) {
      ormSet.add(name);
    }
  }

  const lines = content.split(/\r?\n/);

  interface RuleHit {
    firstLine: number;
    lastLine: number;
    count: number;
    firstSnippet: string;
  }
  const hits = new Map<string, RuleHit>();
  let rawHit = false;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const sqlish = SQLISH.test(line);
    for (const rule of RULES) {
      if (rule.requiresSqlish === true && !sqlish) {
        continue;
      }
      if (!rule.test(line)) {
        continue;
      }
      if (rule.id === 'raw-sql') {
        rawHit = true;
      }
      const key = rule.id;
      const prev = hits.get(key);
      if (prev === undefined) {
        hits.set(key, {
          firstLine: i + 1,
          lastLine: i + 1,
          count: 1,
          firstSnippet: snippetAround(lines, i),
        });
      } else {
        prev.lastLine = i + 1;
        prev.count += 1;
      }
    }
  }

  const issues: Issue[] = [];
  for (const rule of RULES) {
    const hit = hits.get(rule.id);
    if (hit === undefined) {
      continue;
    }
    issues.push(
      mkIssue({
        rule,
        file: absPath,
        firstLine: hit.firstLine,
        lastLine: hit.lastLine,
        count: hit.count,
        snippet: hit.firstSnippet,
      }),
    );
  }

  return {
    issues,
    ormSignals: [...ormSet],
    rawSqlFileCount: rawHit ? 1 : 0,
  };
}

export function mergeDatabaseResults(parts: readonly DatabaseAnalysisResult[]): DatabaseAnalysisResult {
  const issues: Issue[] = [];
  const orm = new Set<string>();
  let rawFiles = 0;
  for (const p of parts) {
    issues.push(...p.issues);
    for (const s of p.ormSignals) {
      orm.add(s);
    }
    rawFiles += p.rawSqlFileCount;
  }
  return { issues, ormSignals: [...orm], rawSqlFileCount: rawFiles };
}

/** For engines that read whole files without AST */
export function scanDatabaseFromDisk(absPath: string): DatabaseAnalysisResult {
  try {
    const content = readFileSync(absPath, 'utf8');
    return runDatabaseEngineOnFile(absPath, content);
  } catch {
    return { issues: [], ormSignals: [], rawSqlFileCount: 0 };
  }
}
