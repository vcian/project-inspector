import { readFile } from 'node:fs/promises';
import { normalize } from 'node:path';

import type { ArchitectureScanResult, AstScanResult, Issue } from '../core/types.js';
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
    id,
    engine: 'architecture',
    severity,
    title,
    file,
    line,
    description,
    impact,
    fix,
    category: 'architecture',
    confidence: 'medium',
    ...extra,
  };
}

function isClientishPath(p: string): boolean {
  const n = p.replaceAll('\\', '/').toLowerCase();
  return (
    n.includes('/components/') ||
    n.includes('/pages/') ||
    n.includes('/app/') ||
    n.includes('/src/app/') ||
    n.includes('/src/components/')
  );
}

function isServerishPath(p: string): boolean {
  const n = p.replaceAll('\\', '/').toLowerCase();
  return (
    n.includes('/server/') ||
    n.includes('/api/') ||
    n.includes('/controllers/') ||
    n.includes('/services/') ||
    n.includes('/modules/') ||
    n.endsWith('.controller.ts') ||
    n.endsWith('.service.ts') ||
    n.endsWith('.module.ts')
  );
}

async function scanBoundary(
  path: string,
  getSourceText?: (normalizedAbs: string) => string | undefined,
): Promise<Issue[]> {
  const issues: Issue[] = [];
  const clientish = isClientishPath(path);
  const serverish = isServerishPath(path);
  if (!clientish && !serverish) {
    return issues;
  }
  let text: string | undefined = getSourceText?.(normalize(path));
  if (text === undefined) {
    try {
      text = await readFile(path, 'utf8');
    } catch {
      return issues;
    }
  }

  if (clientish) {
    if (/\bfrom\s+['"]fs['"]|\bfrom\s+['"]node:fs['"]|\brequire\s*\(\s*['"]fs['"]/.test(text)) {
      issues.push(
        mkIssue(
          `architecture:ui-node-fs:${path}`,
          'HIGH',
          'UI-boundary file imports Node core fs',
          path,
          1,
          'Filesystem access in UI-oriented modules risks bundling into client or violating layering.',
          'Broken edge builds, accidental secret paths, SSR/client boundary bugs.',
          'Move IO to server-only modules (Route Handlers, server actions, backend services).',
          { whyItMatters: 'Bundling `fs` into a browser build will break at runtime.' },
        ),
      );
    }
    if (/\bfrom\s+['"]child_process['"]|\bfrom\s+['"]node:child_process['"]/.test(text)) {
      issues.push(
        mkIssue(
          `architecture:ui-child-process:${path}`,
          'CRITICAL',
          'UI-boundary file imports child_process',
          path,
          1,
          'Process execution must not live in client-shipped graphs.',
          'Severe security and packaging failures if executed in browser bundles.',
          'Isolate process spawning under explicit server-only modules.',
          { whyItMatters: 'A client bundle running child_process is a severe leak of server primitives.' },
        ),
      );
    }
    if (/\bprocess\.env\.[A-Z0-9_]+/.test(text) && !/['"]use server['"]/.test(text)) {
      issues.push(
        mkIssue(
          `architecture:ui-process-env:${path}`,
          'MEDIUM',
          'UI-boundary file reads process.env directly',
          path,
          1,
          'Reading process.env in client-oriented modules leaks config or breaks SSR.',
          'Accidental secret exposure in hydrated output or bundles.',
          'Read env in a server module and pass the value through a typed config.',
          { whyItMatters: 'Next.js public env must be `NEXT_PUBLIC_*` — others leak or throw.' },
        ),
      );
    }
  }

  if (serverish) {
    // Heavy logic mixed with controllers: controllers that declare SQL/ORM calls inline.
    if (/\bcontroller\b/i.test(path) && /(\bquery\s*\(|\bprisma\.|\bmongoose\.)/i.test(text)) {
      issues.push(
        mkIssue(
          `architecture:controller-db:${path}`,
          'MEDIUM',
          'Controller performs DB work directly',
          path,
          1,
          'Controllers should orchestrate; persistence belongs in services/repositories.',
          'Tight coupling, hard to test, duplicated query logic across routes.',
          'Introduce a service/repository layer and inject it into the controller.',
          { whyItMatters: 'Controllers with DB logic make unit testing and swapping databases painful.' },
        ),
      );
    }
  }
  return issues;
}

function hubDetection(ast: AstScanResult): Issue[] {
  const issues: Issue[] = [];
  const outDegree = new Map<string, number>();
  const inDegree = new Map<string, number>();
  for (const e of ast.importGraph) {
    outDegree.set(e.from, (outDegree.get(e.from) ?? 0) + 1);
    inDegree.set(e.to, (inDegree.get(e.to) ?? 0) + 1);
  }
  for (const [file, n] of outDegree) {
    if (n >= 25) {
      issues.push(
        mkIssue(
          `architecture:hub-out:${file}`,
          'MEDIUM',
          'Highly connected module (out-degree hub)',
          file,
          1,
          `This file has ${String(n)} outgoing relative imports.`,
          'Change amplification: editing this file touches many call sites.',
          'Split responsibilities; introduce facades and domain boundaries.',
          { whyItMatters: 'Wide fan-out usually means the file does too many things.' },
        ),
      );
    }
  }
  for (const [file, n] of inDegree) {
    if (n >= 40) {
      issues.push(
        mkIssue(
          `architecture:hub-in:${file}`,
          'MEDIUM',
          'Highly depended-on module (in-degree hub)',
          file,
          1,
          `This file is imported by ${String(n)} other relative modules.`,
          'Central risk: any regression here propagates across the codebase.',
          'Consider stable interfaces and layered boundaries to control blast radius.',
          { whyItMatters: 'Shared utility hubs make changes risky; add tests and avoid leaky exports.' },
        ),
      );
    }
  }
  return issues;
}

export async function runArchitectureEngine(
  cwd: string,
  ast: AstScanResult,
  concurrency: number,
  options?: FileFilterOptions,
): Promise<ArchitectureScanResult> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  const normalized = options?.fileFilter
    ? normalizedAll.filter((f) => options.fileFilter?.has(f))
    : normalizedAll;
  const targets = normalized.length > 0 ? normalized : normalizedAll;
  const getText = options?.getSourceText;
  const boundary = await runPool(targets, concurrency, (f) => scanBoundary(f, getText));
  return { issues: [...hubDetection(ast), ...boundary.flat()] };
}
