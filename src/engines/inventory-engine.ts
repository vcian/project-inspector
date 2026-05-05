import { normalize, relative } from 'node:path';

import type {
  FileKind,
  FrameworkTag,
  InventoryFile,
  InventoryScanResult,
  Issue,
  ProjectProfile,
} from '../core/types.js';
import { frameworkForFile } from '../utils/detect-project.js';

const KIND_MATCHERS: ReadonlyArray<{ readonly kind: FileKind; readonly match: (p: string) => boolean }> = [
  { kind: 'test', match: (p) => /\.(?:test|spec)\.(?:m|c)?[tj]sx?$/.test(p) || /[\\/]__tests__[\\/]/.test(p) },
  { kind: 'controller', match: (p) => p.endsWith('.controller.ts') || p.endsWith('.controller.js') },
  { kind: 'service', match: (p) => p.endsWith('.service.ts') || p.endsWith('.service.js') },
  { kind: 'repository', match: (p) => p.endsWith('.repository.ts') || p.endsWith('.repository.js') || /[\\/]repositories?[\\/]/.test(p) },
  { kind: 'guard', match: (p) => p.endsWith('.guard.ts') || p.endsWith('.guard.js') },
  { kind: 'interceptor', match: (p) => p.endsWith('.interceptor.ts') || p.endsWith('.interceptor.js') },
  { kind: 'pipe', match: (p) => p.endsWith('.pipe.ts') },
  { kind: 'dto', match: (p) => p.endsWith('.dto.ts') || /[\\/]dto[\\/]/.test(p) },
  { kind: 'entity', match: (p) => p.endsWith('.entity.ts') || /[\\/]entities?[\\/]/.test(p) },
  { kind: 'schema', match: (p) => p.endsWith('.schema.ts') || /[\\/]schemas?[\\/]/.test(p) },
  { kind: 'migration', match: (p) => /[\\/]migrations?[\\/]/.test(p) },
  { kind: 'module', match: (p) => p.endsWith('.module.ts') || p.endsWith('.module.js') },
  { kind: 'middleware', match: (p) => /[\\/]middleware[\\/]/.test(p) || p.endsWith('.middleware.ts') },
  { kind: 'route', match: (p) => p.endsWith('route.ts') || p.endsWith('route.tsx') || /[\\/]routes?[\\/]/.test(p) },
  { kind: 'page', match: (p) => /[\\/]pages?[\\/]/.test(p) || p.endsWith('page.tsx') },
  { kind: 'layout', match: (p) => p.endsWith('layout.tsx') },
  { kind: 'hook', match: (p) => /[\\/]hooks?[\\/]/.test(p) || /\\use[A-Z][a-zA-Z0-9]*\.(?:ts|tsx)$/.test(p) },
  { kind: 'store', match: (p) => /[\\/]stores?[\\/]/.test(p) || p.endsWith('.store.ts') },
  { kind: 'component', match: (p) => /[\\/]components?[\\/]/.test(p) || p.endsWith('.component.ts') || p.endsWith('.tsx') || p.endsWith('.jsx') },
  { kind: 'config', match: (p) => /[\\/]config[\\/]/.test(p) || p.endsWith('.config.ts') || p.endsWith('.config.js') },
  { kind: 'type', match: (p) => p.endsWith('.d.ts') || /[\\/]types?[\\/]/.test(p) },
  { kind: 'util', match: (p) => /[\\/]utils?[\\/]/.test(p) || /[\\/]helpers?[\\/]/.test(p) || /[\\/]lib[\\/]/.test(p) },
  { kind: 'style', match: (p) => p.endsWith('.css') || p.endsWith('.scss') || p.endsWith('.less') },
];

function classifyFile(path: string): FileKind {
  const n = path.replaceAll('\\', '/').toLowerCase();
  for (const m of KIND_MATCHERS) {
    if (m.match(n)) {
      return m.kind;
    }
  }
  return 'other';
}

function countLoc(text: string): number {
  let count = 0;
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length === 0) {
      continue;
    }
    if (inBlock) {
      if (line.includes('*/')) {
        inBlock = false;
      }
      continue;
    }
    if (line.startsWith('//')) {
      continue;
    }
    if (line.startsWith('/*')) {
      if (!line.includes('*/')) {
        inBlock = true;
      }
      continue;
    }
    count += 1;
  }
  return count;
}

function emptyKindCounts(): Record<FileKind, number> {
  return {
    controller: 0,
    service: 0,
    repository: 0,
    route: 0,
    middleware: 0,
    component: 0,
    page: 0,
    layout: 0,
    hook: 0,
    store: 0,
    module: 0,
    guard: 0,
    interceptor: 0,
    pipe: 0,
    dto: 0,
    entity: 0,
    schema: 0,
    config: 0,
    migration: 0,
    test: 0,
    util: 0,
    type: 0,
    style: 0,
    other: 0,
  };
}

export interface InventoryEngineOptions {
  readonly profile: ProjectProfile;
  readonly files: readonly string[];
  readonly contents: ReadonlyMap<string, string>;
  readonly sizes?: ReadonlyMap<string, number>;
}

export function runInventoryEngine(cwd: string, opts: InventoryEngineOptions): InventoryScanResult {
  const files: InventoryFile[] = [];
  const kindCounts = emptyKindCounts();
  let totalLoc = 0;
  const issues: Issue[] = [];

  for (const abs of opts.files) {
    const norm = normalize(abs);
    const text = opts.contents.get(norm) ?? '';
    const loc = countLoc(text);
    const bytes = opts.sizes?.get(norm) ?? Buffer.byteLength(text, 'utf8');
    const kind = classifyFile(abs);
    const fw: FrameworkTag = frameworkForFile(abs, opts.profile);
    kindCounts[kind] += 1;
    totalLoc += loc;
    files.push({
      path: abs,
      relPath: relative(cwd, abs).replaceAll('\\', '/'),
      kind,
      loc,
      bytes,
      framework: fw,
    });

    // Inventory-level warnings for very large files (likely god-modules).
    if (loc >= 600 && kind !== 'test') {
      issues.push({
        id: `inventory:large-file:${abs}`,
        engine: 'inventory',
        severity: loc >= 1200 ? 'HIGH' : 'MEDIUM',
        title: 'Very large source file',
        file: abs,
        line: 1,
        description: `File is ~${String(loc)} effective lines of code.`,
        impact: 'Large modules are harder to test, review, and change safely.',
        fix: 'Split into smaller cohesive units per Single Responsibility Principle.',
        category: 'quality',
        framework: fw,
        confidence: 'high',
        whyItMatters: 'Big files usually hide multiple responsibilities and attract bugs.',
      });
    }
  }

  // Framework / structure nudges (cheap, deterministic).
  if (opts.profile.primaryFramework === 'nestjs') {
    const hasDto = kindCounts.dto > 0;
    const hasController = kindCounts.controller > 0;
    if (hasController && !hasDto) {
      issues.push({
        id: 'inventory:nestjs:no-dto',
        engine: 'inventory',
        severity: 'MEDIUM',
        title: 'NestJS controllers without DTO layer',
        file: `${cwd}/package.json`,
        line: 1,
        description: 'Controllers detected but no DTO files were found.',
        impact: 'Missing validation boundary; request payloads may leak into services untyped.',
        fix: 'Add DTOs with class-validator + class-transformer; wire ValidationPipe globally.',
        category: 'architecture',
        framework: 'nestjs',
        confidence: 'high',
        whyItMatters: 'DTOs + ValidationPipe are the standard safety net for NestJS request handling.',
      });
    }
  }

  if (kindCounts.test === 0 && (kindCounts.controller + kindCounts.service + kindCounts.route) > 5) {
    issues.push({
      id: 'inventory:no-tests',
      engine: 'inventory',
      severity: 'HIGH',
      title: 'No test files detected for a non-trivial service',
      file: `${cwd}/package.json`,
      line: 1,
      description: 'Project has controllers/services/routes but zero *.test.ts / *.spec.ts files.',
      impact: 'Regressions ship unnoticed; refactors become risky.',
      fix: 'Introduce Jest/Vitest; add tests for routing, auth, and core domain.',
      category: 'test',
      confidence: 'high',
      whyItMatters: 'Tests are the cheapest safety net for continuous refactors.',
    });
  }

  return {
    issues,
    files,
    profile: opts.profile,
    kindCounts,
    totalLoc,
  };
}
