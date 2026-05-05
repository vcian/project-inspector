import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import type { Issue, MigrationScanResult } from '../core/types.js';
import { discoverWorkspaceProjects } from '../utils/discover-workspace-projects.js';

function mkIssue(
  engine: string,
  severity: Issue['severity'],
  title: string,
  file: string,
  line: number,
  description: string,
  impact: string,
  fix: string,
): Issue {
  const id = `${engine}:${file}:${String(line)}:${title}`.replaceAll(/\s+/g, '_');
  return { id, engine, severity, title, file, line, description, impact, fix };
}

function firstSemverMajor(range: string): number | null {
  const m = range.replace(/^[\^~>=<]+\s*/, '').match(/^(\d+)/);
  return m?.[1] ? Number(m[1]) : null;
}

function readManifest(path: string): {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
} | null {
  if (!existsSync(path)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
  } catch {
    return null;
  }
}

export async function runMigrationEngine(cwd: string): Promise<MigrationScanResult> {
  const root = resolve(cwd);
  const pkgPath = join(root, 'package.json');
  const issues: Issue[] = [];
  const projects = await discoverWorkspaceProjects(root);
  if (!existsSync(pkgPath) && projects.length === 0) {
    return { issues };
  }
  for (const project of projects) {
    const pkg = readManifest(project.packageJsonPath);
    if (pkg === null) {
      continue;
    }
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    const manifestPath = project.packageJsonPath;

    const nextRange = all.next;
    if (nextRange) {
      const maj = firstSemverMajor(nextRange);
      if (maj !== null && maj < 14) {
        issues.push(
          mkIssue(
            'migration',
            'MEDIUM',
            'Next.js version is behind current LTS line',
            manifestPath,
            1,
            `Detected Next.js range "${nextRange}" (major ${String(maj)}).`,
            'Missing security patches, performance improvements, and App Router maturity.',
            'Plan upgrade to Next.js 14+ with official migration guide and incremental adoption.',
          ),
        );
      }
      if (maj !== null && maj >= 14 && maj < 15) {
        issues.push(
          mkIssue(
            'migration',
            'LOW',
            'Consider Next.js 15+ for latest breaking-change guidance',
            manifestPath,
            1,
            `Current range "${nextRange}" (major ${String(maj)}).`,
            'Framework-specific deprecations (e.g. runtime config) evolve quickly.',
            'Read https://nextjs.org/docs/app/building-your-application/upgrading and schedule a staged upgrade.',
          ),
        );
      }
    }

    const reactRange = all.react;
    if (reactRange) {
      const maj = firstSemverMajor(reactRange);
      if (maj !== null && maj < 18) {
        issues.push(
          mkIssue(
            'migration',
            'MEDIUM',
            'React version predates React 18 defaults',
            manifestPath,
            1,
            `Detected React range "${reactRange}".`,
            'Concurrency features and ecosystem alignment gaps.',
            'Upgrade to React 18+ and validate concurrent rendering behavior.',
          ),
        );
      }
      if (maj !== null && maj >= 18 && maj < 19) {
        issues.push(
          mkIssue(
            'migration',
            'LOW',
            'React 19 introduces compiler and ref cleanups - plan compatibility',
            manifestPath,
            1,
            `Detected React range "${reactRange}".`,
            'Third-party libraries may lag React 19 typings or deprecated APIs.',
            'Follow https://react.dev/blog for breaking changes; run RC builds in CI before bumping major.',
          ),
        );
      }
    }

    const expressRange = all.express;
    if (expressRange) {
      const maj = firstSemverMajor(expressRange);
      if (maj !== null && maj < 4) {
        issues.push(
          mkIssue(
            'migration',
            'HIGH',
            'Express major version is outdated',
            manifestPath,
            1,
            `Detected express range "${expressRange}".`,
            'Security and middleware ecosystem drift.',
            'Upgrade to Express 4.x latest minor and review security advisories.',
          ),
        );
      }
    }

    const nestRange = all['@nestjs/core'] ?? all['@nestjs/common'];
    if (nestRange) {
      const maj = firstSemverMajor(nestRange);
      if (maj !== null && maj < 10) {
        issues.push(
          mkIssue(
            'migration',
            'MEDIUM',
            'NestJS major is behind current supported line',
            manifestPath,
            1,
            `Detected @nestjs range "${nestRange}" (major ${String(maj)}).`,
            'Security patches, DI lifecycle fixes, and Fastify/Express adapter changes accrue in newer majors.',
            'Follow https://docs.nestjs.com/migration-guide and upgrade incrementally with e2e coverage.',
          ),
        );
      }
    }

    const fastifyRange = all.fastify;
    if (fastifyRange) {
      const maj = firstSemverMajor(fastifyRange);
      if (maj !== null && maj < 4) {
        issues.push(
          mkIssue(
            'migration',
            'MEDIUM',
            'Fastify major may be outdated',
            manifestPath,
            1,
            `Detected fastify range "${fastifyRange}".`,
            'Plugin compatibility and performance improvements in newer majors.',
            'Review Fastify upgrade guide for v4+.',
          ),
        );
      }
      if (maj !== null && maj >= 4 && maj < 5) {
        issues.push(
          mkIssue(
            'migration',
            'LOW',
            'Evaluate Fastify v5 migration (HTTP/2 defaults, logger changes)',
            manifestPath,
            1,
            `Detected fastify range "${fastifyRange}".`,
            'Breaking plugin API shifts between majors.',
            'See Fastify v5 migration notes and run integration tests for hooks and serializers.',
          ),
        );
      }
    }

    const mongooseRange = all.mongoose;
    if (mongooseRange) {
      const maj = firstSemverMajor(mongooseRange);
      if (maj !== null && maj < 8) {
        issues.push(
          mkIssue(
            'migration',
            'MEDIUM',
            'Mongoose major may miss modern defaults (strictQuery, buffering)',
            manifestPath,
            1,
            `Detected mongoose range "${mongooseRange}".`,
            'ODM behavior changes across majors affect schema validation and middleware.',
            'Upgrade with official migration checklist; enable strictQuery and audit deprecations.',
          ),
        );
      }
    }

    const directAll = all as Record<string, string>;
    const typesNode = directAll['@types/node'];
    if (typesNode) {
      const maj = firstSemverMajor(typesNode);
      if (maj !== null && maj < 18) {
        issues.push(
          mkIssue(
            'migration',
            'LOW',
            '@types/node predates Node 18 typings',
            manifestPath,
            1,
            `Range "${typesNode}".`,
            'Incorrect typings for fetch, structuredClone, and moduleResolution bundler.',
            'Align @types/node major with your runtime LTS (Node 20+ recommended).',
          ),
        );
      }
    }
  }

  return { issues };
}
