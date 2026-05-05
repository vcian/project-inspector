import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { KNOWN_LATEST_MAJOR } from '../data/known-package-majors.js';
import type { Issue, OutdatedDepsScanResult } from '../core/types.js';
import { discoverWorkspaceProjects } from '../utils/discover-workspace-projects.js';
import { declaredMajorFromRange, majorGap } from './semver-lite.js';

const DEPRECATED_NAMES: ReadonlySet<string> = new Set([
  'request',
  'inflight',
  'rimraf',
  'glob',
  'moment',
  '@types/minimatch',
]);

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

interface PackageJson {
  readonly dependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
  readonly peerDependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
}

function readPackageJson(path: string): PackageJson | null {
  if (!existsSync(path)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PackageJson;
  } catch {
    return null;
  }
}

export async function runOutdatedEngine(cwd: string): Promise<OutdatedDepsScanResult> {
  const root = resolve(cwd);
  const pkgPath = join(root, 'package.json');
  const issues: Issue[] = [];
  const projects = await discoverWorkspaceProjects(root);
  if (!existsSync(pkgPath) && projects.length === 0) {
    return { issues, outdatedDirectCount: 0, majorGapCount: 0, deprecatedCount: 0 };
  }
  const manifests = projects
    .map((project) => ({
      project,
      pkg: readPackageJson(project.packageJsonPath),
    }))
    .filter((entry): entry is { project: (typeof projects)[number]; pkg: PackageJson } => entry.pkg !== null);
  let majorGapCount = 0;
  let deprecatedCount = 0;
  let outdatedDirectCount = 0;

  for (const manifest of manifests) {
    const direct = {
      ...manifest.pkg.dependencies,
      ...manifest.pkg.devDependencies,
      ...manifest.pkg.peerDependencies,
      ...manifest.pkg.optionalDependencies,
    };
    const entries = Object.entries(direct);
    outdatedDirectCount += entries.length;
    for (const [name, range] of entries) {
      if (DEPRECATED_NAMES.has(name)) {
        deprecatedCount += 1;
        issues.push(
          mkIssue(
            'outdated',
            'HIGH',
            `Deprecated or legacy package: ${name}`,
            manifest.project.packageJsonPath,
            1,
            `Declared range "${range}". This package is widely considered deprecated or high-risk to keep long-term.`,
            'Supply-chain and security patch gaps.',
            'Plan migration to a maintained replacement and remove from lockfile.',
          ),
        );
        continue;
      }

      const known = KNOWN_LATEST_MAJOR[name];
      if (known === undefined || known <= 0) {
        continue;
      }
      const declared = declaredMajorFromRange(range);
      const gap = majorGap(declared, known);
      if (gap === null || gap <= 0) {
        continue;
      }
      majorGapCount += 1;
      const severity: Issue['severity'] = gap >= 2 ? 'HIGH' : 'MEDIUM';
      issues.push(
        mkIssue(
          'outdated',
          severity,
          `Possible major drift: ${name}`,
          manifest.project.packageJsonPath,
          1,
          `Declared range "${range}" (parsed major ${declared === null ? 'unknown' : String(declared)}). Offline catalog suggests current ecosystem line around major **${String(known)}** (gap ${String(gap)}).`,
          'Missing security fixes, breaking API drift when you eventually upgrade.',
          `Review release notes for ${name}; upgrade across majors with tests, or pin intentionally with documented risk.`,
        ),
      );
    }
  }

  return {
    issues,
    outdatedDirectCount,
    majorGapCount,
    deprecatedCount,
  };
}
