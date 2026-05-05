import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
import { existsSync, readFileSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { CACHE_SUBDIR } from '../core/scan-cache.js';
import type { DependencyScanResult, Issue } from '../core/types.js';
import { LOCAL_VULN_RULES, mergeVulnRules, type LocalVulnRule } from '../data/local-vuln-db.js';
import { discoverWorkspaceProjects } from '../utils/discover-workspace-projects.js';
import { declaredMajorFromRange } from './semver-lite.js';

const DEPRECATED_PACKAGES: ReadonlySet<string> = new Set([
  'request',
  '@types/minimatch',
  'inflight',
  'rimraf',
  'glob',
  'eslint',
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
  readonly name?: string;
  readonly version?: string;
  readonly dependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
  readonly peerDependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
}

function readPackageJson(path: string): PackageJson | null {
  const p = path;
  if (!existsSync(p)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as PackageJson;
  } catch {
    return null;
  }
}

function detectLockfile(cwd: string): DependencyScanResult['lockfileKind'] {
  if (existsSync(join(cwd, 'package-lock.json'))) {
    return 'npm';
  }
  if (existsSync(join(cwd, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (existsSync(join(cwd, 'yarn.lock'))) {
    return 'yarn';
  }
  return 'none';
}

async function loadVulnOverrides(outDir: string | undefined): Promise<readonly LocalVulnRule[]> {
  if (!outDir) {
    return [];
  }
  try {
    const raw = await readFile(join(outDir, CACHE_SUBDIR, 'vuln-db-override.json'), 'utf8');
    const parsed = JSON.parse(raw) as { rules?: LocalVulnRule[] };
    return parsed.rules ?? [];
  } catch {
    return [];
  }
}

async function runNpmAudit(cwd: string): Promise<DependencyScanResult['auditSummary'] | undefined> {
  try {
    const { stdout } = await execFileAsync('npm', ['audit', '--json'], {
      cwd,
      maxBuffer: 50_000_000,
      windowsHide: true,
      timeout: 120_000,
    });
    const data = JSON.parse(stdout) as {
      metadata?: { vulnerabilities?: Record<string, number> };
    };
    const v = data.metadata?.vulnerabilities;
    if (!v) {
      return undefined;
    }
    return {
      critical: v.critical ?? 0,
      high: v.high ?? 0,
      moderate: v.moderate ?? 0,
      low: v.low ?? 0,
      info: v.info ?? 0,
    };
  } catch {
    return undefined;
  }
}

export interface DependencyEngineOptions {
  /** When set, merge `project-report/.cache/vuln-db-override.json` rules (from `update-vuln-db`). */
  readonly reportOutDir?: string;
  /** When true, skip vulnerability DB staleness hints. */
  readonly offline?: boolean;
}

const MS_PER_DAY = 86_400_000;

function warnVulnDbStaleness(reportOutDir: string | undefined, offline: boolean | undefined): void {
  if (offline === true || !reportOutDir) {
    return;
  }
  const cacheDir = join(resolve(reportOutDir), CACHE_SUBDIR);
  const metaPath = join(cacheDir, 'vuln-db-meta.json');
  const overridePath = join(cacheDir, 'vuln-db-override.json');
  let fetchedMs: number | undefined;
  try {
    const raw = readFileSync(metaPath, 'utf8');
    const parsed = JSON.parse(raw) as { fetchedAt?: string };
    if (typeof parsed.fetchedAt === 'string') {
      const t = Date.parse(parsed.fetchedAt);
      if (!Number.isNaN(t)) {
        fetchedMs = t;
      }
    }
  } catch {
    /* no meta */
  }
  if (fetchedMs === undefined && existsSync(overridePath)) {
    try {
      fetchedMs = statSync(overridePath).mtimeMs;
    } catch {
      fetchedMs = undefined;
    }
  }
  if (fetchedMs === undefined) {
    return;
  }
  const ageDays = Math.floor((Date.now() - fetchedMs) / MS_PER_DAY);
  if (ageDays < 7) {
    return;
  }
  const yellow = '\x1b[33m';
  const reset = '\x1b[0m';
  process.stderr.write(
    `${yellow}⚠ Vulnerability DB is ${String(ageDays)} days old. Run \`project-inspector update-vuln-db\` or use --auto-update-db to refresh automatically.${reset}\n`,
  );
}

export async function runDependencyEngine(
  cwd: string,
  online: boolean,
  options?: DependencyEngineOptions,
): Promise<DependencyScanResult> {
  const root = resolve(cwd);
  const issues: Issue[] = [];
  const pkgPath = join(root, 'package.json');
  warnVulnDbStaleness(options?.reportOutDir, options?.offline);
  const pkg = readPackageJson(pkgPath);
  const lockfileKind = detectLockfile(root);
  const workspaceProjects = await discoverWorkspaceProjects(root);
  const manifests = workspaceProjects.length > 0 ? workspaceProjects : [];
  const manifestPkgs = manifests
    .map((project) => ({
      project,
      pkg: readPackageJson(project.packageJsonPath),
    }))
    .filter((entry): entry is { project: (typeof manifests)[number]; pkg: PackageJson } => entry.pkg !== null);

  if (!pkg && manifestPkgs.length === 0) {
    issues.push(
      mkIssue(
        'dependency',
        'HIGH',
        'Missing package.json',
        pkgPath,
        1,
        'No package.json found at project root.',
        'Dependency and supply-chain posture cannot be assessed.',
        'Add a valid package.json for the workspace root.',
      ),
    );
    return { issues, lockfileKind: 'none', directDependencyCount: 0 };
  }
  const directDependencyCount = manifestPkgs.reduce((sum, entry) => {
    const direct = {
      ...entry.pkg.dependencies,
      ...entry.pkg.devDependencies,
      ...entry.pkg.peerDependencies,
      ...entry.pkg.optionalDependencies,
    };
    return sum + Object.keys(direct).length;
  }, 0);

  if (lockfileKind === 'none') {
    issues.push(
      mkIssue(
        'dependency',
        'MEDIUM',
        'No lockfile detected',
        pkgPath,
        1,
        'Neither package-lock.json, pnpm-lock.yaml, nor yarn.lock was found.',
        'Non-reproducible installs and harder incident response for supply-chain issues.',
        'Commit a lockfile (npm install, pnpm install, or yarn) and use frozen installs in CI.',
      ),
    );
  }

  const vulnRules = mergeVulnRules(LOCAL_VULN_RULES, await loadVulnOverrides(options?.reportOutDir));
  const emittedLocalVuln = new Set<string>();

  for (const entry of manifestPkgs) {
    const direct = {
      ...entry.pkg.dependencies,
      ...entry.pkg.devDependencies,
      ...entry.pkg.peerDependencies,
      ...entry.pkg.optionalDependencies,
    };
    for (const [name, range] of Object.entries(direct)) {
      if (DEPRECATED_PACKAGES.has(name)) {
        issues.push(
          mkIssue(
            'dependency',
            'MEDIUM',
            `Potentially deprecated dependency: ${name}`,
            entry.project.packageJsonPath,
            1,
            `Declared range: ${range}. "${name}" is flagged as legacy/unmaintained in many ecosystems.`,
            'Unpatched vulnerabilities and ecosystem drift.',
            'Migrate to maintained alternatives and remove unused packages.',
          ),
        );
      }

      for (const rule of vulnRules) {
        if (!rule.packageNames.includes(name)) {
          continue;
        }
        if (rule.matchIfDeclaredMajorAtMost !== undefined) {
          const declaredMajor = declaredMajorFromRange(range);
          if (declaredMajor === null || declaredMajor > rule.matchIfDeclaredMajorAtMost) {
            continue;
          }
        }
        const dedupeKey = `${rule.id}:${name}:${entry.project.relPath}`;
        if (emittedLocalVuln.has(dedupeKey)) {
          continue;
        }
        emittedLocalVuln.add(dedupeKey);
        issues.push(
          mkIssue(
            'dependency',
            rule.severity,
            `${rule.title} (${name})`,
            entry.project.packageJsonPath,
            1,
            `${rule.description} Declared range: ${range}.`,
            rule.impact,
            rule.fix,
          ),
        );
      }
    }
  }

  let auditSummary: DependencyScanResult['auditSummary'];
  if (online) {
    auditSummary = await runNpmAudit(root);
    if (auditSummary) {
      if (auditSummary.critical > 0) {
        issues.push(
          mkIssue(
            'dependency',
            'CRITICAL',
            `npm audit reports ${String(auditSummary.critical)} critical vulnerabilities`,
            pkgPath,
            1,
            'Aggregated from `npm audit --json` (requires network).',
            'Exploitable dependency chain in production builds.',
            'Run npm audit fix, upgrade affected packages, and verify with tests.',
          ),
        );
      }
      if (auditSummary.high > 0) {
        issues.push(
          mkIssue(
            'dependency',
            'HIGH',
            `npm audit reports ${String(auditSummary.high)} high vulnerabilities`,
            pkgPath,
            1,
            'Aggregated from `npm audit --json` (requires network).',
            'Serious security exposure via dependencies.',
            'Upgrade vulnerable packages; review transitive paths in the audit output.',
          ),
        );
      }
    } else {
      issues.push(
        mkIssue(
          'dependency',
          'LOW',
          'npm audit did not return vulnerability metadata',
          pkgPath,
          1,
          '`npm audit --json` failed or returned an unexpected shape (offline registry, npm error, or no audit data).',
          'CI may miss known CVE signals when online audit is unavailable.',
          'Ensure npm is installed, registry is reachable, and retry with network access.',
        ),
      );
    }
  }

  if (auditSummary !== undefined) {
    return { issues, lockfileKind, directDependencyCount, projectManifestCount: manifestPkgs.length, auditSummary };
  }
  return { issues, lockfileKind, directDependencyCount, projectManifestCount: manifestPkgs.length };
}
