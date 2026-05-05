import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { sha256File, sha256String } from './file-hash.js';
import { discoverWorkspaceProjects } from '../utils/discover-workspace-projects.js';

const REPORT_CACHE_SUBDIR = '.cache';

export interface DependencySnapshotV1 {
  readonly version: 1;
  readonly packageJsonSha256: string;
  readonly lockfileKind: 'npm' | 'pnpm' | 'yarn' | 'none';
  readonly lockfileRelPath: string | null;
  readonly lockfileSha256: string | null;
  /** Sorted direct dependency names + ranges for drift detection. */
  readonly treeFingerprint: string;
  /** Fingerprint of optional vuln override + meta under report `.cache/` (forces dep re-scan when rules refresh). */
  readonly vulnDbFingerprint?: string | null;
}

function detectLockfileRel(cwd: string): { kind: DependencySnapshotV1['lockfileKind']; rel: string | null } {
  if (existsSync(join(cwd, 'package-lock.json'))) {
    return { kind: 'npm', rel: 'package-lock.json' };
  }
  if (existsSync(join(cwd, 'pnpm-lock.yaml'))) {
    return { kind: 'pnpm', rel: 'pnpm-lock.yaml' };
  }
  if (existsSync(join(cwd, 'yarn.lock'))) {
    return { kind: 'yarn', rel: 'yarn.lock' };
  }
  return { kind: 'none', rel: null };
}

async function vulnDbFingerprintForReport(outDir: string | undefined): Promise<string | null> {
  if (!outDir) {
    return null;
  }
  const base = join(resolve(outDir), REPORT_CACHE_SUBDIR);
  const parts: string[] = [];
  const override = join(base, 'vuln-db-override.json');
  const meta = join(base, 'vuln-db-meta.json');
  if (existsSync(override)) {
    try {
      parts.push(await readFile(override, 'utf8'));
    } catch {
      /* ignore */
    }
  }
  if (existsSync(meta)) {
    try {
      parts.push(await readFile(meta, 'utf8'));
    } catch {
      /* ignore */
    }
  }
  if (parts.length === 0) {
    return null;
  }
  return sha256String(parts.join('\n---\n'));
}

export async function buildDependencySnapshot(cwd: string, reportOutDir?: string): Promise<DependencySnapshotV1 | null> {
  const root = resolve(cwd);
  const projects = await discoverWorkspaceProjects(root);
  if (projects.length === 0) {
    return null;
  }
  const manifestHashes = await Promise.all(
    projects.map(async (project) => `${project.relPath}:${await sha256File(project.packageJsonPath)}`),
  );
  const packageJsonSha256 = sha256String(manifestHashes.sort().join('\n'));
  const { kind, rel } = detectLockfileRel(root);
  let lockfileSha256: string | null = null;
  if (rel) {
    const lockAbs = join(root, rel);
    if (existsSync(lockAbs)) {
      lockfileSha256 = await sha256File(lockAbs);
    }
  }
  let treeFingerprint = '';
  try {
    const entries: string[] = [];
    for (const project of projects) {
      const raw = await readFile(project.packageJsonPath, 'utf8');
      const pkg = JSON.parse(raw) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        peerDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
      };
      const direct = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies,
      };
      for (const [name, range] of Object.entries(direct)) {
        entries.push(`${project.relPath}:${name}@${range}`);
      }
    }
    treeFingerprint = sha256String(entries.sort().join('\n'));
  } catch {
    treeFingerprint = sha256String('');
  }

  const vulnDbFingerprint = await vulnDbFingerprintForReport(reportOutDir);

  return {
    version: 1,
    packageJsonSha256,
    lockfileKind: kind,
    lockfileRelPath: rel,
    lockfileSha256,
    treeFingerprint,
    vulnDbFingerprint,
  };
}

export function snapshotsEqual(a: DependencySnapshotV1, b: DependencySnapshotV1): boolean {
  return (
    a.packageJsonSha256 === b.packageJsonSha256 &&
    a.lockfileSha256 === b.lockfileSha256 &&
    a.treeFingerprint === b.treeFingerprint &&
    a.lockfileKind === b.lockfileKind &&
    (a.vulnDbFingerprint ?? null) === (b.vulnDbFingerprint ?? null)
  );
}
