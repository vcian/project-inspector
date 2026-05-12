import type { DependencySnapshotV1 } from '../core/dependency-snapshot.js';
import type { FileHashesFileV1 } from '../core/scan-cache.js';

/** Safe JSON.parse with a type guard and a fallback value. */
export function parseJson<T>(
  raw: string,
  guard: (v: unknown) => v is T,
  fallback: T,
): T {
  try {
    const parsed: unknown = JSON.parse(raw);
    return guard(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function isDependencySnapshotV1(v: unknown): v is DependencySnapshotV1 {
  if (!isRecord(v)) return false;
  return (
    v['version'] === 1 &&
    typeof v['packageJsonSha256'] === 'string' &&
    typeof v['lockfileKind'] === 'string' &&
    typeof v['treeFingerprint'] === 'string'
  );
}

export function isFileHashesFileV1(v: unknown): v is FileHashesFileV1 {
  if (!isRecord(v)) return false;
  return v['version'] === 1 && isRecord(v['hashes']);
}

export interface VulnDbMeta {
  readonly fetchedAt?: string;
}

export function isVulnDbMeta(v: unknown): v is VulnDbMeta {
  if (!isRecord(v)) return false;
  return v['fetchedAt'] === undefined || typeof v['fetchedAt'] === 'string';
}
