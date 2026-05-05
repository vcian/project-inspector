import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { DependencySnapshotV1 } from './dependency-snapshot.js';
import type { EnvHashes } from './env-snapshot.js';
import type { ScanResult } from './types.js';

export const CACHE_SUBDIR = '.cache';
export const FILE_HASHES_JSON = 'file-hashes.json';
export const DEPENDENCY_SNAPSHOT_JSON = 'dependency-snapshot.json';
export const SCAN_META_JSON = 'scan-meta.json';
export const MERGED_SCAN_JSON = 'merged-scan.json';
export const ENV_SNAPSHOT_JSON = 'env-snapshot.json';
export const FILE_CONTENTS_JSON = 'file-contents-v1.json';
export const SCAN_INTERRUPTED_JSON = 'scan-interrupted.json';

export interface FileHashesFileV1 {
  readonly version: 1;
  readonly hashes: Record<string, string>;
}

export interface ScanMetaV1 {
  readonly version: 1;
  readonly lastScanAt: string;
  readonly lastScanDurationMs?: number;
  readonly cacheHit?: boolean;
}

export function cacheDirFor(outDir: string): string {
  return join(outDir, CACHE_SUBDIR);
}

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    const raw = await readFile(path, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    return undefined;
  }
}

export async function loadFileHashes(outDir: string): Promise<FileHashesFileV1 | undefined> {
  return readJson<FileHashesFileV1>(join(cacheDirFor(outDir), FILE_HASHES_JSON));
}

export async function saveFileHashes(outDir: string, hashes: Record<string, string>): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  const body: FileHashesFileV1 = { version: 1, hashes };
  await writeFile(join(dir, FILE_HASHES_JSON), `${JSON.stringify(body, null, 2)}\n`, 'utf8');
}

export async function loadDependencySnapshot(outDir: string): Promise<DependencySnapshotV1 | undefined> {
  return readJson<DependencySnapshotV1>(join(cacheDirFor(outDir), DEPENDENCY_SNAPSHOT_JSON));
}

export async function saveDependencySnapshot(outDir: string, snap: DependencySnapshotV1): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, DEPENDENCY_SNAPSHOT_JSON), `${JSON.stringify(snap, null, 2)}\n`, 'utf8');
}

export async function loadMergedScan(outDir: string): Promise<ScanResult | undefined> {
  const data = await readJson<ScanResult>(join(cacheDirFor(outDir), MERGED_SCAN_JSON));
  return data;
}

export async function saveMergedScan(outDir: string, result: ScanResult): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, MERGED_SCAN_JSON), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
}

export async function saveScanMeta(outDir: string, meta: ScanMetaV1): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, SCAN_META_JSON), `${JSON.stringify(meta, null, 2)}\n`, 'utf8');
}

interface EnvSnapshotFileV1 {
  readonly version: 1;
  readonly files: EnvHashes;
}

export async function loadEnvSnapshot(outDir: string): Promise<EnvHashes | undefined> {
  const data = await readJson<EnvSnapshotFileV1>(join(cacheDirFor(outDir), ENV_SNAPSHOT_JSON));
  return data?.version === 1 ? data.files : undefined;
}

export async function saveEnvSnapshot(outDir: string, env: EnvHashes): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  const body: EnvSnapshotFileV1 = { version: 1, files: env };
  await writeFile(join(dir, ENV_SNAPSHOT_JSON), `${JSON.stringify(body, null, 2)}\n`, 'utf8');
}

interface FileContentsFileV1 {
  readonly version: 1;
  readonly entries: Record<string, string>;
}

const MAX_FILE_CONTENTS_BYTES = 3_500_000;

export async function loadFileContentsBundle(outDir: string): Promise<Record<string, string> | undefined> {
  const data = await readJson<FileContentsFileV1>(join(cacheDirFor(outDir), FILE_CONTENTS_JSON));
  return data?.version === 1 ? data.entries : undefined;
}

export async function saveFileContentsBundle(outDir: string, entries: Record<string, string>): Promise<void> {
  const raw = JSON.stringify({ version: 1 as const, entries });
  if (raw.length > MAX_FILE_CONTENTS_BYTES) {
    return;
  }
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, FILE_CONTENTS_JSON), `${raw}\n`, 'utf8');
}

export async function loadScanInterrupted(outDir: string): Promise<boolean> {
  const data = await readJson<{ readonly version?: number; readonly incomplete?: boolean }>(
    join(cacheDirFor(outDir), SCAN_INTERRUPTED_JSON),
  );
  return data?.version === 1 && data.incomplete === true;
}

export async function writeScanInterruptedMarker(outDir: string): Promise<void> {
  const dir = cacheDirFor(outDir);
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, SCAN_INTERRUPTED_JSON),
    `${JSON.stringify({ version: 1, incomplete: true, at: new Date().toISOString() }, null, 2)}\n`,
    'utf8',
  );
}

export async function clearScanInterruptedMarker(outDir: string): Promise<void> {
  try {
    await unlink(join(cacheDirFor(outDir), SCAN_INTERRUPTED_JSON));
  } catch {
    /* ignore */
  }
}
