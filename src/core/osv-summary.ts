import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

interface OsvVuln {
  readonly id: string;
  readonly summary?: string;
}

interface OsvQueryResult {
  readonly vulns?: readonly OsvVuln[];
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

interface CacheFile {
  readonly version: 1;
  readonly updatedAt: string;
  readonly entries: Record<string, { readonly fetchedAt: string; readonly result: OsvQueryResult }>;
}

async function loadCache(outDir: string): Promise<CacheFile> {
  const p = join(outDir, '.cache', 'osv-query-cache.json');
  try {
    const raw = await readFile(p, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    const rec = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
    if (
      rec !== undefined &&
      rec.version === 1 &&
      typeof rec.entries === 'object' &&
      rec.entries !== null &&
      !Array.isArray(rec.entries)
    ) {
      return parsed as CacheFile;
    }
  } catch {
    /* empty */
  }
  return { version: 1, updatedAt: new Date().toISOString(), entries: {} };
}

async function saveCache(outDir: string, cache: CacheFile): Promise<void> {
  const dir = join(outDir, '.cache');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'osv-query-cache.json'), `${JSON.stringify(cache, null, 2)}\n`, 'utf8');
}

function cacheKey(name: string, version: string): string {
  return `${name}@${version}`;
}

/** Best-effort OSV vulnerability summary for npm packages in package-lock (requires network when not cached). */
export async function writeOsvSummary(cwd: string, outDir: string, offline: boolean): Promise<void> {
  if (offline) {
    await writeFile(
      join(outDir, 'osv-summary.json'),
      `${JSON.stringify({ skipped: true, reason: 'offline mode' }, null, 2)}\n`,
      'utf8',
    );
    return;
  }
  let lockRaw: string;
  try {
    lockRaw = await readFile(join(cwd, 'package-lock.json'), 'utf8');
  } catch {
    await writeFile(join(outDir, 'osv-summary.json'), `${JSON.stringify({ packages: [] })}\n`, 'utf8');
    return;
  }
  const lock = JSON.parse(lockRaw) as {
    packages?: Record<string, { name?: string; version?: string }>;
  };
  const pkgs = lock.packages ?? {};
  const direct: { name: string; version: string }[] = [];
  for (const [k, meta] of Object.entries(pkgs)) {
    if (k === '') {
      continue;
    }
    const depth = k.split('node_modules/').length - 1;
    if (depth <= 1 && meta.name !== undefined && meta.version !== undefined) {
      direct.push({ name: meta.name, version: meta.version });
    }
  }
  const capped = direct.slice(0, 40);
  let cache = await loadCache(outDir);
  const now = Date.now();
  const packages: { name: string; version: string; vulnCount: number; ids: readonly string[] }[] = [];

  for (const { name, version } of capped) {
    const key = cacheKey(name, version);
    const cached = cache.entries[key];
    let resolved: { readonly fetchedAt: string; readonly result: OsvQueryResult } | undefined;
    if (cached !== undefined && now - Date.parse(cached.fetchedAt) < CACHE_TTL_MS) {
      resolved = cached;
    } else {
      try {
        const res = await fetch('https://api.osv.dev/v1/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            package: { ecosystem: 'npm', name },
            version,
          }),
          signal: AbortSignal.timeout(12_000),
        });
        if (!res.ok) {
          continue;
        }
        const result = (await res.json()) as OsvQueryResult;
        resolved = { fetchedAt: new Date().toISOString(), result };
        cache = {
          ...cache,
          entries: { ...cache.entries, [key]: resolved },
        };
      } catch {
        continue;
      }
    }
    const vulns = resolved.result.vulns ?? [];
    packages.push({
      name,
      version,
      vulnCount: vulns.length,
      ids: vulns.map((v) => v.id),
    });
  }
  await saveCache(outDir, cache);
  await writeFile(
    join(outDir, 'osv-summary.json'),
    `${JSON.stringify({ generatedAt: new Date().toISOString(), packages }, null, 2)}\n`,
    'utf8',
  );
}
