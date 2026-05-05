import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { logger } from '../utils/logger.js';
import { CACHE_SUBDIR } from './scan-cache.js';

const FETCH_TIMEOUT_MS = 3000;

function isRulesDocument(parsed: unknown): parsed is { rules: unknown[] } {
  if (!parsed || typeof parsed !== 'object') {
    return false;
  }
  const r = parsed as { rules?: unknown };
  return Array.isArray(r.rules);
}

/** Best-effort download used by `--auto-update-db` (short timeout, non-fatal on failure). */
export async function tryAutoUpdateVulnDb(outDir: string): Promise<boolean> {
  const url = process.env.VULN_DB_URL;
  if (!url || url.length === 0) {
    logger.warn('auto-update-db: VULN_DB_URL is not set; skipping fetch');
    return false;
  }
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      logger.warn({ url }, 'auto-update-db: only https URLs allowed');
      return false;
    }
    const ac = new AbortController();
    const t = setTimeout(() => {
      ac.abort();
    }, FETCH_TIMEOUT_MS);
    const res = await fetch(u, { redirect: 'manual', signal: ac.signal });
    clearTimeout(t);
    if (!res.ok) {
      logger.warn({ status: res.status }, 'auto-update-db: fetch failed');
      return false;
    }
    const parsed: unknown = await res.json();
    if (!isRulesDocument(parsed)) {
      logger.warn('auto-update-db: response missing rules array');
      return false;
    }
    const dir = join(outDir, CACHE_SUBDIR);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'vuln-db-override.json'), `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
    const meta = {
      version: 1 as const,
      fetchedAt: new Date().toISOString(),
      source: url,
      ruleCount: parsed.rules.length,
    };
    await writeFile(join(dir, 'vuln-db-meta.json'), `${JSON.stringify(meta, null, 2)}\n`, 'utf8');
    logger.info({ ruleCount: parsed.rules.length }, 'auto-update-db: refreshed vulnerability override DB');
    return true;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    logger.warn({ err: msg }, 'auto-update-db: fetch error; continuing with cached rules');
    return false;
  }
}
