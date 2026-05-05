import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { CACHE_SUBDIR } from './scan-cache.js';

function isRulesDocument(parsed: unknown): parsed is { rules: unknown[]; version?: unknown; updated?: unknown } {
  if (!parsed || typeof parsed !== 'object') {
    return false;
  }
  const r = parsed as { rules?: unknown };
  return Array.isArray(r.rules);
}

/** Optional online refresh: set `VULN_DB_URL` to an HTTPS JSON document `{ "rules": [...] }`. */
export async function downloadVulnDbOverride(outDir: string): Promise<{ ok: boolean; message: string }> {
  const url = process.env.VULN_DB_URL;
  if (!url || url.length === 0) {
    return {
      ok: false,
      message: 'Set VULN_DB_URL to an HTTPS JSON endpoint returning { "rules": LocalVulnRule[] }.',
    };
  }
  let parsed: unknown;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') {
      return { ok: false, message: 'Only https: URLs are allowed for VULN_DB_URL.' };
    }
    const res = await fetch(u, { redirect: 'manual' });
    if (!res.ok) {
      return { ok: false, message: `Fetch failed: HTTP ${String(res.status)}` };
    }
    parsed = await res.json();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, message: `Fetch error: ${msg}` };
  }

  if (!isRulesDocument(parsed)) {
    return {
      ok: false,
      message: 'Downloaded JSON must be an object with a `rules` array (optional `version`, `updated` fields).',
    };
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

  return { ok: true, message: `Wrote ${join(dir, 'vuln-db-override.json')} and vuln-db-meta.json` };
}
