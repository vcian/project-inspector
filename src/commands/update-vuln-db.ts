import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { LocalVulnRule } from '../data/local-vuln-db.js';
import { CACHE_SUBDIR } from '../core/scan-cache.js';
import { logger } from '../utils/logger.js';

interface VulnRulesDocument {
  readonly version: string | number;
  readonly updated: string;
  readonly rules: readonly LocalVulnRule[];
}

function isSeverity(value: unknown): value is LocalVulnRule['severity'] {
  return value === 'LOW' || value === 'MEDIUM' || value === 'HIGH' || value === 'CRITICAL';
}

function isLocalVulnRule(value: unknown): value is LocalVulnRule {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.id === 'string' &&
    Array.isArray(candidate.packageNames) &&
    candidate.packageNames.every((entry) => typeof entry === 'string') &&
    isSeverity(candidate.severity) &&
    typeof candidate.title === 'string' &&
    typeof candidate.description === 'string' &&
    typeof candidate.impact === 'string' &&
    typeof candidate.fix === 'string' &&
    (candidate.matchIfDeclaredMajorAtMost === undefined || typeof candidate.matchIfDeclaredMajorAtMost === 'number') &&
    (candidate.severityScore === undefined || typeof candidate.severityScore === 'number')
  );
}

function isRulesDocument(value: unknown): value is VulnRulesDocument {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    (typeof candidate.version === 'string' || typeof candidate.version === 'number') &&
    typeof candidate.updated === 'string' &&
    Array.isArray(candidate.rules) &&
    candidate.rules.every(isLocalVulnRule)
  );
}

async function existingOverrideExists(cacheDir: string): Promise<boolean> {
  try {
    await readFile(join(cacheDir, 'vuln-db-override.json'), 'utf8');
    return true;
  } catch {
    return false;
  }
}

export async function runUpdateVulnDbCommand(outDir: string): Promise<{ ok: boolean; message: string }> {
  const url = process.env.VULN_DB_URL;
  if (typeof url !== 'string' || url.trim().length === 0) {
    return { ok: false, message: 'VULN_DB_URL is not set.' };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return { ok: false, message: 'VULN_DB_URL is not a valid URL.' };
  }
  if (parsedUrl.protocol !== 'https:') {
    return { ok: false, message: 'VULN_DB_URL must use https://.' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, 10_000);

  const cacheDir = join(outDir, CACHE_SUBDIR);
  try {
    const response = await fetch(parsedUrl, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) {
      const keepExisting = await existingOverrideExists(cacheDir);
      const message = `Failed to download vulnerability DB: HTTP ${String(response.status)}.${keepExisting ? ' Existing DB kept.' : ''}`;
      logger.warn({ status: response.status }, 'update-vuln-db failed');
      return { ok: false, message };
    }
    const parsed: unknown = await response.json();
    if (!isRulesDocument(parsed)) {
      const keepExisting = await existingOverrideExists(cacheDir);
      const message = `Downloaded vulnerability DB has an invalid shape.${keepExisting ? ' Existing DB kept.' : ''}`;
      logger.warn('update-vuln-db rejected invalid payload');
      return { ok: false, message };
    }

    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, 'vuln-db-override.json'), `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
    await writeFile(
      join(cacheDir, 'vuln-db-meta.json'),
      `${JSON.stringify(
        {
          fetchedAt: new Date().toISOString(),
          source: parsedUrl.toString(),
          ruleCount: parsed.rules.length,
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    return {
      ok: true,
      message: `Vulnerability DB updated from ${parsedUrl.toString()} with ${String(parsed.rules.length)} rule(s).`,
    };
  } catch (error) {
    const keepExisting = await existingOverrideExists(cacheDir);
    const reason = error instanceof Error ? error.message : String(error);
    logger.warn({ err: reason }, 'update-vuln-db failed');
    return {
      ok: false,
      message: `Failed to update vulnerability DB: ${reason}.${keepExisting ? ' Existing DB kept.' : ''}`,
    };
  } finally {
    clearTimeout(timer);
  }
}
