import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { KNOWN_LATEST_MAJOR } from '../src/data/known-package-majors.js';

const REGISTRY_CONCURRENCY = 5;
const FETCH_TIMEOUT_MS = 10_000;

function majorFromVersion(version: string | undefined): number | null {
  if (typeof version !== 'string') {
    return null;
  }
  const match = /^v?(\d+)/.exec(version);
  if (match?.[1] === undefined) {
    return null;
  }
  const value = Number.parseInt(match[1], 10);
  return Number.isNaN(value) ? null : value;
}

async function fetchLatestMajor(pkg: string): Promise<number | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}/latest`, {
      signal: controller.signal,
      redirect: 'follow',
    });
    if (!response.ok) {
      return null;
    }
    const parsed = (await response.json()) as { version?: string };
    return majorFromVersion(parsed.version);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function runPool<T, R>(items: readonly T[], concurrency: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  let nextIndex = 0;
  const runners = Array.from({ length: Math.min(items.length, concurrency) }, async () => {
    for (;;) {
      const current = nextIndex;
      nextIndex += 1;
      if (current >= items.length) {
        return;
      }
      const item = items[current];
      if (item === undefined) {
        continue;
      }
      results[current] = await worker(item);
    }
  });
  await Promise.all(runners);
  return results;
}

function formatKnownMajors(record: Readonly<Record<string, number>>, timestamp: string): string {
  const lines = Object.keys(record)
    .sort((left, right) => left.localeCompare(right))
    .map((name) => `  ${JSON.stringify(name)}: ${String(record[name])},`);
  return `// Last updated: ${timestamp}\n/**
 * Offline "latest known" majors for drift detection (curated, not live registry).
 * Refresh periodically with ecosystem LTS lines.
 */
export const KNOWN_LATEST_MAJOR: Readonly<Record<string, number>> = {
${lines.join('\n')}
};
`;
}

async function main(): Promise<void> {
  const target = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'data', 'known-package-majors.ts');
  await readFile(target, 'utf8');

  const packages = Object.keys(KNOWN_LATEST_MAJOR).sort((left, right) => left.localeCompare(right));
  const majors = { ...KNOWN_LATEST_MAJOR };
  const fetched = await runPool(packages, REGISTRY_CONCURRENCY, async (pkg) => ({
    pkg,
    major: await fetchLatestMajor(pkg),
  }));

  for (const entry of fetched) {
    if (entry?.major !== null && entry?.major !== undefined) {
      majors[entry.pkg] = entry.major;
    }
  }

  const timestamp = new Date().toISOString();
  await writeFile(target, formatKnownMajors(majors, timestamp), 'utf8');
  process.stdout.write(`Updated ${target} for ${String(packages.length)} package(s).\n`);
}

void main();
