import assert from 'node:assert/strict';
import { join, normalize } from 'node:path';
import os from 'node:os';
import { describe, it } from 'node:test';

import { runPerformanceEngine } from './performance-engine.js';

const TMP = os.tmpdir();

/**
 * Returns a (filePath, getSourceText) pair so performance-engine tests run fully
 * in-memory without writing any files to disk.
 */
function inMemoryFile(
  name: string,
  source: string,
): { filePath: string; getSourceText: (p: string) => string | undefined } {
  const filePath = normalize(join(TMP, name));
  return {
    filePath,
    getSourceText: (p: string) => (p === filePath ? source : undefined),
  };
}

describe('runPerformanceEngine — await-in-loop', () => {
  it('flags sequential await inside a for-of loop', async () => {
    const { filePath, getSourceText } = inMemoryFile('await-loop-test.ts', `
for (const item of items) {
  const data = await fetch(item);
}
`);
    const result = await runPerformanceEngine(TMP, 1, {
      sourceFiles: [filePath],
      getSourceText,
    });
    const ids = result.issues.map((i) => i.id);
    assert.ok(
      ids.some((id) => id.includes('await-in-loop')),
      `expected await-in-loop issue; got: ${JSON.stringify(ids)}`,
    );
  });

  it('does not flag await outside a loop', async () => {
    const { filePath, getSourceText } = inMemoryFile('no-loop-test.ts', `
const data = await fetch('https://api.example.com/items');
`);
    const result = await runPerformanceEngine(TMP, 1, {
      sourceFiles: [filePath],
      getSourceText,
    });
    const awaitLoopIssues = result.issues.filter((i) => i.id.includes('await-in-loop'));
    assert.equal(awaitLoopIssues.length, 0);
  });
});

describe('runPerformanceEngine — sync-fs', () => {
  it('flags readFileSync in general-purpose utility code', async () => {
    const { filePath, getSourceText } = inMemoryFile('data-utils.ts', `
import { readFileSync } from 'fs';
const config = readFileSync('/tmp/config.json', 'utf8');
`);
    const result = await runPerformanceEngine(TMP, 1, {
      sourceFiles: [filePath],
      getSourceText,
    });
    const ids = result.issues.map((i) => i.id);
    assert.ok(
      ids.some((id) => id.includes('sync-fs')),
      `expected sync-fs issue; got: ${JSON.stringify(ids)}`,
    );
  });

  it('does not flag readFileSync inside a startup file (main.ts)', async () => {
    // isLikelyStartup() returns true for paths ending with /main.ts
    const { filePath, getSourceText } = inMemoryFile('main.ts', `
import { readFileSync } from 'fs';
const bootstrap = readFileSync('./config.json', 'utf8');
`);
    const result = await runPerformanceEngine(TMP, 1, {
      sourceFiles: [filePath],
      getSourceText,
    });
    const syncFsIssues = result.issues.filter((i) => i.id.includes('sync-fs'));
    assert.equal(
      syncFsIssues.length,
      0,
      'startup files must not be flagged for sync-fs',
    );
  });
});

describe('runPerformanceEngine — sync-child-process', () => {
  it('flags execSync in request-handling code', async () => {
    const { filePath, getSourceText } = inMemoryFile('handler.ts', `
import { execSync } from 'child_process';
export function handler(req, res) {
  const out = execSync('ls /tmp');
  res.send(out);
}
`);
    const result = await runPerformanceEngine(TMP, 1, {
      sourceFiles: [filePath],
      getSourceText,
    });
    const ids = result.issues.map((i) => i.id);
    assert.ok(
      ids.some((id) => id.includes('sync-child-process')),
      `expected sync-child-process; got: ${JSON.stringify(ids)}`,
    );
  });
});
