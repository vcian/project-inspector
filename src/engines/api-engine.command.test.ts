import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

import { runApiEngine } from './api-engine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..', '..');
const cliTs = resolve(repoRoot, 'src', 'cli.ts');

describe('api-engine Commander CLI routes', () => {
  it('detects .command() entries in src/cli.ts', async () => {
    const result = await runApiEngine(repoRoot, 2, { pathsOverride: new Set([cliTs]) });
    const cli = result.routes.filter((r) => r.method === 'CLI');
    assert.ok(cli.length >= 5, `expected multiple CLI commands, got ${String(cli.length)}`);
    assert.ok(
      cli.some((r) => r.pathPattern.includes('scan')),
      `expected scan subcommand in path patterns: ${cli.map((r) => r.pathPattern).join(', ')}`,
    );
  });
});
