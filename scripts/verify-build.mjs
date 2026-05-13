#!/usr/bin/env node
/**
 * Post-build integrity check.
 * Verifies that dist/cli.js exists and starts with the shebang,
 * and that dist/index.js exists as the library entry point.
 */
import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(import.meta.url), '../..');
let failed = false;

async function check(label, fn) {
  try {
    await fn();
    process.stdout.write(`  ✓  ${label}\n`);
  } catch (err) {
    process.stderr.write(`  ✗  ${label}: ${err.message}\n`);
    failed = true;
  }
}

await check('dist/cli.js exists', async () => {
  await stat(join(root, 'dist', 'cli.js'));
});

await check('dist/cli.js line 1 is #!/usr/bin/env node', async () => {
  const text = await readFile(join(root, 'dist', 'cli.js'), 'utf8');
  const firstLine = text.split('\n')[0];
  if (firstLine !== '#!/usr/bin/env node') {
    throw new Error(`unexpected first line: ${JSON.stringify(firstLine)}`);
  }
});

await check('dist/index.js exists', async () => {
  await stat(join(root, 'dist', 'index.js'));
});

if (failed) {
  process.stderr.write('\nBuild verification FAILED — see errors above.\n');
  process.exit(1);
}

process.stdout.write('\nBuild verified.\n');
