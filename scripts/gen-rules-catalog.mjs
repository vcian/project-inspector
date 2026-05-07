#!/usr/bin/env node
/**
 * Lightweight catalog: lists engine files and extracts quoted titles (heuristic).
 * Run from repo root: node scripts/gen-rules-catalog.mjs > docs/rules-catalog.md
 */
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const enginesDir = join(root, 'src', 'engines');
const outPath = join(root, 'docs', 'rules-catalog.md');

const files = (await readdir(enginesDir)).filter((f) => f.endsWith('.ts')).sort();

let md = `# Rules catalog (generated)\n\n`;
md += `_Heuristic extraction from \`src/engines/*.ts\`. Regenerate: \`node scripts/gen-rules-catalog.mjs\`._\n\n`;

for (const f of files) {
  const text = await readFile(join(enginesDir, f), 'utf8');
  const titles = new Set();
  for (const m of text.matchAll(/title:\s*['"]([^'"]+)['"]/gu)) {
    titles.add(m[1]);
  }
  md += `## ${f}\n\n`;
  if (titles.size === 0) {
    md += `_No quoted titles matched — engine may build titles dynamically._\n\n`;
    continue;
  }
  md += '| Rule title (sample) |\n| --- |\n';
  for (const t of [...titles].slice(0, 60)) {
    md += `| ${t.replaceAll('|', '\\|')} |\n`;
  }
  md += '\n';
}

await writeFile(outPath, md, 'utf8');
process.stdout.write(`Wrote ${outPath}\n`);
