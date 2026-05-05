import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface CodeOwnersRule {
  readonly pattern: string;
  readonly owners: readonly string[];
}

function escapeRegex(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/gu, '\\$&');
}

/** `relPath` — forward slashes, no leading slash, relative to repo root. */
function matchesCodeownersPattern(relPath: string, patternRaw: string): boolean {
  let pat = patternRaw.trim().replaceAll('\\', '/');
  if (pat.startsWith('/')) {
    pat = pat.slice(1);
  }
  const path = relPath.replace(/^\/+/, '');
  if (pat.endsWith('/')) {
    const prefix = pat.slice(0, -1);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  const parts = pat.split('/');
  const segs = path.split('/');
  let pi = 0;
  let si = 0;
  while (pi < parts.length && si < segs.length) {
    const p = parts[pi];
    if (p === undefined) {
      break;
    }
    if (p === '**') {
      return true;
    }
    const s = segs[si];
    if (s === undefined) {
      return false;
    }
    if (p === '*') {
      pi += 1;
      si += 1;
      continue;
    }
    if (p.includes('*')) {
      const re = new RegExp(`^${escapeRegex(p).replaceAll('\\*', '[^/]*')}$`, 'iu');
      if (!re.test(s)) {
        return false;
      }
      pi += 1;
      si += 1;
      continue;
    }
    if (p !== s) {
      return false;
    }
    pi += 1;
    si += 1;
  }
  return pi === parts.length && si === segs.length;
}

/**
 * Load `.github/CODEOWNERS` or root `CODEOWNERS` (first found). Best-effort; invalid lines skipped.
 */
export async function loadCodeOwnersRules(cwd: string): Promise<readonly CodeOwnersRule[]> {
  const candidates = [join(cwd, '.github', 'CODEOWNERS'), join(cwd, 'CODEOWNERS')];
  let text: string | undefined;
  for (const path of candidates) {
    try {
      text = await readFile(path, 'utf8');
      break;
    } catch {
      /* try next */
    }
  }
  if (text === undefined) {
    return [];
  }
  const rules: CodeOwnersRule[] = [];
  for (const line of text.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }
    const parts = trimmed.split(/\s+/u).filter((s) => s.length > 0);
    if (parts.length < 2) {
      continue;
    }
    const pattern = parts[0];
    if (pattern === undefined) {
      continue;
    }
    const owners = parts.slice(1).filter((t) => t.startsWith('@'));
    if (owners.length === 0) {
      continue;
    }
    rules.push({ pattern, owners });
  }
  return rules;
}

/** Last matching rule wins (GitHub-style). */
export function ownerForPath(rules: readonly CodeOwnersRule[], relPath: string): string | undefined {
  const norm = relPath.replaceAll('\\', '/').replace(/^\/+/, '');
  let hit: string | undefined;
  for (const r of rules) {
    if (matchesCodeownersPattern(norm, r.pattern)) {
      hit = r.owners.join(' ');
    }
  }
  return hit;
}
