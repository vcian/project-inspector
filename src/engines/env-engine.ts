import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
import fg from 'fast-glob';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, normalize, relative, resolve } from 'node:path';

import type { EnvScanResult, Issue } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';

function mkIssue(
  engine: string,
  severity: Issue['severity'],
  title: string,
  file: string,
  line: number,
  description: string,
  impact: string,
  fix: string,
): Issue {
  const id = `${engine}:${file}:${String(line)}:${title}`.replaceAll(/\s+/g, '_');
  return { id, engine, severity, title, file, line, description, impact, fix };
}

function parseEnvKeys(text: string): string[] {
  const keys: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    if (/^[A-Z0-9_]+$/.test(key)) {
      keys.push(key);
    }
  }
  return keys;
}

async function isTrackedByGit(cwd: string, relPath: string): Promise<boolean> {
  try {
    await execFileAsync('git', ['-C', cwd, 'ls-files', '--error-unmatch', relPath], {
      windowsHide: true,
      maxBuffer: 1_000_000,
    });
    return true;
  } catch {
    return false;
  }
}

async function collectEnvFiles(cwd: string): Promise<string[]> {
  const root = resolve(cwd);
  const envLike = await fg(['**/.env', '**/.env.*'], {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    unique: true,
    ignore: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/build/**',
      '**/coverage/**',
      '**/.git/**',
      '**/.cache/**',
      '**/project-report/**',
    ],
  });
  return envLike.filter((path) => {
    const base = path.split(/[/\\]/).pop()?.toLowerCase() ?? '';
    return !base.endsWith('.sample') && !base.endsWith('.example');
  });
}

export interface EnvEngineOptions {
  readonly sourceFiles?: readonly string[];
  readonly getSourceText?: (normalizedAbs: string) => string | undefined;
}

export async function runEnvEngine(cwd: string, options?: EnvEngineOptions): Promise<EnvScanResult> {
  const root = resolve(cwd);
  const issues: Issue[] = [];
  const envFiles = await collectEnvFiles(root);
  const keysFound = new Set<string>();

  for (const ef of envFiles) {
    let text: string;
    try {
      text = await readFile(ef, 'utf8');
    } catch {
      continue;
    }
    for (const k of parseEnvKeys(text)) {
      keysFound.add(k);
    }

    const rel = relative(root, ef).replaceAll('\\', '/');
    const tracked = await isTrackedByGit(root, rel);
    if (tracked && basenameLikeSecretFile(ef)) {
      issues.push(
        mkIssue(
          'env',
          'CRITICAL',
          'Environment file appears tracked by git',
          ef,
          1,
          `File ${rel} is tracked in version control.`,
          'Secrets leak via repository clones, forks, and backups.',
          'Remove from git history, rotate secrets, add to .gitignore, and use secret managers.',
        ),
      );
    }
  }

  const usedKeys = await collectProcessEnvKeys(root, options?.getSourceText, options?.sourceFiles);
  let unusedCap = 0;
  for (const k of keysFound) {
    if (!usedKeys.has(k) && unusedCap < 6) {
      unusedCap += 1;
      issues.push(
        mkIssue(
          'env',
          'LOW',
          `Possibly unused environment variable: ${k}`,
          join(root, '.env'),
          1,
          `Key "${k}" was not found via process.env.${k}, configService.get('${k}'), or similar patterns in scanned sources. May still be consumed by external tooling or a framework config loader.`,
          'Noise in configuration; may still be used by tooling or framework (e.g. NestJS ConfigModule).',
          'Remove unused keys or add a comment documenting the external consumer.',
        ),
      );
    }
  }

  const criticalRefs = ['DATABASE_URL', 'JWT_SECRET', 'SESSION_SECRET', 'REDIS_URL', 'API_KEY'];
  for (const k of criticalRefs) {
    if (usedKeys.has(k) && !keysFound.has(k) && envFiles.length > 0) {
      issues.push(
        mkIssue(
          'env',
          'MEDIUM',
          `Referenced environment variable missing from scanned .env files: ${k}`,
          join(root, 'package.json'),
          1,
          'Code references this key but it was not listed in discovered .env files (may be injected in deployment).',
          'Runtime failures or accidental use of undefined secrets.',
          'Document required env vars; validate at startup; provide .env.example without secrets.',
        ),
      );
    }
  }

  if (envFiles.length === 0 && existsSync(join(root, 'package.json'))) {
    issues.push(
      mkIssue(
        'env',
        'LOW',
        'No .env files discovered in repository',
        join(root, 'package.json'),
        1,
        'No `.env`, `.env.local`, etc. found in the repository (they may be gitignored as expected).',
        'Harder to verify local/dev parity.',
        'Maintain `.env.example` with required keys (no secret values).',
      ),
    );
  }

  return {
    issues,
    envFiles,
    keysFound: [...keysFound].sort(),
  };
}

function basenameLikeSecretFile(p: string): boolean {
  const b = p.split(/[/\\]/).pop() ?? '';
  return b === '.env' || b.startsWith('.env.');
}

async function collectProcessEnvKeys(
  cwd: string,
  getSourceText?: (normalizedAbs: string) => string | undefined,
  sourceFiles?: readonly string[],
): Promise<Set<string>> {
  const keys = new Set<string>();
  // Covers: process.env.KEY, process.env['KEY'], configService.get('KEY'),
  // configService.get<T>('KEY'), configService.getOrThrow('KEY'),
  // this.configService.get('KEY'), registerAs namespace strings, etc.
  const patterns = [
    /process\.env\.([A-Z][A-Z0-9_]*)/g,
    /process\.env\[['"]([A-Z][A-Z0-9_]*)['"]]/g,
    /\.get(?:OrThrow)?(?:<[^>]*>)?\(\s*['"]([A-Z][A-Z0-9_]*)['"]/g,
    /injectToken\s*\(\s*['"]([A-Z][A-Z0-9_]*)['"]/g,
    /process\.env\b.*?\b([A-Z][A-Z0-9_]{2,})/g,
  ];
  const files =
    sourceFiles && sourceFiles.length > 0 ? [...sourceFiles] : await discoverSourceFiles(cwd);
  for (const f of files) {
    let text: string | undefined = getSourceText?.(normalize(f));
    if (text === undefined) {
      try {
        text = await readFile(f, 'utf8');
      } catch {
        continue;
      }
    }
    for (const re of patterns) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      for (;;) {
        m = re.exec(text);
        if (m === null) break;
        if (m[1]) keys.add(m[1]);
      }
    }
  }
  return keys;
}
