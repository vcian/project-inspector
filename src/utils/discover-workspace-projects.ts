import fg from 'fast-glob';
import { existsSync, readFileSync } from 'node:fs';
import { basename, join, relative, resolve } from 'node:path';

import type { FrameworkTag, ProjectProfile, WorkspaceProject, WorkspaceProjectRole } from '../core/types.js';

interface PackageJsonLike {
  readonly name?: string;
  readonly main?: string;
  readonly module?: string;
  readonly exports?: unknown;
  readonly workspaces?: readonly string[] | { readonly packages?: readonly string[] };
  readonly dependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
  readonly peerDependencies?: Record<string, string>;
}

const DEFAULT_WORKSPACE_PATTERNS: readonly string[] = [
  'apps/*/package.json',
  'packages/*/package.json',
  'services/*/package.json',
  'microservices/*/package.json',
  'frontends/*/package.json',
  'micro-frontends/*/package.json',
  'libs/*/package.json',
];

const DISCOVERY_IGNORE: readonly string[] = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.git/**',
  '**/coverage/**',
  '**/.turbo/**',
  '**/.cache/**',
  '**/project-report/**',
];

function readPackageJsonSafe(path: string): PackageJsonLike | null {
  if (!existsSync(path)) {
    return null;
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as PackageJsonLike;
  } catch {
    return null;
  }
}

function hasDep(pkg: PackageJsonLike, name: string): boolean {
  return Boolean(pkg.dependencies?.[name] ?? pkg.devDependencies?.[name] ?? pkg.peerDependencies?.[name]);
}

function inferFrameworks(pkg: PackageJsonLike): FrameworkTag[] {
  const frameworks: FrameworkTag[] = [];
  if (hasDep(pkg, '@nestjs/core') || hasDep(pkg, '@nestjs/common')) {
    frameworks.push('nestjs');
  }
  if (hasDep(pkg, 'next')) {
    frameworks.push('nextjs');
  }
  if (hasDep(pkg, '@angular/core')) {
    frameworks.push('angular');
  }
  if (hasDep(pkg, 'react') || hasDep(pkg, 'react-dom')) {
    frameworks.push('react');
  }
  if (hasDep(pkg, 'vue')) {
    frameworks.push('vue');
  }
  if (hasDep(pkg, 'svelte') || hasDep(pkg, '@sveltejs/kit')) {
    frameworks.push('svelte');
  }
  if (hasDep(pkg, 'express')) {
    frameworks.push('express');
  }
  if (hasDep(pkg, 'fastify')) {
    frameworks.push('fastify');
  }
  if (frameworks.length === 0 && pkg.name !== undefined) {
    frameworks.push('node');
  }
  return [...new Set(frameworks)];
}

function pickPrimary(frameworks: readonly FrameworkTag[]): FrameworkTag {
  const priority: readonly FrameworkTag[] = [
    'nestjs',
    'nextjs',
    'angular',
    'svelte',
    'vue',
    'react',
    'fastify',
    'express',
    'node',
  ];
  for (const fw of priority) {
    if (frameworks.includes(fw)) {
      return fw;
    }
  }
  return 'unknown';
}

function runtimeForFrameworks(frameworks: readonly FrameworkTag[]): ProjectProfile['runtime'] {
  const hasServer = frameworks.includes('nestjs') || frameworks.includes('express') || frameworks.includes('fastify');
  const hasBrowser =
    frameworks.includes('react') ||
    frameworks.includes('nextjs') ||
    frameworks.includes('angular') ||
    frameworks.includes('vue') ||
    frameworks.includes('svelte');
  if (frameworks.includes('nextjs')) {
    return 'hybrid';
  }
  if (hasServer && hasBrowser) {
    return 'hybrid';
  }
  if (hasBrowser) {
    return 'browser';
  }
  if (hasServer || frameworks.includes('node')) {
    return 'node';
  }
  return 'unknown';
}

function packageManagerFor(projectRoot: string): ProjectProfile['packageManager'] {
  if (existsSync(join(projectRoot, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (existsSync(join(projectRoot, 'yarn.lock'))) {
    return 'yarn';
  }
  if (existsSync(join(projectRoot, 'package-lock.json'))) {
    return 'npm';
  }
  return 'unknown';
}

function inferRole(relPath: string): WorkspaceProjectRole {
  if (relPath === '.') {
    return 'root';
  }
  const first = relPath.split(/[\\/]/)[0]?.toLowerCase() ?? '';
  if (first === 'apps') {
    return 'app';
  }
  if (first === 'packages' || first === 'libs') {
    return 'package';
  }
  if (first === 'services' || first === 'microservices') {
    return 'service';
  }
  if (first === 'frontends' || first === 'micro-frontends') {
    return 'micro-frontend';
  }
  return 'workspace';
}

function normalizeOneWorkspacePattern(pattern: string): string {
  return pattern.endsWith('/package.json') || pattern === 'package.json'
    ? pattern
    : `${pattern.replace(/\/+$/, '')}/package.json`;
}

function normalizeWorkspacePatterns(raw: PackageJsonLike['workspaces']): string[] {
  if (Array.isArray(raw)) {
    const out: string[] = [];
    for (const entry of raw) {
      if (typeof entry !== 'string') {
        continue;
      }
      out.push(normalizeOneWorkspacePattern(entry));
    }
    return out;
  }
  if (typeof raw === 'object' && 'packages' in raw) {
    const pkgs = raw.packages;
    if (!Array.isArray(pkgs)) {
      return [];
    }
    const out: string[] = [];
    for (const entry of pkgs) {
      if (typeof entry !== 'string') {
        continue;
      }
      out.push(normalizeOneWorkspacePattern(entry));
    }
    return out;
  }
  return [];
}

export async function discoverWorkspaceProjects(cwd: string): Promise<readonly WorkspaceProject[]> {
  const root = resolve(cwd);
  const rootPkgPath = join(root, 'package.json');
  const rootPkg = readPackageJsonSafe(rootPkgPath);
  const patterns = new Set<string>(DEFAULT_WORKSPACE_PATTERNS);
  for (const pattern of normalizeWorkspacePatterns(rootPkg?.workspaces)) {
    patterns.add(pattern);
  }

  const manifestPaths = new Set<string>();
  if (rootPkg !== null) {
    manifestPaths.add(rootPkgPath);
  }
  const hits = await fg([...patterns], {
    cwd: root,
    absolute: true,
    onlyFiles: true,
    unique: true,
    ignore: [...DISCOVERY_IGNORE],
  });
  for (const hit of hits) {
    manifestPaths.add(resolve(hit));
  }

  const projects: WorkspaceProject[] = [];
  for (const packageJsonPath of [...manifestPaths].sort((a, b) => a.localeCompare(b))) {
    const pkg = readPackageJsonSafe(packageJsonPath);
    if (pkg === null) {
      continue;
    }
    const rootDir = resolve(packageJsonPath, '..');
    const relPath = relative(root, rootDir).replaceAll('\\', '/') || '.';
    const frameworks = inferFrameworks(pkg);
    const role = inferRole(relPath);
    const packageManager = role === 'root' ? packageManagerFor(rootDir) : packageManagerFor(root);
    const entryPoints = [pkg.main, pkg.module].filter((value): value is string => typeof value === 'string' && value.length > 0);
    projects.push({
      name: pkg.name ?? basename(rootDir),
      rootDir,
      relPath,
      packageJsonPath,
      role,
      primaryFramework: pickPrimary(frameworks),
      frameworks,
      runtime: runtimeForFrameworks(frameworks),
      packageManager,
      entryPoints,
    });
  }

  return projects;
}
