import { join, resolve } from 'node:path';
import { existsSync } from 'node:fs';

import type { FrameworkTag, ProjectProfile } from '../core/types.js';
import { discoverWorkspaceProjects } from './discover-workspace-projects.js';

export async function detectProjectProfile(cwd: string): Promise<ProjectProfile> {
  const root = resolve(cwd);
  let hasTypescript = false;
  let hasJsx = false;
  let packageManager: ProjectProfile['packageManager'] = 'unknown';
  const entryPoints = new Set<string>();
  const frameworks = new Set<FrameworkTag>();

  hasTypescript = existsSync(join(root, 'tsconfig.json'));

  if (existsSync(join(root, 'pnpm-lock.yaml'))) {
    packageManager = 'pnpm';
  } else if (existsSync(join(root, 'yarn.lock'))) {
    packageManager = 'yarn';
  } else if (existsSync(join(root, 'package-lock.json'))) {
    packageManager = 'npm';
  }

  const projects = await discoverWorkspaceProjects(root);
  for (const project of projects) {
    for (const fw of project.frameworks) {
      frameworks.add(fw);
    }
    if (project.frameworks.includes('react') || project.frameworks.includes('nextjs')) {
      hasJsx = true;
    }
    for (const entry of project.entryPoints) {
      entryPoints.add(project.relPath === '.' ? entry : `${project.relPath}/${entry}`.replaceAll('\\', '/'));
    }
    if (!hasTypescript && existsSync(join(project.rootDir, 'tsconfig.json'))) {
      hasTypescript = true;
    }
  }

  const frameworkList = [...frameworks];
  const hasNextOrAngular = frameworkList.includes('nextjs') || frameworkList.includes('angular');
  const hasServer =
    frameworkList.includes('nestjs') || frameworkList.includes('express') || frameworkList.includes('fastify');
  const hasBrowser =
    frameworkList.includes('react') ||
    frameworkList.includes('vue') ||
    frameworkList.includes('svelte') ||
    frameworkList.includes('angular');
  let runtime: ProjectProfile['runtime'] = 'unknown';
  if (hasNextOrAngular) {
    runtime = 'hybrid';
  } else if (hasServer && hasBrowser) {
    runtime = 'hybrid';
  } else if (hasBrowser) {
    runtime = 'browser';
  } else if (hasServer || frameworkList.includes('node')) {
    runtime = 'node';
  }

  const serviceCount = projects.filter((project) => project.role === 'service').length;
  const mfeCount = projects.filter((project) => project.role === 'micro-frontend').length;
  const nonRootCount = projects.filter((project) => project.role !== 'root').length;
  const topology: NonNullable<ProjectProfile['topology']> =
    projects.length <= 1
      ? 'single'
      : serviceCount >= 2
        ? 'microservices'
        : mfeCount >= 2
          ? 'micro-frontend'
          : nonRootCount > 0
            ? 'monorepo'
            : 'multi-project';

  return {
    primaryFramework: pickPrimary(frameworkList),
    frameworks: frameworkList,
    hasTypescript,
    hasJsx,
    runtime,
    packageManager,
    entryPoints: [...entryPoints],
    topology,
    projects,
  };
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

/**
 * Heuristic for per-file framework tagging (cheap path match).
 */
export function frameworkForFile(absPath: string, profile: ProjectProfile): FrameworkTag {
  const n = absPath.replaceAll('\\', '/').toLowerCase();
  if (profile.frameworks.includes('nextjs') && (n.includes('/app/') || n.includes('/pages/'))) {
    return 'nextjs';
  }
  if (
    profile.frameworks.includes('angular') &&
    (n.endsWith('.component.ts') ||
      n.endsWith('.module.ts') ||
      n.endsWith('.service.ts') ||
      n.endsWith('.directive.ts') ||
      n.endsWith('.pipe.ts'))
  ) {
    return 'angular';
  }
  if (
    profile.frameworks.includes('nestjs') &&
    (n.endsWith('.controller.ts') ||
      n.endsWith('.module.ts') ||
      n.endsWith('.service.ts') ||
      n.endsWith('.guard.ts') ||
      n.endsWith('.interceptor.ts'))
  ) {
    return 'nestjs';
  }
  if (profile.frameworks.includes('react') && (n.endsWith('.tsx') || n.endsWith('.jsx'))) {
    return 'react';
  }
  return profile.primaryFramework;
}
