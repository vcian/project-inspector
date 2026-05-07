import { relative } from 'node:path';

import type { ArchitecturePolicyConfig } from '../core/inspector-config.js';
import type { ImportEdge, Issue } from '../core/types.js';

function globToRegExp(pattern: string): RegExp {
  const normalized = pattern.replaceAll('\\', '/').replaceAll(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withStars = normalized
    .replaceAll(/\*\*/g, '§DOUBLE§')
    .replaceAll('*', '[^/]*')
    .replaceAll('§DOUBLE§', '.*');
  return new RegExp(`^${withStars}$`, 'i');
}

function matchesGlob(relPosix: string, pattern: string): boolean {
  return globToRegExp(pattern).test(relPosix);
}

/** Layer/import rules similar to dependency-cruiser (glob-based, best-effort). */
export function runArchitecturePolicyEngine(
  cwd: string,
  policy: ArchitecturePolicyConfig | undefined,
  edges: readonly ImportEdge[],
): Issue[] {
  if (policy?.forbid === undefined || policy.forbid.length === 0) {
    return [];
  }
  const issues: Issue[] = [];
  let idx = 0;
  for (const edge of edges) {
    const fromRel = relative(cwd, edge.from).replaceAll('\\', '/');
    const toSpec = edge.specifier;
    for (const rule of policy.forbid) {
      if (!matchesGlob(fromRel, rule.fromPathGlob)) {
        continue;
      }
      if (!globToRegExp(rule.importGlob).test(toSpec)) {
        continue;
      }
      idx += 1;
      const title = rule.message ?? `Forbidden import: ${fromRel} → ${toSpec}`;
      issues.push({
        id: `arch-policy:${String(idx)}:${fromRel}:${toSpec}`,
        engine: 'architecture',
        severity: 'HIGH',
        title,
        file: edge.from,
        line: 1,
        description: `Import edge violates architecturePolicy: from matches \`${rule.fromPathGlob}\`, specifier matches \`${rule.importGlob}\`.`,
        impact: 'Layering boundaries may be violated; coupling and circular dependency risk.',
        fix: 'Refactor import path or adjust architecturePolicy if intentional.',
        category: 'architecture',
        confidence: 'medium',
      });
    }
  }
  return issues;
}
