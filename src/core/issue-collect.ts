import type { Issue, ScanResult } from './types.js';

/** All issues used for scoring, hotspots, and cross-engine reports. */
export function gatherAllIssues(result: ScanResult): Issue[] {
  return [
    ...result.security.issues,
    ...result.dependency.issues,
    ...result.outdated.issues,
    ...result.tests.issues,
    ...result.database.issues,
    ...result.api.issues,
    ...result.env.issues,
    ...result.ast.issues,
    ...result.architecture.issues,
    ...result.performance.issues,
    ...result.memory.issues,
    ...result.codeSmell.issues,
    ...result.migration.issues,
    ...result.inventory.issues,
    ...result.lint.issues,
  ];
}
