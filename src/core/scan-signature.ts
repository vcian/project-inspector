import type { ScanResult } from './types.js';

/** Cheap fingerprint to skip rewriting merged-scan.json when nothing material changed. */
export function scanResultFingerprint(result: ScanResult): string {
  const issueIds = (issues: readonly { readonly id: string }[]): string =>
    [...issues]
      .map((i) => i.id)
      .sort()
      .join('\n');

  const payload = {
    scores: result.scores,
    mode: result.mode,
    incremental: result.incremental,
    online: result.online,
    astFiles: result.ast.filesAnalyzed,
    astFn: result.ast.functions.length,
    astEdges: result.ast.importGraph.length,
    astCycles: result.ast.circularDependencyChains.length,
    ids: {
      ast: issueIds(result.ast.issues),
      security: issueIds(result.security.issues),
      dependency: issueIds(result.dependency.issues),
      outdated: issueIds(result.outdated.issues),
      tests: issueIds(result.tests.issues),
      database: issueIds(result.database.issues),
      api: issueIds(result.api.issues),
      env: issueIds(result.env.issues),
      arch: issueIds(result.architecture.issues),
      perf: issueIds(result.performance.issues),
      mem: issueIds(result.memory.issues),
      smell: issueIds(result.codeSmell.issues),
      mig: issueIds(result.migration.issues),
    },
    routes: result.api.routes.length,
    hotspots: result.hotspots.map((h) => `${String(h.rank)}:${h.title}`).join('|'),
  };

  return JSON.stringify(payload);
}
