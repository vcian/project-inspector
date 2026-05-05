import { normalize } from 'node:path';

import type { ApiRouteInfo, Issue } from './types.js';

export function mergeIssuesByReanalyze(
  previous: readonly Issue[],
  allCurrentFiles: ReadonlySet<string>,
  reanalyzedFiles: ReadonlySet<string>,
  freshIssues: readonly Issue[],
): Issue[] {
  const kept = previous.filter((i) => {
    const f = normalize(i.file);
    return allCurrentFiles.has(f) && !reanalyzedFiles.has(f);
  });
  return [...kept, ...freshIssues];
}

export function mergeApiRoutes(
  previous: readonly ApiRouteInfo[],
  reanalyzedFiles: ReadonlySet<string>,
  freshRoutes: readonly ApiRouteInfo[],
): ApiRouteInfo[] {
  const kept = previous.filter((r) => !reanalyzedFiles.has(normalize(r.file)));
  return [...kept, ...freshRoutes];
}
