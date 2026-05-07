import type { ApiRouteInfo } from '../core/types.js';

/** Minimal OpenAPI 3.1 document from heuristically discovered routes. */
export function buildOpenApi31FromRoutes(
  routes: readonly ApiRouteInfo[],
  title: string,
  version: string,
): Record<string, unknown> {
  const httpRoutes = routes.filter((r) => r.method !== 'CLI' && r.pathPattern !== '(next-app-router)');
  const paths: Record<string, unknown> = {};
  for (const r of httpRoutes) {
    const openApiPath = toOpenApiPath(r.pathPattern);
    const method = r.method.toLowerCase();
    const existing = (paths[openApiPath] as Record<string, unknown> | undefined) ?? {};
    existing[method] = {
      operationId: `${r.method.toLowerCase()}_${sanitizeOpId(r.pathPattern)}`.slice(0, 64),
      summary: `Heuristic: ${r.method} ${r.pathPattern}`,
      responses: {
        '200': { description: 'OK' },
        '4XX': { description: 'Client error' },
        '5XX': { description: 'Server error' },
      },
      'x-source': `${r.file}:${String(r.line)}`,
      'x-auth-heuristic': r.authHeuristic,
      'x-validation-heuristic': r.validationHeuristic,
    };
    paths[openApiPath] = existing;
  }
  return {
    openapi: '3.1.0',
    info: { title, version, description: 'Auto-generated from project-inspector route heuristics; not a substitute for a hand-authored spec.' },
    paths,
  };
}

function toOpenApiPath(pattern: string): string {
  if (pattern === '(next-app-router)') {
    return '/_next_app_router';
  }
  let p = pattern.startsWith('/') ? pattern : `/${pattern}`;
  p = p.replaceAll(/:(\w+)/g, '{$1}');
  return p;
}

function sanitizeOpId(s: string): string {
  return s.replaceAll(/[^A-Za-z0-9_]+/gu, '_').replace(/^_+|_+$/gu, '') || 'route';
}
