import { existsSync, readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, join, normalize, resolve } from 'node:path';

import type { FileFilterOptions } from '../core/engine-options.js';
import type { ApiRouteInfo, ApiScanResult, Issue } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { runPool } from '../utils/async-pool.js';

/** HTTP methods that never use @Body() — do not flag missing DTO / validation. */
const SKIP_VALIDATION_METHODS = new Set(['GET', 'DELETE', 'HEAD', 'OPTIONS']);

/** Intentionally public paths — skip missing-auth heuristics. */
const PUBLIC_PATH_PATTERNS: readonly RegExp[] = [
  /health/i,
  /ping/i,
  /status/i,
  /login/i,
  /signup/i,
  /register/i,
  /forgot.password/i,
  /reset.password/i,
  /verify.otp/i,
  /resend/i,
  /callback/i,
  /oauth/i,
  /webhook/i,
  /refresh/i,
];

function globToRegExp(globPattern: string): RegExp {
  const esc = globPattern.replaceAll(/[.+^${}()|[\]\\]/g, '\\$&');
  const rx = `^${esc.replaceAll('*', '.*')}$`;
  return new RegExp(rx, 'i');
}

function isPublicApiPath(routePath: string, configuredPublicPatterns: readonly RegExp[]): boolean {
  return (
    PUBLIC_PATH_PATTERNS.some((p) => p.test(routePath)) ||
    configuredPublicPatterns.some((p) => p.test(routePath))
  );
}

function hasRoleBasedSignal(text: string): boolean {
  return /\b(@Roles\s*\(|rolesGuard|rbac|permission(s|Guard)?|scope(s|Guard)?)\b/i.test(text);
}

function classifyAccess(args: {
  readonly authHeuristic: ApiRouteInfo['authHeuristic'];
  readonly contextText: string;
  readonly routePath: string;
  readonly configuredPublicPatterns: readonly RegExp[];
}): NonNullable<ApiRouteInfo['accessClassification']> {
  if (hasRoleBasedSignal(args.contextText)) {
    return 'role-based';
  }
  if (args.authHeuristic === 'likely-protected') {
    return 'authenticated';
  }
  if (
    args.authHeuristic === 'likely-open' ||
    isPublicApiPath(args.routePath, args.configuredPublicPatterns)
  ) {
    return 'public';
  }
  return 'unknown';
}

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

const EXPRESS_METHODS = /(?:app|router)\.(get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
const FASTIFY_METHODS = /(?:fastify)\.(get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
/** Commander-style `.command('name')` after a `commander` import (CLI surface, not HTTP). */
const COMMANDER_SUBCOMMAND = /\.command\(\s*['"`]([^'"`]+)['"`]/g;

function detectAuthHint(text: string): ApiRouteInfo['authHeuristic'] {
  if (/\b(requireAuth|authenticate|isAuthenticated|verifyToken|authMiddleware|ensureAuth|withAuth)\b/.test(text)) {
    return 'likely-protected';
  }
  if (/\b(public|skipAuth|optionalAuth|anonymous)\b/i.test(text)) {
    return 'likely-open';
  }
  return 'unknown';
}

function detectValidationHint(text: string): ApiRouteInfo['validationHeuristic'] {
  if (/\b(z\.object|Joi\.|class-validator|ValidationPipe|celebrate|checkSchema|body\s*\(\s*['"`]|\bparse\s*\()\b/.test(text)) {
    return 'likely-present';
  }
  return 'likely-missing';
}

function workspaceUsesNest(cwd: string): boolean {
  const p = join(resolve(cwd), 'package.json');
  if (!existsSync(p)) {
    return false;
  }
  try {
    const pkg = JSON.parse(readFileSync(p, 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    return Boolean(all['@nestjs/core'] ?? all['@nestjs/common']);
  } catch {
    return false;
  }
}

const NEST_HTTP: Readonly<Record<string, string>> = {
  Get: 'GET',
  Post: 'POST',
  Put: 'PUT',
  Patch: 'PATCH',
  Delete: 'DELETE',
  Options: 'OPTIONS',
  Head: 'HEAD',
  All: 'ALL',
};

function fileUsesCommander(text: string): boolean {
  return (
    /(?:from|import)\s+['"]commander['"]/.test(text) ||
    /require\s*\(\s*['"]commander['"]\s*\)/.test(text)
  );
}

function scanCommanderSubcommands(path: string, text: string, routes: ApiRouteInfo[]): void {
  if (!fileUsesCommander(text)) {
    return;
  }
  const nameMatch = text.match(/\.name\(\s*['"`]([^'"`]+)['"`]\s*\)/);
  const programName = (nameMatch?.[1] ?? 'cli').replace(/^\/+|\/+$/g, '');
  const re = new RegExp(COMMANDER_SUBCOMMAND.source, 'g');
  let m: RegExpExecArray | null;
  for (;;) {
    m = re.exec(text);
    if (m === null) {
      break;
    }
    const sub = (m[1] ?? 'command').trim();
    if (sub.length === 0) {
      continue;
    }
    const prefix = text.slice(0, m.index);
    const line = prefix.split(/\r?\n/).length;
    const pathPattern = `/${[programName, sub].filter((s) => s.length > 0).join('/')}`.replaceAll(/\/+/g, '/');
    routes.push({
      method: 'CLI',
      pathPattern: pathPattern.length > 0 ? pathPattern : `/${sub}`,
      file: path,
      line,
      authHeuristic: 'unknown',
      validationHeuristic: 'unknown',
    });
  }
}

function extractControllerPrefix(text: string): string {
  // @Controller('prefix') or @Controller("prefix")
  const strMatch = text.match(/@Controller\s*\(\s*['"]([^'"]*)['"]\s*\)/);
  if (strMatch?.[1] != null) return strMatch[1].replace(/^\/+|\/+$/g, '');
  // @Controller({ path: 'prefix' })
  const objMatch = text.match(/@Controller\s*\(\s*\{[^}]*path\s*:\s*['"]([^'"]*)['"]/);
  if (objMatch?.[1] != null) return objMatch[1].replace(/^\/+|\/+$/g, '');
  // @Controller() with no arg — prefix is ''
  return '';
}

function scanNestControllerRoutes(
  path: string,
  text: string,
  routes: ApiRouteInfo[],
  issues: Issue[],
  configuredPublicPatterns: readonly RegExp[],
): void {
  if (!/@Controller\b/.test(text)) {
    return;
  }
  // Skip test / spec files — mock routes inflate counts
  if (/\.(spec|test)\.(ts|js)$/.test(path)) {
    return;
  }
  const prefix = extractControllerPrefix(text);
  const lines = text.split(/\r?\n/);
  const fileHasClassValidator = /\bclass-validator\b/.test(text);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const m = line.match(/@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)/);
    if (!m?.[1]) {
      continue;
    }
    const nestName = m[1];
    const method = NEST_HTTP[nestName] ?? 'GET';
    const sub = (m[2] ?? '').replace(/^\/+|\/+$/g, '');
    const combined = `/${[prefix, sub].filter((s) => s.length > 0).join('/')}`.replaceAll(/\/+/g, '/');
    const lineNo = i + 1;
    const windowStart = Math.max(0, i - 18);
    const ctx = lines.slice(windowStart, i + 1).join('\n');
    const authHeuristic = /@UseGuards\s*\(/.test(ctx) ? 'likely-protected' : 'unknown';
    const accessClassification = classifyAccess({
      authHeuristic,
      contextText: ctx,
      routePath: combined,
      configuredPublicPatterns,
    });
    const blockAhead = lines.slice(i, Math.min(lines.length, i + 6)).join('\n');
    let validationHeuristic: ApiRouteInfo['validationHeuristic'] = detectValidationHint(blockAhead);
    if (['POST', 'PUT', 'PATCH'].includes(method) && !/@Body\s*\(/.test(blockAhead)) {
      validationHeuristic = fileHasClassValidator ? 'likely-missing' : validationHeuristic;
    }
    if (/@Body\s*\(/.test(blockAhead)) {
      validationHeuristic = 'likely-present';
    }
    if (SKIP_VALIDATION_METHODS.has(method)) {
      validationHeuristic = 'unknown';
    }

    routes.push({
      method,
      pathPattern: combined.length > 0 ? combined : '/',
      file: path,
      line: lineNo,
      authHeuristic,
      accessClassification,
      validationHeuristic,
    });

    if (authHeuristic === 'unknown' && accessClassification === 'unknown') {
      const authSeverity: Issue['severity'] = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)
        ? 'MEDIUM'
        : 'LOW';
      issues.push(
        {
          ...mkIssue(
          'api',
          authSeverity,
          `Endpoint access classification is unknown: ${method} ${combined}`,
          path,
          lineNo,
          'No clear @UseGuards / @Roles / explicit public signal detected near this NestJS handler.',
          'Anonymous access if the handler is sensitive.',
            'Declare @UseGuards/Auth strategy or list intentional public endpoints in project-inspector.config.json (intentionalPublicRouteGlobs).',
          ),
          confidence: 'low',
          whyItMatters: 'Unclassified endpoint access can hide unintended public exposure.',
        },
      );
    }
    if (validationHeuristic === 'likely-missing' && !SKIP_VALIDATION_METHODS.has(method)) {
      issues.push(
        mkIssue(
          'api',
          'MEDIUM',
          `NestJS mutating route may lack DTO / validation: ${method} ${combined}`,
          path,
          lineNo,
          'No @Body() parameter or class-validator-powered DTO detected near this handler.',
          'Malformed input and injection-class bugs.',
          'Use @Body() with a class-validator DTO or Zod pipe.',
        ),
      );
    }
  }
}

async function analyzeApiFile(
  path: string,
  getSourceText: ((normalizedAbs: string) => string | undefined) | undefined,
  nestEnabled: boolean,
  configuredPublicPatterns: readonly RegExp[],
): Promise<{ routes: ApiRouteInfo[]; issues: Issue[] }> {
  const routes: ApiRouteInfo[] = [];
  const issues: Issue[] = [];
  let text: string | undefined = getSourceText?.(normalize(path));
  if (text === undefined) {
    try {
      text = await readFile(path, 'utf8');
    } catch {
      return { routes, issues };
    }
  }

  const lines = text.split(/\r?\n/);

  const scanRegex = (re: RegExp, framework: 'express' | 'fastify'): void => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    for (;;) {
      m = re.exec(text);
      if (m === null) {
        break;
      }
      const method = (m[1] ?? 'GET').toUpperCase();
      const pathPattern = m[2] ?? '/';
      const prefix = text.slice(0, m.index);
      const line = prefix.split(/\r?\n/).length;
      const windowStart = Math.max(0, m.index - 400);
      const windowEnd = Math.min(text.length, m.index + 400);
      const ctx = text.slice(windowStart, windowEnd);
      const authHeuristic = detectAuthHint(ctx);
      const validationHeuristic = detectValidationHint(ctx);
      const accessClassification = classifyAccess({
        authHeuristic,
        contextText: ctx,
        routePath: pathPattern,
        configuredPublicPatterns,
      });
      routes.push({ method, pathPattern, file: path, line, authHeuristic, accessClassification, validationHeuristic });

      if (authHeuristic === 'unknown' && (pathPattern === '/health' || pathPattern === '/metrics')) {
        // informational only
      } else if (authHeuristic === 'unknown' && framework === 'express' && accessClassification === 'unknown') {
        issues.push(
          {
            ...mkIssue(
            'api',
            'LOW',
            `Endpoint access classification is unknown: ${method} ${pathPattern}`,
            path,
            line,
            'No obvious auth helper / role guard / explicit public signal near this route registration.',
            'Unauthenticated access if route handles sensitive operations.',
              'Apply route-level auth middleware or add intentional public path globs in project-inspector.config.json.',
            ),
            confidence: 'low',
            whyItMatters: 'Unclassified endpoint access can hide unintended public exposure.',
          },
        );
      }

      if (validationHeuristic === 'likely-missing' && ['POST', 'PUT', 'PATCH'].includes(method)) {
        issues.push(
          mkIssue(
            'api',
            'MEDIUM',
            `Mutating route may lack request validation: ${method} ${pathPattern}`,
            path,
            line,
            'No obvious schema validation (zod/joi/class-validator/etc.) near handler registration.',
            'Injection and malformed input risk; inconsistent 4xx behavior.',
            'Validate body/query/params with a shared schema layer.',
          ),
        );
      }
    }
  };

  // Skip test/spec files for Express/Fastify scanning too
  if (!/\.(spec|test)\.(ts|js)$/.test(path)) {
    scanRegex(new RegExp(EXPRESS_METHODS.source, 'g'), 'express');
    scanRegex(new RegExp(FASTIFY_METHODS.source, 'g'), 'fastify');
  }

  if (nestEnabled && /\.(ts|tsx)$/.test(path)) {
    scanNestControllerRoutes(path, text, routes, issues, configuredPublicPatterns);
  }

  const base = basename(path).toLowerCase();
  if (base === 'route.ts' || base === 'route.js') {
    const handlerLine = lines.findIndex((l) => /\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/.test(l));
    if (handlerLine >= 0) {
      const line = handlerLine + 1;
      const m = lines[handlerLine]?.match(/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/);
      const method = m?.[1] ?? 'GET';
      routes.push({
        method,
        pathPattern: '(next-app-router)',
        file: path,
        line,
        authHeuristic: detectAuthHint(text),
        accessClassification: classifyAccess({
          authHeuristic: detectAuthHint(text),
          contextText: text,
          routePath: '(next-app-router)',
          configuredPublicPatterns,
        }),
        validationHeuristic: detectValidationHint(text),
      });
    }
  }

  scanCommanderSubcommands(path, text, routes);

  if (/\/(pages|app)\//.test(path.replaceAll('\\', '/')) && /\.(tsx|jsx)$/.test(path)) {
    if (/\/pages\//.test(path) && !text.includes('getServerSideProps') && !text.includes('getStaticProps')) {
      issues.push(
        mkIssue(
          'api',
          'LOW',
          'Legacy Next.js pages route without data fetching guardrails noted',
          path,
          1,
          'Heuristic only: pages router component without obvious gSSP/gSP.',
          'May still be static; verify data exposure on client bundles.',
          'Prefer App Router patterns or explicit data boundaries.',
        ),
      );
    }
  }

  return { routes, issues };
}

export interface ApiEngineOptions extends FileFilterOptions {
  readonly pathsOverride?: ReadonlySet<string>;
  readonly intentionalPublicRouteGlobs?: readonly string[];
}

export async function runApiEngine(cwd: string, concurrency: number, options?: ApiEngineOptions): Promise<ApiScanResult> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  let scoped = normalizedAll;
  if (options?.fileFilter) {
    scoped = scoped.filter((f) => options.fileFilter?.has(f));
  }
  const pathsOverride = options?.pathsOverride;
  if (pathsOverride) {
    scoped = scoped.filter((f) => pathsOverride.has(f));
  }
  const filtered = Boolean(options?.fileFilter || pathsOverride);
  if (filtered && scoped.length === 0) {
    return { routes: [], issues: [] };
  }
  const targets = filtered ? scoped : normalizedAll;
  const getText = options?.getSourceText;
  const nestEnabled = workspaceUsesNest(cwd);
  const configuredPublicPatterns = (options?.intentionalPublicRouteGlobs ?? [])
    .filter((p) => p.trim().length > 0)
    .map((p) => globToRegExp(p.trim()));
  const results = await runPool(targets, concurrency, (f) =>
    analyzeApiFile(f, getText, nestEnabled, configuredPublicPatterns),
  );
  const allRoutes = results.flatMap((r) => r.routes);
  const issues = results.flatMap((r) => r.issues);

  // Deduplicate: same method + path + file + line = same route
  const seen = new Set<string>();
  const routes = allRoutes.filter((r) => {
    const key = `${r.method}|${r.pathPattern}|${r.file}|${String(r.line)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { routes, issues };
}
