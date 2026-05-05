import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Optional `project-inspector.config.json` in the project root.
 * Used to suppress noise and tune false-positive control.
 */
export interface InspectorConfig {
  readonly version: 1;
  /** Glob patterns (forward slashes) relative to project root; matched paths are excluded from trusted findings. */
  readonly ignorePathGlobs: readonly string[];
  /** Exact `Issue.id` values to drop from trusted output. */
  readonly suppressIssueIds: readonly string[];
  /** Case-insensitive substring match on `Issue.title` — dropped when matched. */
  readonly suppressTitleSubstrings: readonly string[];
  /** When true, findings with `confidence: low` are excluded from scoring and decision output. */
  readonly excludeLowConfidence: boolean;
  /** CI / decision gate thresholds (0–100). */
  readonly gates?: {
    readonly minProductionReadiness?: number;
    readonly minSecurityScore?: number;
  };
  /**
   * Extra fast-glob patterns (relative to project root) counted as test files, in addition to the
   * built-in `*.test.*`, `*.spec.*`, and `__tests__/**` defaults.
   */
  readonly testFileGlobs?: readonly string[];
  /**
   * Route path patterns treated as intentionally public for API auth heuristics.
   * Supports `*` wildcards, e.g. `/public/*`, `/auth/login`, `/webhooks/*`.
   */
  readonly intentionalPublicRouteGlobs?: readonly string[];
}

export const DEFAULT_INSPECTOR_CONFIG: InspectorConfig = {
  version: 1,
  ignorePathGlobs: [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/coverage/**',
    '**/.next/**',
    '**/*.test.ts',
    '**/*.test.tsx',
    '**/*.test.js',
    '**/*.spec.ts',
    '**/*.spec.tsx',
    '**/*.spec.js',
    '**/__tests__/**',
    '**/e2e/**',
    '**/__mocks__/**',
  ],
  suppressIssueIds: [],
  suppressTitleSubstrings: [],
  excludeLowConfidence: false,
  testFileGlobs: [],
  intentionalPublicRouteGlobs: [],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asStringArray(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const out: string[] = [];
  for (const v of value) {
    if (typeof v === 'string' && v.length > 0) {
      out.push(v);
    }
  }
  return out;
}

export async function loadInspectorConfig(cwd: string): Promise<InspectorConfig> {
  const path = join(cwd, 'project-inspector.config.json');
  try {
    const raw = await readFile(path, 'utf8');
    const parsed: unknown = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return DEFAULT_INSPECTOR_CONFIG;
    }
    const ignorePathGlobs = asStringArray(parsed.ignorePathGlobs) ?? [...DEFAULT_INSPECTOR_CONFIG.ignorePathGlobs];
    const suppressIssueIds = asStringArray(parsed.suppressIssueIds) ?? [];
    const suppressTitleSubstrings = asStringArray(parsed.suppressTitleSubstrings) ?? [];
    const excludeLowConfidence =
      typeof parsed.excludeLowConfidence === 'boolean' ? parsed.excludeLowConfidence : false;
    let gates: InspectorConfig['gates'];
    if (isRecord(parsed.gates)) {
      const g = parsed.gates;
      gates = {
        ...(typeof g.minProductionReadiness === 'number' ? { minProductionReadiness: g.minProductionReadiness } : {}),
        ...(typeof g.minSecurityScore === 'number' ? { minSecurityScore: g.minSecurityScore } : {}),
      };
    }
    const testFileGlobs = asStringArray(parsed.testFileGlobs) ?? [];
    const intentionalPublicRouteGlobs = asStringArray(parsed.intentionalPublicRouteGlobs) ?? [];
    return {
      version: 1,
      ignorePathGlobs,
      suppressIssueIds,
      suppressTitleSubstrings,
      excludeLowConfidence,
      ...(gates !== undefined && Object.keys(gates).length > 0 ? { gates } : {}),
      ...(testFileGlobs.length > 0 ? { testFileGlobs } : {}),
      ...(intentionalPublicRouteGlobs.length > 0 ? { intentionalPublicRouteGlobs } : {}),
    };
  } catch {
    return DEFAULT_INSPECTOR_CONFIG;
  }
}
