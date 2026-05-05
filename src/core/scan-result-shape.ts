/* eslint-disable @typescript-eslint/no-unnecessary-condition -- older merged-scan.json may omit new keys */
import type {
  DatabaseAnalysisResult,
  FileKind,
  InventoryScanResult,
  LintScanResult,
  OutdatedDepsScanResult,
  ProjectProfile,
  ScanResult,
  TestCoverageScanResult,
} from './types.js';

export const EMPTY_OUTDATED: OutdatedDepsScanResult = {
  issues: [],
  outdatedDirectCount: 0,
  majorGapCount: 0,
  deprecatedCount: 0,
};

export const EMPTY_TESTS: TestCoverageScanResult = {
  issues: [],
  testFileCount: 0,
  sourceFileCount: 0,
  ratioApprox: 0,
  uncoveredEntryHints: [],
};

export const EMPTY_DATABASE: DatabaseAnalysisResult = {
  issues: [],
  ormSignals: [],
  rawSqlFileCount: 0,
};

export const EMPTY_PROFILE: ProjectProfile = {
  primaryFramework: 'unknown',
  frameworks: [],
  hasTypescript: false,
  hasJsx: false,
  runtime: 'unknown',
  packageManager: 'unknown',
  entryPoints: [],
  topology: 'single',
  projects: [],
};

const EMPTY_KIND_COUNTS: Readonly<Record<FileKind, number>> = {
  controller: 0,
  service: 0,
  repository: 0,
  route: 0,
  middleware: 0,
  component: 0,
  page: 0,
  layout: 0,
  hook: 0,
  store: 0,
  module: 0,
  guard: 0,
  interceptor: 0,
  pipe: 0,
  dto: 0,
  entity: 0,
  schema: 0,
  config: 0,
  migration: 0,
  test: 0,
  util: 0,
  type: 0,
  style: 0,
  other: 0,
};

export const EMPTY_INVENTORY: InventoryScanResult = {
  issues: [],
  files: [],
  profile: EMPTY_PROFILE,
  kindCounts: EMPTY_KIND_COUNTS,
  totalLoc: 0,
};

export const EMPTY_LINT: LintScanResult = {
  issues: [],
  eslintAvailable: false,
  tscAvailable: false,
  prettierAvailable: false,
  eslintErrorCount: 0,
  eslintWarningCount: 0,
  tscErrorCount: 0,
  prettierUnformattedCount: 0,
  durationMs: 0,
};

/** Backfill fields introduced after older `merged-scan.json` caches. */
export function ensureScanShape(raw: ScanResult): ScanResult {
  const scores =
    typeof raw.scores.tests === 'number'
      ? raw.scores
      : {
          ...raw.scores,
          /** Older caches had no dedicated test axis; approximate from code quality. */
          tests: raw.scores.codeQuality,
        };
  return {
    ...raw,
    scores,
    outdated: raw.outdated ?? { ...EMPTY_OUTDATED },
    tests: raw.tests ?? { ...EMPTY_TESTS, uncoveredEntryHints: [...EMPTY_TESTS.uncoveredEntryHints] },
    database: raw.database ?? { ...EMPTY_DATABASE, ormSignals: [...EMPTY_DATABASE.ormSignals] },
    hotspots: raw.hotspots ?? [],
    inventory: raw.inventory ?? { ...EMPTY_INVENTORY, files: [], profile: { ...EMPTY_PROFILE } },
    lint: raw.lint ?? { ...EMPTY_LINT },
    ...(raw.trustedIssues !== undefined ? { trustedIssues: raw.trustedIssues } : {}),
    ...(raw.productionDecision !== undefined ? { productionDecision: raw.productionDecision } : {}),
    ...(raw.baselineComparison !== undefined ? { baselineComparison: raw.baselineComparison } : {}),
  };
}

/* eslint-enable @typescript-eslint/no-unnecessary-condition */
