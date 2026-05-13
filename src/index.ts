/**
 * Public API for `project-inspector`.
 *
 * @example
 * ```ts
 * import { runScan, computeScores } from 'project-inspector';
 * const result = await runScan({ cwd: process.cwd(), outDir: './project-report', mode: 'deep', concurrency: 8 });
 * console.log(result.scores.productionReadiness);
 * ```
 *
 * @module
 */

/** Core type shapes. Unchanged across minor versions. */
export type { CheckResult, Issue, ScanMode, ScanOptions, ScanResult, Severity } from './core/types.js';

/** Evaluate a ScanResult against gate thresholds and return a pass/fail CheckResult. */
export { evaluateCheckGates, runCheckGate } from './core/check-gate.js';

/** Delete all files inside the report output directory. */
export { clearProjectReportDir } from './core/clear-project-report.js';

/** Download a fresh copy of the bundled vulnerability database. */
export { downloadVulnDbOverride } from './core/update-vuln-db.js';

/**
 * Scoring helpers — all are pure functions with no side-effects.
 *
 * - `computeScores` — deducts per-issue across axes, returns a `Scores` object.
 * - `buildScoreDiagnostics` — per-axis hit counts for human-readable explanations.
 * - `computeHotspots` — top-10 issues ranked by exploitability heuristic.
 * - `computeSegmentScores` — per top-level folder breakdown (monorepo-friendly).
 */
export {
  buildScoreDiagnostics,
  computeHotspots,
  computeScores,
  computeSegmentScores,
} from './core/scoring-engine.js';

/**
 * Run a full project scan.
 * Returns a `ScanResult` with scores, trusted issues, production decision, and all engine outputs.
 */
export { runScan, defaultReportDir } from './core/scan-runner.js';

/** The three structured report section keys: `'api' | 'architecture' | 'database'`. */
export type { ReportSection } from './reports/writers.js';

/** Write all scan artifacts (JSON, Markdown, SARIF, SBOM, OpenAPI) into `outDir`. */
export { writeScanArtifacts } from './reports/writers.js';

/** Write a SARIF 2.1.0 report from a completed ScanResult. */
export { writeSarifReport } from './reports/sarif-writer.js';
