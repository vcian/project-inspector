export type { CheckResult, Issue, ScanMode, ScanOptions, ScanResult, Severity } from './core/types.js';
export { evaluateCheckGates, runCheckGate } from './core/check-gate.js';
export { clearProjectReportDir } from './core/clear-project-report.js';
export { downloadVulnDbOverride } from './core/update-vuln-db.js';
export { buildScoreDiagnostics, computeHotspots, computeScores } from './core/scoring-engine.js';
export { runScan, defaultReportDir } from './core/scan-runner.js';
export type { ReportSection } from './reports/writers.js';
export { writeScanArtifacts } from './reports/writers.js';
export { writeSarifReport } from './reports/sarif-writer.js';
