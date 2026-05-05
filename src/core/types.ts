export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ComplianceFramework = 'OWASP_TOP_10' | 'SANS_TOP_25' | 'GDPR' | 'HIPAA' | 'INDIA_IT';

export interface ComplianceTag {
  readonly framework: ComplianceFramework;
  readonly ruleId: string;
  readonly ruleName: string;
}

export type IssueCategory =
  | 'security'
  | 'performance'
  | 'memory'
  | 'quality'
  | 'architecture'
  | 'dependency'
  | 'lint'
  | 'inventory'
  | 'test'
  | 'migration'
  | 'api'
  | 'database'
  | 'env';

export type IssueConfidence = 'high' | 'medium' | 'low';

export type FrameworkTag =
  | 'nestjs'
  | 'express'
  | 'nextjs'
  | 'react'
  | 'angular'
  | 'vue'
  | 'fastify'
  | 'svelte'
  | 'node'
  | 'unknown';

export type WorkspaceProjectRole = 'root' | 'app' | 'package' | 'service' | 'micro-frontend' | 'workspace';

export interface WorkspaceProject {
  readonly name: string;
  readonly rootDir: string;
  readonly relPath: string;
  readonly packageJsonPath: string;
  readonly role: WorkspaceProjectRole;
  readonly primaryFramework: FrameworkTag;
  readonly frameworks: readonly FrameworkTag[];
  readonly runtime: 'node' | 'browser' | 'hybrid' | 'unknown';
  readonly packageManager: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  readonly entryPoints: readonly string[];
}

export interface Issue {
  readonly id: string;
  readonly engine: string;
  readonly severity: Severity;
  readonly title: string;
  readonly file: string;
  readonly line: number;
  readonly description: string;
  readonly impact: string;
  readonly fix: string;
  readonly column?: number;
  readonly code?: string;
  readonly compliance?: readonly ComplianceTag[];
  /** Top-level grouping for summaries + hotspots. */
  readonly category?: IssueCategory;
  /** Framework this finding is specific to (when known). */
  readonly framework?: FrameworkTag;
  /** ≤140-char plain-language explanation for non-experts / AI. */
  readonly whyItMatters?: string;
  /** 1–3 lines of real source with the offending line marked `>`. */
  readonly codeSnippet?: string;
  /** Rule confidence: high = deterministic, medium = heuristic, low = best-effort. */
  readonly confidence?: IssueConfidence;
  /** How many times this exact rule matched on this file (dedup representative). */
  readonly count?: number;
  /** First line in the file where this rule matched. */
  readonly firstLine?: number;
  /** Last line in the file where this rule matched. */
  readonly lastLine?: number;
  /** Estimated event-loop blocking impact text, set by performance engine. */
  readonly whyItBlocks?: string;
}

export interface FunctionInfo {
  readonly name: string;
  readonly file: string;
  readonly line: number;
  readonly complexity: number;
  readonly maxNesting: number;
  readonly lineCount: number;
}

export interface ImportEdge {
  readonly from: string;
  readonly to: string;
  readonly specifier: string;
}

export interface AstScanResult {
  readonly filesAnalyzed: number;
  readonly functions: readonly FunctionInfo[];
  readonly issues: readonly Issue[];
  readonly importGraph: readonly ImportEdge[];
  readonly circularDependencyChains: readonly string[][];
}

export interface SecurityScanResult {
  readonly issues: readonly Issue[];
}

export interface DependencyScanResult {
  readonly issues: readonly Issue[];
  readonly lockfileKind: 'npm' | 'pnpm' | 'yarn' | 'none';
  readonly directDependencyCount: number;
  readonly projectManifestCount?: number;
  readonly auditSummary?: {
    readonly critical: number;
    readonly high: number;
    readonly moderate: number;
    readonly low: number;
    readonly info: number;
  };
}

export interface ApiRouteInfo {
  readonly method: string;
  readonly pathPattern: string;
  readonly file: string;
  readonly line: number;
  readonly authHeuristic: 'unknown' | 'likely-protected' | 'likely-open';
  /**
   * Higher-level access model for endpoint inventory.
   * - public: intentionally open endpoint (health/login/webhook/etc.)
   * - authenticated: requires auth but no explicit role claim detected
   * - role-based: explicit role/permission guard signal detected
   * - unknown: not enough static evidence either way
   */
  readonly accessClassification?: 'public' | 'authenticated' | 'role-based' | 'unknown';
  readonly validationHeuristic: 'unknown' | 'likely-present' | 'likely-missing';
}

export interface ApiScanResult {
  readonly issues: readonly Issue[];
  readonly routes: readonly ApiRouteInfo[];
}

export interface EnvScanResult {
  readonly issues: readonly Issue[];
  readonly envFiles: readonly string[];
  readonly keysFound: readonly string[];
}

export interface ArchitectureScanResult {
  readonly issues: readonly Issue[];
}

export interface PerformanceScanResult {
  readonly issues: readonly Issue[];
}

export interface MemoryScanResult {
  readonly issues: readonly Issue[];
}

export interface CodeSmellScanResult {
  readonly issues: readonly Issue[];
}

export interface MigrationScanResult {
  readonly issues: readonly Issue[];
}

export interface OutdatedDepsScanResult {
  readonly issues: readonly Issue[];
  readonly outdatedDirectCount: number;
  readonly majorGapCount: number;
  readonly deprecatedCount: number;
}

export interface TestCoverageScanResult {
  readonly issues: readonly Issue[];
  readonly testFileCount: number;
  readonly sourceFileCount: number;
  readonly ratioApprox: number;
  readonly uncoveredEntryHints: readonly string[];
  readonly testDetection?: {
    /** Exact glob patterns used for test-file discovery in this scan. */
    readonly globs: readonly string[];
    /** Paths ignored when running test-file discovery. */
    readonly ignore: readonly string[];
    /** Small sample of matched test file paths, relative to project root. */
    readonly matchedSample: readonly string[];
  };
}

/** Parsed schema hints (Prisma / ORM / SQL DDL / inventory) for diagrams and maps — heuristic only. */
export interface DatabaseIntelligence {
  readonly sources: readonly ('prisma' | 'typeorm' | 'mongoose' | 'sql' | 'inventory')[];
  readonly models: readonly {
    readonly name: string;
    readonly source: 'prisma' | 'typeorm' | 'mongoose' | 'sql' | 'inventory';
    readonly fields: readonly { readonly name: string; readonly typeToken: string }[];
  }[];
  readonly relations: readonly {
    readonly from: string;
    readonly to: string;
    readonly cardinality: '1:1' | '1:N' | 'N:1' | 'N:N' | 'unknown';
  }[];
  readonly indexingHints: readonly string[];
}

export interface DatabaseAnalysisResult {
  readonly issues: readonly Issue[];
  readonly ormSignals: readonly string[];
  readonly rawSqlFileCount: number;
  readonly intelligence?: DatabaseIntelligence;
}

export type FileKind =
  | 'controller'
  | 'service'
  | 'repository'
  | 'route'
  | 'middleware'
  | 'component'
  | 'page'
  | 'layout'
  | 'hook'
  | 'store'
  | 'module'
  | 'guard'
  | 'interceptor'
  | 'pipe'
  | 'dto'
  | 'entity'
  | 'schema'
  | 'config'
  | 'migration'
  | 'test'
  | 'util'
  | 'type'
  | 'style'
  | 'other';

export interface InventoryFile {
  readonly path: string;
  readonly relPath: string;
  readonly kind: FileKind;
  readonly loc: number;
  readonly bytes: number;
  readonly framework?: FrameworkTag;
  readonly exportsCount?: number;
}

export interface InventoryScanResult {
  readonly issues: readonly Issue[];
  readonly files: readonly InventoryFile[];
  readonly profile: ProjectProfile;
  readonly kindCounts: Readonly<Record<FileKind, number>>;
  readonly totalLoc: number;
}

export interface LintScanResult {
  readonly issues: readonly Issue[];
  readonly eslintAvailable: boolean;
  readonly tscAvailable: boolean;
  readonly prettierAvailable: boolean;
  readonly eslintErrorCount: number;
  readonly eslintWarningCount: number;
  readonly tscErrorCount: number;
  readonly prettierUnformattedCount: number;
  readonly skippedReason?: string;
  readonly durationMs: number;
}

export interface ProjectProfile {
  readonly primaryFramework: FrameworkTag;
  readonly frameworks: readonly FrameworkTag[];
  readonly hasTypescript: boolean;
  readonly hasJsx: boolean;
  readonly runtime: 'node' | 'browser' | 'hybrid' | 'unknown';
  readonly packageManager: 'npm' | 'pnpm' | 'yarn' | 'unknown';
  readonly entryPoints: readonly string[];
  readonly topology?: 'single' | 'monorepo' | 'microservices' | 'micro-frontend' | 'multi-project';
  readonly projects?: readonly WorkspaceProject[];
}

export interface HotspotItem {
  readonly rank: number;
  readonly severity: Severity;
  readonly title: string;
  readonly file: string;
  readonly line: number;
  readonly engine: string;
  readonly impact: string;
  readonly fixHint: string;
  /** Plain-language root cause for decision-style reports. */
  readonly rootCause?: string;
  /** How to prove the fix (tests, scan, audit). */
  readonly verifyStep?: string;
  /** Heuristic exploit narrative (input → sink). */
  readonly attackChain?: string;
}

export type ProductionVerdict = 'READY' | 'NOT_READY';

export interface ProductionDecisionTopItem {
  readonly rank: number;
  readonly severity: Severity;
  readonly relFile: string;
  readonly line: number;
  readonly title: string;
  readonly engine: string;
  readonly rootCause: string;
  readonly fix: string;
  readonly verify: string;
  /** Heuristic input → processing → sink line for exploit thinking. */
  readonly attackChain: string;
}

export interface ProductionDecision {
  readonly verdict: ProductionVerdict;
  readonly confidenceNote: string;
  readonly blockers: readonly string[];
  readonly quickWins: readonly string[];
  readonly majorRisks: readonly string[];
  readonly nextSteps: readonly string[];
  readonly topCritical: readonly ProductionDecisionTopItem[];
  readonly gateOk: boolean;
  readonly readinessScore: number;
}

/** `quick` = core engines only; `deep` = all engines; `diff` = deep + git-changed files only. */
export type ScanMode = 'quick' | 'deep' | 'diff';

export interface ScanOptions {
  readonly cwd: string;
  readonly outDir: string;
  readonly concurrency: number;
  readonly mode: ScanMode;
  /** When true, run npm audit (requires network + npm). Ignored in `quick` mode. */
  readonly online: boolean;
  /** When true, restrict analysis to git-changed files. For `diff` mode this is forced on. */
  readonly incremental: boolean;
  /**
   * When true, ignore disk caches and git-scoped incremental analysis — full workspace pass
   * (same effect as `--no-cache` with incremental off).
   */
  readonly rescan?: boolean;
  /**
   * When not false (default), skip per-file engines for unchanged content (see
   * `project-report/.cache/file-hashes.json`). Git `--incremental` / `diff` disables AST cache merge.
   */
  readonly useFileCache?: boolean;
  /** Suppress vuln DB staleness hints and automatic refresh attempts. */
  readonly offline?: boolean;
  /** Best-effort refresh of vuln override DB before dependency scan (requires network). */
  readonly autoUpdateDb?: boolean;
  /** Extra scan outputs (markdown reports always written). */
  readonly outputFormat?: 'md' | 'json' | 'sarif';
  /** Soft budget in milliseconds; a warning is surfaced if exceeded. */
  readonly budgetMs?: number;
  /** When true, skip ESLint / tsc / Prettier lint engine even if tools are installed. */
  readonly skipLint?: boolean;
  /** After scan, overwrite trusted-issue fingerprint baseline in `project-report/.cache/` for delta views. */
  readonly saveBaseline?: boolean;
}

/** Delta vs last `--save-baseline` snapshot (trusted fingerprints). */
export interface BaselineComparison {
  readonly baselineSavedAt: string;
  readonly newCount: number;
  readonly resolvedCount: number;
  readonly unchangedCount: number;
}

export interface Scores {
  /** 0–100 */
  readonly security: number;
  readonly performance: number;
  readonly codeQuality: number;
  readonly compliance: number;
  /** Test posture and test-engine signals (0–100). */
  readonly tests: number;
  /** 0–100 weighted gate */
  readonly productionReadiness: number;
}

/** Per-axis trusted-issue counts so 0 scores are not mistaken for “unscored”. */
export interface ScoreAxisDiagnostics {
  readonly contributingTrustedIssueCount: number;
  readonly enginesRepresented: readonly string[];
}

export interface ScoreDiagnostics {
  readonly version: 1;
  readonly axes: {
    readonly security: ScoreAxisDiagnostics;
    readonly performance: ScoreAxisDiagnostics;
    readonly codeQuality: ScoreAxisDiagnostics;
    readonly compliance: ScoreAxisDiagnostics;
    readonly tests: ScoreAxisDiagnostics;
  };
  /** Human-readable blend formula and interpretation of low scores. */
  readonly readinessWeightNotes: string;
}

export interface EngineTiming {
  readonly engine: string;
  readonly ms: number;
}

export interface ScanResult {
  readonly cwd: string;
  readonly outDir: string;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly mode: ScanMode;
  readonly incremental: boolean;
  readonly online: boolean;
  readonly ast: AstScanResult;
  readonly security: SecurityScanResult;
  readonly dependency: DependencyScanResult;
  readonly outdated: OutdatedDepsScanResult;
  readonly tests: TestCoverageScanResult;
  readonly database: DatabaseAnalysisResult;
  readonly hotspots: readonly HotspotItem[];
  readonly api: ApiScanResult;
  readonly env: EnvScanResult;
  readonly architecture: ArchitectureScanResult;
  readonly performance: PerformanceScanResult;
  readonly memory: MemoryScanResult;
  readonly codeSmell: CodeSmellScanResult;
  readonly migration: MigrationScanResult;
  readonly inventory: InventoryScanResult;
  readonly lint: LintScanResult;
  readonly scores: Scores;
  /** CI gate thresholds from config (defaults applied in scan-runner). */
  readonly gateThresholds?: {
    readonly minProductionReadiness: number;
    readonly minSecurityScore: number;
  };
  /**
   * Issues after suppressions, path ignores, optional low-confidence drop, and dedupe.
   * Used for scoring, CI gate critical loop, hotspots, SARIF, and decision docs.
   */
  readonly trustedIssues?: readonly Issue[];
  /** Trusted-issue counts per score axis (explains low or 0 axis scores). */
  readonly scoreDiagnostics?: ScoreDiagnostics;
  /** When a baseline file exists, compares trusted fingerprints to the last `--save-baseline` run. */
  readonly baselineComparison?: BaselineComparison;
  /** Structured production readiness answer (see `production-decision.md`). */
  readonly productionDecision?: ProductionDecision;
  readonly timings?: readonly EngineTiming[];
  readonly profile?: ProjectProfile;
  readonly totalDurationMs?: number;
  readonly budgetMs?: number;
  readonly budgetExceeded?: boolean;
}

export interface CheckFailure {
  readonly file: string;
  readonly line: number;
  readonly reason: string;
  readonly fix: string;
}

export interface CheckResult {
  readonly ok: boolean;
  readonly failures: readonly CheckFailure[];
}
