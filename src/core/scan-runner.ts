import { mkdir, readFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, normalize, resolve } from 'node:path';
import { JsxEmit, ScriptTarget } from 'typescript';
import { Project as MorphProject } from 'ts-morph';

import { loadAstByFileMap, saveAstByFileMap } from '../engines/ast-cache-io.js';
import {
  runAstEngineWithAnalyses,
  type AstEngineOptions,
  type AstEngineRun,
  type FileAstAnalysis,
} from '../engines/ast-engine.js';
import { runArchitectureEngine } from '../engines/architecture-engine.js';
import { runArchitecturePolicyEngine } from '../engines/arch-policy-engine.js';
import { runApiEngine } from '../engines/api-engine.js';
import { enrichAllIssues } from '../engines/compliance-mapper.js';
import { runCodeSmellEngine } from '../engines/code-smell-engine.js';
import { extractDatabaseIntelligence } from '../engines/database-intel.js';
import { mergeDatabaseResults, runDatabaseEngineOnFile } from '../engines/database-engine.js';
import { runDependencyEngine } from '../engines/dependency-engine.js';
import { runEnvEngine } from '../engines/env-engine.js';
import { runInventoryEngine } from '../engines/inventory-engine.js';
import { runLintEngine } from '../engines/lint-engine.js';
import { runMemoryEngine } from '../engines/memory-engine.js';
import { runMigrationEngine } from '../engines/migration-engine.js';
import { runPolyglotEngine } from '../engines/polyglot-engine.js';
import { runOutdatedEngine } from '../engines/outdated-engine.js';
import { runPerformanceEngine } from '../engines/performance-engine.js';
import { runSecurityEngine, type SecurityEngineOptions } from '../engines/security-engine.js';
import { runSelfCheckEngine } from '../engines/self-check-engine.js';
import { runTestEngine } from '../engines/test-engine.js';
import { resolvePrCommentScope } from '../reports/pr-comment.js';
import { writeScanArtifacts, writeScanReports, writeScanReportsPartial, type ReportSection } from '../reports/writers.js';
import { runPool } from '../utils/async-pool.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { detectProjectProfile } from '../utils/detect-project.js';
import { getGitChangedPaths } from '../utils/git-incremental.js';
import { logger } from '../utils/logger.js';
import { ScanProgress } from '../utils/progress.js';
import { createSerialQueue } from '../utils/serial-queue.js';
import { buildDependencySnapshot, snapshotsEqual, type DependencySnapshotV1 } from './dependency-snapshot.js';
import { buildEnvHashes, type EnvHashes } from './env-snapshot.js';
import { sha256File, sha256String } from './file-hash.js';
import { tryReadLcovSummary } from './coverage-ingest.js';
import {
  compareTrustedToBaseline,
  loadBaselineHistory,
  loadBaselineTrusted,
  saveBaselineTrusted,
} from './baseline.js';
import { buildAttackChainNarrative } from './attack-chain.js';
import { buildProductionDecision } from './decision-engine.js';
import { collectPluginSuppressPatterns } from '../plugins/manifest-loader.js';
import { loadInspectorConfig, type InspectorConfig } from './inspector-config.js';
import { mergePolicyPack } from './policy-packs.js';
import { applyIssuePipeline } from './issue-pipeline.js';
import { gatherAllIssues } from './issue-collect.js';
import { mergeApiRoutes, mergeIssuesByReanalyze } from './issue-merge.js';
import { relKey } from './rel-path.js';
import {
  EMPTY_INVENTORY,
  EMPTY_LINT,
  EMPTY_OUTDATED,
  EMPTY_TESTS,
  ensureScanShape,
} from './scan-result-shape.js';
import {
  clearScanInterruptedMarker,
  loadDependencySnapshot,
  loadEnvSnapshot,
  loadFileContentsBundle,
  loadFileHashes,
  loadMergedScan,
  loadScanInterrupted,
  saveDependencySnapshot,
  saveEnvSnapshot,
  saveFileContentsBundle,
  saveFileHashes,
  saveMergedScan,
  saveScanMeta,
  writeScanInterruptedMarker,
} from './scan-cache.js';
import {
  activateScanMetrics,
  buildScoreDiagnostics,
  computeHotspots,
  computeScores,
  createScanMetrics,
  deduplicateIssues,
  notePipelineAndDedupedCounts,
  noteRawGatherIssueCount,
  type ScanReportingMetrics,
} from './scoring-engine.js';
import type {
  ApiScanResult,
  ArchitectureScanResult,
  AstScanResult,
  CodeSmellScanResult,
  DependencyScanResult,
  DatabaseAnalysisResult,
  EngineTiming,
  EnvScanResult,
  HotspotItem,
  InventoryScanResult,
  Issue,
  LintScanResult,
  MemoryScanResult,
  MigrationScanResult,
  OutdatedDepsScanResult,
  PerformanceScanResult,
  ProjectProfile,
  ScanOptions,
  ScanResult,
  SecurityScanResult,
  TestCoverageScanResult,
} from './types.js';
import { tryAutoUpdateVulnDb } from './vuln-auto-update.js';
import { redactScanResultForStorage } from '../report/redact-evidence.js';
import { parseJson, isDependencySnapshotV1, isVulnDbMeta } from '../utils/type-guards.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const EMPTY_API: ApiScanResult = { issues: [], routes: [] };
const EMPTY_ENV: EnvScanResult = { issues: [], envFiles: [], keysFound: [] };
const EMPTY_PERFORMANCE: PerformanceScanResult = { issues: [] };
const EMPTY_MEMORY: MemoryScanResult = { issues: [] };
const EMPTY_CODE_SMELL: CodeSmellScanResult = { issues: [] };
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BUNDLE_BYTES = 20 * 1024 * 1024; // 20 MB

export type CacheMode = 'full-reuse' | 'shallow-reuse' | 'incremental' | 'cold-start';

// ─── Intermediate pipeline types ─────────────────────────────────────────────

export interface CacheState {
  readonly previousHashes: Record<string, string>;
  readonly previousMerged: ScanResult | undefined;
  readonly previousEnv: EnvHashes | undefined;
  readonly previousContents: Record<string, string> | undefined;
  readonly previousDep: DependencySnapshotV1 | undefined;
  readonly astByFileMap: Map<string, FileAstAnalysis>;
  readonly coldStart: boolean;
}

export interface FileState {
  readonly normalizedFiles: readonly string[];
  readonly fileSet: ReadonlySet<string>;
  readonly currentHashes: Record<string, string>;
  readonly dirtyFiles: ReadonlySet<string>;
  readonly reanalyzedFiles: ReadonlySet<string>;
  readonly contents: Map<string, string>;
  readonly sizes: Map<string, number>;
  readonly cacheMode: CacheMode;
  readonly dependencyDirty: boolean;
  readonly envDirty: boolean;
  readonly removedFiles: boolean;
  readonly diffFilter: ReadonlySet<string> | undefined;
  readonly dependencySnapshotNow: DependencySnapshotV1 | null;
  readonly envSnapshotNow: EnvHashes;
}

export interface RawEngineOutput {
  readonly ast: AstScanResult;
  readonly astAnalyses: readonly FileAstAnalysis[];
  readonly security: SecurityScanResult;
  readonly dependency: DependencyScanResult;
  readonly outdated: OutdatedDepsScanResult;
  readonly migration: MigrationScanResult;
  readonly tests: TestCoverageScanResult;
  readonly api: ApiScanResult;
  readonly env: EnvScanResult;
  readonly performance: PerformanceScanResult;
  readonly memory: MemoryScanResult;
  readonly codeSmell: CodeSmellScanResult;
  readonly architecture: ArchitectureScanResult;
  readonly database: DatabaseAnalysisResult;
  readonly inventory: InventoryScanResult;
  readonly lint: LintScanResult;
}

// ─── Small helpers ────────────────────────────────────────────────────────────

interface TimingsRecorder {
  readonly timings: readonly EngineTiming[];
  readonly push: (entry: EngineTiming) => void;
  readonly record: <T>(name: string, work: () => Promise<T> | T) => Promise<T>;
}

function createTimingsRecorder(): TimingsRecorder {
  const timings: EngineTiming[] = [];
  return {
    timings,
    push(entry) { timings.push(entry); },
    async record<T>(name: string, work: () => Promise<T> | T): Promise<T> {
      const started = Date.now();
      try {
        return await Promise.resolve(work());
      } finally {
        timings.push({ engine: name, ms: Date.now() - started });
      }
    },
  };
}

function issueFromCrash(engine: string, cwd: string, error: unknown): Issue {
  const message = error instanceof Error ? error.message : String(error);
  return {
    id: `${engine}:engine-crash`,
    engine,
    severity: 'MEDIUM',
    title: `${engine} engine failed and was skipped`,
    file: join(cwd, 'package.json'),
    line: 1,
    description: message,
    impact: 'This engine returned a fallback result, so the scan completed with reduced coverage.',
    fix: 'Inspect the engine error in logs and re-run the scan after fixing the underlying issue.',
    category: 'quality',
    confidence: 'high',
  };
}

async function guarded<T>(
  engine: string,
  cwd: string,
  work: () => Promise<T>,
  fallback: (issue: Issue) => T,
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    logger.warn({ engine, err: error }, 'engine failed');
    return fallback(issueFromCrash(engine, cwd, error));
  }
}

/** Lightweight scan fingerprint — avoids serializing the entire ScanResult. */
export function scanFingerprint(r: ScanResult): string {
  return sha256String([
    String(r.ast.filesAnalyzed),
    String(r.trustedIssues?.length ?? 0),
    String(r.scores.productionReadiness),
    r.finishedAt,
  ].join('::'));
}

function gateThresholdsFromConfig(config: InspectorConfig): NonNullable<ScanResult['gateThresholds']> {
  return {
    minProductionReadiness: config.gates?.minProductionReadiness ?? 48,
    minSecurityScore: config.gates?.minSecurityScore ?? 50,
  };
}

function hotspotItems(issues: readonly Issue[]): ScanResult['hotspots'] {
  return issues.map((issue, index): HotspotItem => ({
    rank: index + 1,
    severity: issue.severity,
    title: issue.title,
    file: issue.file,
    line: issue.line,
    engine: issue.engine,
    impact: issue.impact,
    fixHint: issue.fix,
    rootCause: issue.whyItMatters ?? issue.description,
    verifyStep: issue.engine === 'lint'
      ? 'Run lint/typecheck until clean; re-scan.'
      : issue.engine === 'dependency' || issue.engine === 'outdated'
        ? 'Update dependency / lockfile; re-run audit and scan.'
        : 'Add or run targeted tests for the module; re-run project-inspector.',
    attackChain: buildAttackChainNarrative(issue),
  }));
}

async function readDependencySnapshotAlias(outDir: string): Promise<DependencySnapshotV1 | undefined> {
  const primary = await loadDependencySnapshot(outDir);
  if (primary !== undefined) return primary;
  const aliasPath = join(outDir, '.cache', 'dep-snapshot.json');
  if (!existsSync(aliasPath)) return undefined;
  try {
    const raw = await readFile(aliasPath, 'utf8');
    return parseJson(raw, isDependencySnapshotV1, undefined as unknown as DependencySnapshotV1);
  } catch {
    return undefined;
  }
}

async function warnOnVulnDbStaleness(outDir: string, offline: boolean | undefined): Promise<void> {
  if (offline === true) return;
  const metaPath = join(outDir, '.cache', 'vuln-db-meta.json');
  if (!existsSync(metaPath)) return;
  try {
    const raw = await readFile(metaPath, 'utf8');
    const parsed = parseJson(raw, isVulnDbMeta, {});
    if (typeof parsed.fetchedAt !== 'string') return;
    const fetchedAt = Date.parse(parsed.fetchedAt);
    if (Number.isNaN(fetchedAt) || Date.now() - fetchedAt <= SEVEN_DAYS_MS) return;
    logger.warn({ fetchedAt: parsed.fetchedAt }, 'vulnerability DB metadata is older than 7 days; run update-vuln-db or use --auto-update-db');
  } catch (error) {
    logger.debug({ err: error }, 'failed to read vulnerability DB metadata');
  }
}

function computeTouchedSections(args: {
  readonly coldStart: boolean;
  readonly hadRemovedFiles: boolean;
  readonly astDirty: boolean;
  readonly depDirty: boolean;
  readonly envDirty: boolean;
  readonly partialFilesChanged: boolean;
  readonly mode: ScanOptions['mode'];
}): ReadonlySet<ReportSection> {
  if (args.coldStart || args.hadRemovedFiles) {
    return new Set<ReportSection>(['api', 'architecture', 'database']);
  }
  const touched = new Set<ReportSection>();
  if (args.astDirty || args.partialFilesChanged) {
    touched.add('architecture');
    if (args.mode !== 'quick') { touched.add('api'); touched.add('database'); }
  }
  touched.add('database');
  return touched;
}

// ─── Stage 1: resolveCache ────────────────────────────────────────────────────

export async function resolveCache(options: Pick<ScanOptions, 'cwd' | 'outDir' | 'rescan' | 'useFileCache'>): Promise<CacheState> {
  const { outDir, cwd } = options;
  const skipCache = options.rescan === true || options.useFileCache === false;

  const [previousHashesFile, previousMergedRaw, previousEnv, previousContents, interrupted, previousDep, astByFileMap] =
    await Promise.all([
      skipCache ? Promise.resolve(undefined) : loadFileHashes(outDir),
      skipCache ? Promise.resolve(undefined) : loadMergedScan(outDir),
      skipCache ? Promise.resolve(undefined) : loadEnvSnapshot(outDir),
      skipCache ? Promise.resolve(undefined) : loadFileContentsBundle(outDir),
      skipCache ? Promise.resolve(false) : loadScanInterrupted(outDir),
      skipCache ? Promise.resolve(undefined) : readDependencySnapshotAlias(outDir),
      skipCache ? Promise.resolve(new Map<string, FileAstAnalysis>()) : loadAstByFileMap(outDir, cwd),
    ]);

  const previousMerged = previousMergedRaw ? ensureScanShape(previousMergedRaw) : undefined;
  const coldStart = skipCache || previousMerged === undefined || interrupted;

  return {
    previousHashes: previousHashesFile?.hashes ?? {},
    previousMerged,
    previousEnv,
    previousContents,
    previousDep,
    astByFileMap,
    coldStart,
  };
}

// ─── Stage 2: discoverAndHash ─────────────────────────────────────────────────

export async function discoverAndHash(
  options: ScanOptions,
  cache: CacheState,
  timings: TimingsRecorder,
  progress?: ScanProgress,
): Promise<FileState> {
  const { cwd, outDir, concurrency } = options;
  const incrementalMode = options.rescan === true ? false : options.mode === 'diff' || options.incremental;

  const sourceFiles = await timings.record('discover-files', () => discoverSourceFiles(cwd));
  const normalizedFiles = sourceFiles.map((file) => normalize(file));
  const fileSet = new Set<string>(normalizedFiles);
  const n = normalizedFiles.length;

  // Phase 1 — Hashing  (global 0 → 20%)
  progress?.beginPhase('Hashing', n, 0, 20);
  const hashPairs = await timings.record('file-hashes', () =>
    runPool(normalizedFiles, Math.max(1, concurrency), async (file) => {
      progress?.tick(file);
      return [relKey(cwd, file), await sha256File(file)] as const;
    }),
  );

  const currentHashes: Record<string, string> = Object.fromEntries(hashPairs);
  const { previousHashes, previousMerged, coldStart, previousContents } = cache;

  const dirtySet = new Set<string>();
  if (coldStart) {
    for (const f of normalizedFiles) dirtySet.add(f);
  } else {
    for (const f of normalizedFiles) {
      const k = relKey(cwd, f);
      if (previousHashes[k] !== currentHashes[k]) dirtySet.add(f);
    }
  }

  const removedFiles = Object.keys(previousHashes).some((k) => !(k in currentHashes));

  const online = options.mode === 'quick' ? false : options.online;

  if (options.autoUpdateDb === true && options.offline !== true) {
    await tryAutoUpdateVulnDb(outDir);
  }
  await warnOnVulnDbStaleness(outDir, options.offline);

  const dependencySnapshotNow = await buildDependencySnapshot(cwd, outDir);
  const previousDep = cache.previousDep;
  const dependencyDirty =
    coldStart ||
    dependencySnapshotNow === null ||
    previousDep === undefined ||
    !snapshotsEqual(previousDep, dependencySnapshotNow) ||
    (online && options.mode !== 'quick');

  const envSnapshotNow = await buildEnvHashes(cwd);
  const envDirty = coldStart || JSON.stringify(envSnapshotNow) !== JSON.stringify(cache.previousEnv ?? {});

  let diffFilter: Set<string> | undefined;
  if (incrementalMode) {
    const gitChangedPaths = await getGitChangedPaths(cwd);
    if (gitChangedPaths !== null && gitChangedPaths.length > 0) {
      const filtered = gitChangedPaths.map((f) => normalize(f)).filter((f) => fileSet.has(f));
      if (filtered.length > 0) diffFilter = new Set(filtered);
    }
  }

  const effectiveDirty = new Set<string>();
  for (const f of dirtySet) {
    if (diffFilter === undefined || diffFilter.has(f)) effectiveDirty.add(f);
  }

  const reanalyzedFiles =
    coldStart || diffFilter === undefined
      ? new Set<string>(coldStart ? normalizedFiles : effectiveDirty)
      : new Set<string>([...diffFilter].filter((f) => effectiveDirty.has(f)));

  const fullReuse =
    !coldStart &&
    previousMerged?.mode === options.mode &&
    !removedFiles &&
    dirtySet.size === 0 &&
    !dependencyDirty &&
    !envDirty &&
    !incrementalMode &&
    !online;

  const cacheMode: CacheMode = fullReuse ? 'full-reuse' : coldStart ? 'cold-start' : reanalyzedFiles.size > 0 ? 'incremental' : 'shallow-reuse';
  logger.debug({ cacheMode }, 'scan cache mode resolved');

  const contents = new Map<string, string>();
  const sizes = new Map<string, number>();
  if (!fullReuse) {
    // Phase 2 — Reading file contents  (global 20 → 40%)
    progress?.beginPhase('Reading', n, 20, 40);
    await timings.record('read-files', () =>
      runPool(normalizedFiles, Math.max(1, concurrency), async (file) => {
        progress?.tick(file);
        const key = relKey(cwd, file);
        const cached = previousContents?.[key];
        const unchanged = !coldStart && previousHashes[key] === currentHashes[key];
        if (unchanged && typeof cached === 'string') {
          contents.set(file, cached);
          sizes.set(file, Buffer.byteLength(cached, 'utf8'));
          return;
        }
        try {
          const [text, fileStat] = await Promise.all([readFile(file, 'utf8'), stat(file).catch(() => undefined)]);
          contents.set(file, text);
          sizes.set(file, fileStat?.size ?? Buffer.byteLength(text, 'utf8'));
        } catch {
          contents.set(file, '');
          sizes.set(file, 0);
        }
      }),
    );
  }

  return {
    normalizedFiles,
    fileSet,
    currentHashes,
    dirtyFiles: dirtySet,
    reanalyzedFiles,
    contents,
    sizes,
    cacheMode,
    dependencyDirty,
    envDirty,
    removedFiles,
    diffFilter,
    dependencySnapshotNow,
    envSnapshotNow,
  };
}

// ─── Stage 3: runEngines ──────────────────────────────────────────────────────


export async function runEngines(
  options: ScanOptions,
  fileState: FileState,
  cache: CacheState,
  config: InspectorConfig,
  profile: ProjectProfile,
  timings: TimingsRecorder,
  statusFn: (msg: string) => void,
  progress?: ScanProgress,
): Promise<RawEngineOutput> {
  const { cwd, concurrency } = options;
  const { normalizedFiles, fileSet, reanalyzedFiles, contents, sizes, cacheMode, dependencyDirty, diffFilter } = fileState;
  const { previousMerged, coldStart, astByFileMap } = cache;
  const shallowReuse = cacheMode === 'shallow-reuse';
  const online = options.mode === 'quick' ? false : options.online;

  const getSourceText = (file: string): string | undefined => contents.get(normalize(file));
  const morphProject = new MorphProject({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: { allowJs: true, checkJs: false, jsx: JsxEmit.ReactJSX, target: ScriptTarget.ES2022 },
  });
  const morph = { project: morphProject, runExclusive: createSerialQueue(), getSourceText };

  const baseOptions = { sourceFiles: normalizedFiles, getSourceText };
  const filteredOptions = diffFilter ? { ...baseOptions, fileFilter: diffFilter } : baseOptions;
  const astOptions: AstEngineOptions = { ...filteredOptions, ...(diffFilter ? { partial: true } : {}), morph };
  const securityOptions: SecurityEngineOptions = { ...filteredOptions, morph, profile };

  const n = normalizedFiles.length;
  // Phases 3–7 live in the 40–90% global range via progress.status(msg, jumpTo).
  const stat = (msg: string, jumpTo?: number): void => {
    if (progress) { progress.status(msg, jumpTo); } else { statusFn(msg); }
    logger.debug(msg);
  };

  // ── AST ──────────────────────────────────────────────────────────────────
  stat(`Analyzing code structure (${String(n)} files)...`, 42);
  const astRun = (override?: Partial<AstEngineOptions>): Promise<AstEngineRun> =>
    guarded('ast', cwd, () => runAstEngineWithAnalyses(cwd, concurrency, { ...astOptions, ...override }), (issue) => ({
      analyses: [], scan: { filesAnalyzed: 0, functions: [], issues: [issue], importGraph: [], circularDependencyChains: [] },
    }));

  let ast: AstScanResult = previousMerged?.ast ?? { filesAnalyzed: 0, functions: [], issues: [], importGraph: [], circularDependencyChains: [] };
  let astAnalyses: readonly FileAstAnalysis[] = [];
  let astDirty = coldStart || reanalyzedFiles.size > 0 || fileState.removedFiles;

  if (shallowReuse) {
    ast = previousMerged ? previousMerged.ast : ast;
    astDirty = false;
  } else if (!coldStart && astByFileMap.size > 0 && reanalyzedFiles.size > 0 && diffFilter === undefined && !fileState.removedFiles) {
    const inc = await timings.record('ast', () => astRun({ incremental: { dirtyPaths: reanalyzedFiles, cachedByFile: astByFileMap } }));
    ast = inc.scan; astAnalyses = inc.analyses;
  } else {
    const full = await timings.record('ast', () => astRun());
    ast = full.scan; astAnalyses = full.analyses;
  }

  // ── Security ─────────────────────────────────────────────────────────────
  stat(`Scanning security patterns (${String(n)} files)...`, 50);
  let security: SecurityScanResult;
  if (shallowReuse) {
    security = previousMerged ? previousMerged.security : { issues: [] };
  } else if (!coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length) {
    const fresh = await timings.record('security', () =>
      guarded('security', cwd, () => runSecurityEngine(cwd, concurrency, { ...securityOptions, pathsOverride: reanalyzedFiles }), (i) => ({ issues: [i] })));
    security = {
      issues: mergeIssuesByReanalyze(previousMerged ? previousMerged.security.issues : [], fileSet, reanalyzedFiles, fresh.issues),
    };
  } else {
    security = await timings.record('security', () =>
      guarded('security', cwd, () => runSecurityEngine(cwd, concurrency, securityOptions), (i) => ({ issues: [i] })));
  }

  // ── Dependency / outdated / migration ────────────────────────────────────
  stat('Checking dependencies...', 57);
  const [dependency, outdated, migration] = await Promise.all([
    dependencyDirty
      ? timings.record('dependency', () => guarded('dependency', cwd, () => runDependencyEngine(cwd, online, { reportOutDir: options.outDir, offline: options.offline === true }), (i): DependencyScanResult => ({ issues: [i], lockfileKind: 'none', directDependencyCount: 0 })))
      : Promise.resolve(previousMerged ? previousMerged.dependency : { issues: [], lockfileKind: 'none' as const, directDependencyCount: 0 }),
    dependencyDirty
      ? timings.record('outdated', () => guarded('outdated', cwd, () => runOutdatedEngine(cwd), (i) => ({ ...EMPTY_OUTDATED, issues: [i] })))
      : Promise.resolve(previousMerged ? previousMerged.outdated : { ...EMPTY_OUTDATED }),
    dependencyDirty
      ? timings.record('migration', () => guarded('migration', cwd, () => runMigrationEngine(cwd), (i) => ({ issues: [i] })))
      : Promise.resolve(previousMerged ? previousMerged.migration : { issues: [] }),
  ]);

  // ── Parallel engines ─────────────────────────────────────────────────────
  stat(`Mapping API surface + performance (${String(n)} files)...`, 62);
  type NamedTask = { readonly name: string; readonly work: () => Promise<unknown> };
  const groupedTasks: NamedTask[] = [];

  if (!shallowReuse) {
    groupedTasks.push({
      name: 'api',
      work: () => guarded('api', cwd, () => runApiEngine(cwd, concurrency, {
        ...filteredOptions,
        ...(config.intentionalPublicRouteGlobs && config.intentionalPublicRouteGlobs.length > 0 ? { intentionalPublicRouteGlobs: config.intentionalPublicRouteGlobs } : {}),
        ...(reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length ? { pathsOverride: reanalyzedFiles } : {}),
      }), (i) => ({ ...EMPTY_API, issues: [i] })),
    });
  }

  if (options.mode !== 'quick' && (fileState.envDirty || !shallowReuse)) {
    groupedTasks.push({ name: 'env', work: () => guarded('env', cwd, () => runEnvEngine(cwd, baseOptions), (i) => ({ ...EMPTY_ENV, issues: [i] })) });
  }

  if (options.mode !== 'quick' && !shallowReuse) {
    const partOpts = reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length ? { pathsOverride: reanalyzedFiles } : {};
    groupedTasks.push(
      { name: 'performance', work: () => guarded('performance', cwd, () => runPerformanceEngine(cwd, concurrency, { ...filteredOptions, ...partOpts }), (i) => ({ issues: [i] })) },
      { name: 'memory', work: () => guarded('memory', cwd, () => runMemoryEngine(cwd, concurrency, { ...filteredOptions, ...partOpts }), (i) => ({ issues: [i] })) },
      { name: 'codeSmell', work: () => guarded('code-smell', cwd, () => runCodeSmellEngine(cwd, concurrency, { ...filteredOptions, ...partOpts }), (i) => ({ issues: [i] })) },
    );
  }

  stat('Computing architecture graph...', 64);
  const taskResultsArr = groupedTasks.length > 0
    ? await timings.record('parallel-engines', () => runPool(groupedTasks, Math.min(concurrency, groupedTasks.length), async (task) => [task.name, await task.work()] as const))
    : [];
  const taskResults = new Map<string, unknown>(taskResultsArr);

  let api: ApiScanResult = previousMerged?.api ?? EMPTY_API;
  let env: EnvScanResult = options.mode === 'quick' ? EMPTY_ENV : previousMerged?.env ?? EMPTY_ENV;
  let performance: PerformanceScanResult = options.mode === 'quick' ? EMPTY_PERFORMANCE : previousMerged?.performance ?? EMPTY_PERFORMANCE;
  let memory: MemoryScanResult = options.mode === 'quick' ? EMPTY_MEMORY : previousMerged?.memory ?? EMPTY_MEMORY;
  let codeSmell: CodeSmellScanResult = options.mode === 'quick' ? EMPTY_CODE_SMELL : previousMerged?.codeSmell ?? EMPTY_CODE_SMELL;

  if (groupedTasks.length > 0) {
    const nextApi = (taskResults.get('api') as ApiScanResult | undefined) ?? EMPTY_API;
    api = !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length && previousMerged
      ? { routes: mergeApiRoutes(previousMerged.api.routes, reanalyzedFiles, nextApi.routes), issues: mergeIssuesByReanalyze(previousMerged.api.issues, fileSet, reanalyzedFiles, nextApi.issues) }
      : nextApi;
    env = (taskResults.get('env') as EnvScanResult | undefined) ?? EMPTY_ENV;
    const nextPerf = (taskResults.get('performance') as PerformanceScanResult | undefined) ?? EMPTY_PERFORMANCE;
    performance = !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length && previousMerged
      ? { issues: mergeIssuesByReanalyze(previousMerged.performance.issues, fileSet, reanalyzedFiles, nextPerf.issues) }
      : nextPerf;
    const nextMem = (taskResults.get('memory') as MemoryScanResult | undefined) ?? EMPTY_MEMORY;
    memory = !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length && previousMerged
      ? { issues: mergeIssuesByReanalyze(previousMerged.memory.issues, fileSet, reanalyzedFiles, nextMem.issues) }
      : nextMem;
    const nextSmell = (taskResults.get('codeSmell') as CodeSmellScanResult | undefined) ?? EMPTY_CODE_SMELL;
    codeSmell = !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length && previousMerged
      ? { issues: mergeIssuesByReanalyze(previousMerged.codeSmell.issues, fileSet, reanalyzedFiles, nextSmell.issues) }
      : nextSmell;
  }

  // ── Architecture / database / inventory / lint / tests ───────────────────
  const [architectureRaw, databaseBase, inventory, lint, testsBase] = await Promise.all([
    shallowReuse && !astDirty && previousMerged
      ? Promise.resolve(previousMerged.architecture)
      : timings.record('architecture', () => guarded('architecture', cwd, () => runArchitectureEngine(cwd, ast, concurrency, filteredOptions), (i) => ({ issues: [i] }))),
    (coldStart || fileState.removedFiles || reanalyzedFiles.size > 0)
      ? timings.record('database', async () => {
          if (!coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length && previousMerged) {
            const dbFiles = [...reanalyzedFiles];
            progress?.beginPhase('Database', dbFiles.length, 65, 90);
            const fresh = mergeDatabaseResults(
              await runPool(dbFiles, concurrency, (file) => { progress?.tick(file); return Promise.resolve(runDatabaseEngineOnFile(file, contents.get(file) ?? '')); }),
            );
            const mergedIssues = mergeIssuesByReanalyze(previousMerged.database.issues, fileSet, reanalyzedFiles, fresh.issues);
            const ormSignals = [...new Set([...previousMerged.database.ormSignals, ...fresh.ormSignals])];
            const rawSqlFileCount = new Set(mergedIssues.filter((i) => i.title.toLowerCase().includes('raw sql')).map((i) => normalize(i.file))).size;
            return { issues: mergedIssues, ormSignals, rawSqlFileCount };
          }
          progress?.beginPhase('Database', normalizedFiles.length, 65, 90);
          const parts = await runPool(normalizedFiles, concurrency, (file) => { progress?.tick(file); return Promise.resolve(runDatabaseEngineOnFile(file, contents.get(file) ?? '')); });
          return mergeDatabaseResults(parts);
        })
      : Promise.resolve(previousMerged ? previousMerged.database : { issues: [], ormSignals: [], rawSqlFileCount: 0 }),
    timings.record('inventory', () =>
      guarded('inventory', cwd, async () => Promise.resolve(runInventoryEngine(cwd, { profile, files: normalizedFiles, contents, sizes })),
        (i) => ({ ...EMPTY_INVENTORY, issues: [i], profile }))),
    options.mode === 'quick' || options.skipLint === true
      ? Promise.resolve({ ...EMPTY_LINT, skippedReason: options.mode === 'quick' ? 'quick mode skips lint engine' : 'skipLint flag was set' })
      : timings.record('lint', () => guarded('lint', cwd, () => runLintEngine(cwd, { budgetMs: Math.min(Math.max(options.budgetMs ?? 45_000, 15_000), 90_000) }), (i) => ({ ...EMPTY_LINT, issues: [i] }))),
    (coldStart || fileState.removedFiles || reanalyzedFiles.size > 0)
      ? timings.record('tests', () =>
          guarded('tests', cwd, () => runTestEngine(cwd, normalizedFiles, config.testFileGlobs && config.testFileGlobs.length > 0 ? { testFileGlobs: config.testFileGlobs } : undefined), (i) => ({ ...EMPTY_TESTS, issues: [i] })))
      : Promise.resolve(previousMerged ? previousMerged.tests : { ...EMPTY_TESTS }),
  ]);

  const archPolicyIssues = runArchitecturePolicyEngine(cwd, config.architecturePolicy, ast.importGraph);
  const architecture: ArchitectureScanResult = { ...architectureRaw, issues: [...architectureRaw.issues, ...archPolicyIssues] };

  const selfCheck = await runSelfCheckEngine(cwd);
  const lcov = await tryReadLcovSummary(cwd);
  const testsMerged = selfCheck.issues.length === 0 ? testsBase : { ...testsBase, issues: [...testsBase.issues, ...selfCheck.issues] };
  const tests = lcov !== undefined ? { ...testsMerged, lcovSummary: lcov } : testsMerged;

  const polyglotIssues = await runPolyglotEngine(cwd);
  const databaseIntel = await extractDatabaseIntelligence(cwd, inventory.files, databaseBase.ormSignals);
  const database: DatabaseAnalysisResult = { ...databaseBase, intelligence: databaseIntel };

  return {
    ast, astAnalyses, security, dependency, outdated, migration, tests, api, env,
    performance, memory,
    codeSmell: { ...codeSmell, issues: [...codeSmell.issues, ...polyglotIssues] },
    architecture, database, inventory, lint,
  };
}

// ─── Stage 4: mergeAndScore ───────────────────────────────────────────────────

export async function mergeAndScore(
  raw: RawEngineOutput,
  options: ScanOptions,
  config: InspectorConfig,
  profile: ProjectProfile,
  metrics: ScanReportingMetrics,
  startedAt: string,
  prCommentScopePaths: readonly string[] | undefined,
): Promise<ScanResult> {
  const { cwd, outDir } = options;
  const finishedAt = new Date().toISOString();

  const baseResult: ScanResult = {
    cwd,
    outDir,
    startedAt,
    finishedAt,
    mode: options.mode,
    incremental: options.rescan === true ? false : options.mode === 'diff' || options.incremental,
    online: options.mode === 'quick' ? false : options.online,
    ast: raw.ast,
    security: raw.security,
    dependency: raw.dependency,
    outdated: raw.outdated,
    tests: raw.tests,
    database: raw.database,
    hotspots: [],
    api: raw.api,
    env: raw.env,
    architecture: raw.architecture,
    performance: raw.performance,
    memory: raw.memory,
    codeSmell: raw.codeSmell,
    migration: raw.migration,
    inventory: raw.inventory,
    lint: raw.lint,
    scores: { security: 0, performance: 0, codeQuality: 0, compliance: 0, tests: 0, productionReadiness: 0 },
    profile,
    ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs } : {}),
  };

  const enriched = enrichAllIssues(baseResult);
  const gateThresholds = gateThresholdsFromConfig(config);
  const gathered = gatherAllIssues(enriched);
  noteRawGatherIssueCount(gathered.length, metrics);
  const piped = applyIssuePipeline(gathered, config, cwd);
  const trusted = deduplicateIssues(piped);
  notePipelineAndDedupedCounts(piped.length, trusted.length, metrics);

  const scores = computeScores(trusted, { testFileCount: raw.tests.testFileCount, sourceFileCount: raw.tests.sourceFileCount });
  const scoreDiagnostics = buildScoreDiagnostics(trusted);
  const hotspots = hotspotItems(computeHotspots(trusted, raw.api.routes));
  const scanForDecision: ScanResult = { ...enriched, gateThresholds };
  const productionDecision = buildProductionDecision(scanForDecision, trusted, scores);

  const baselineFile = await loadBaselineTrusted(outDir);
  const baselineComparison = compareTrustedToBaseline(cwd, trusted, baselineFile);
  if (options.saveBaseline === true) {
    await saveBaselineTrusted(outDir, trusted, cwd);
  }
  const baselineHistory = await loadBaselineHistory(outDir);
  const totalDurationMs = Date.parse(finishedAt) - Date.parse(startedAt);

  return {
    ...scanForDecision,
    scores,
    scoreDiagnostics,
    hotspots,
    trustedIssues: trusted,
    productionDecision,
    totalDurationMs,
    ...(baselineComparison !== undefined ? { baselineComparison } : {}),
    ...(baselineHistory.length > 0 ? { baselineHistory } : {}),
    ...(prCommentScopePaths !== undefined ? { prCommentScopePaths } : {}),
    ...(options.budgetMs !== undefined
      ? { budgetMs: options.budgetMs, budgetExceeded: totalDurationMs > options.budgetMs }
      : {}),
  };
}

// ─── Stage 5: persistAndWrite ─────────────────────────────────────────────────

export async function persistAndWrite(
  result: ScanResult,
  options: ScanOptions,
  fileState: FileState,
  astAnalyses: readonly FileAstAnalysis[],
  previousMerged: ScanResult | undefined,
  metrics: ScanReportingMetrics,
  timings: TimingsRecorder,
): Promise<void> {
  const { outDir, cwd } = options;
  const { normalizedFiles, currentHashes, envSnapshotNow, dependencySnapshotNow, cacheMode, reanalyzedFiles, contents } = fileState;

  activateScanMetrics(metrics);

  const redactedResult = redactScanResultForStorage(result);
  const touchedSections = computeTouchedSections({
    coldStart: cacheMode === 'cold-start',
    hadRemovedFiles: fileState.removedFiles,
    astDirty: cacheMode !== 'shallow-reuse',
    depDirty: fileState.dependencyDirty,
    envDirty: fileState.envDirty,
    partialFilesChanged: reanalyzedFiles.size > 0,
    mode: options.mode,
  });

  if (cacheMode === 'incremental' || cacheMode === 'shallow-reuse') {
    await writeScanReportsPartial(touchedSections, redactedResult, outDir);
  } else {
    await writeScanReports(redactedResult, outDir);
  }
  await writeScanArtifacts(redactedResult, outDir);

  if (dependencySnapshotNow !== null) {
    await saveDependencySnapshot(outDir, dependencySnapshotNow);
  }
  await saveFileHashes(outDir, currentHashes);
  await saveEnvSnapshot(outDir, envSnapshotNow);

  // ── Content bundle with 20 MB memory cap ──────────────────────────────
  const contentBundle: Record<string, string> = {};
  let bundleBytes = 0;
  let skippedCount = 0;
  for (const file of normalizedFiles) {
    const content = contents.get(file) ?? '';
    bundleBytes += content.length;
    if (bundleBytes > MAX_BUNDLE_BYTES) {
      skippedCount += 1;
      continue;
    }
    contentBundle[relKey(cwd, file)] = content;
  }
  if (skippedCount > 0) {
    logger.warn({ skipped: skippedCount }, 'content bundle capped at 20 MB — some files excluded from offline chat');
  }
  await saveFileContentsBundle(outDir, contentBundle);

  if (astAnalyses.length > 0) {
    await saveAstByFileMap(outDir, cwd, astAnalyses);
  }

  // Only persist merged scan when content changed (lightweight fingerprint).
  const prevFp = previousMerged !== undefined ? scanFingerprint(previousMerged) : undefined;
  const nextFp = scanFingerprint(result);
  if (prevFp !== nextFp) {
    await saveMergedScan(outDir, redactedResult);
  }

  const finishedAt = result.finishedAt;
  await saveScanMeta(outDir, {
    version: 1,
    lastScanAt: finishedAt,
    ...(result.totalDurationMs !== undefined ? { lastScanDurationMs: result.totalDurationMs } : {}),
    cacheHit: false,
  });
  await clearScanInterruptedMarker(outDir);

  void timings;
}

// ─── runScan coordinator (≤ 60 lines) ────────────────────────────────────────

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const cwd = resolve(options.cwd);
  const outDir = resolve(options.outDir);
  const resolvedOptions: ScanOptions = { ...options, cwd, outDir, concurrency: Math.max(1, options.concurrency) };
  const startedAt = new Date().toISOString();
  const timings = createTimingsRecorder();
  const metrics = createScanMetrics();

  await mkdir(outDir, { recursive: true });

  const handleSignal = (): void => { void writeScanInterruptedMarker(outDir); };
  process.on('SIGINT', handleSignal);
  process.on('SIGTERM', handleSignal);

  try {
    // One shared progress instance drives all phases (0 → 100%).
    const progress = new ScanProgress(cwd);
    progress.status('Loading cache...');
    logger.debug('Loading cache...');
    const cache = await resolveCache(resolvedOptions);

    progress.status('Discovering files...');
    logger.debug('Discovering files...');
    const fileState = await discoverAndHash(resolvedOptions, cache, timings, progress);

    const status = (msg: string): void => { progress.status(msg); logger.debug(msg); };

    const profile: ProjectProfile = await timings.record('profile', () => detectProjectProfile(cwd));
    const inspectorConfig = await mergePolicyPack(cwd, await loadInspectorConfig(cwd));
    const pluginSuppress = await collectPluginSuppressPatterns(cwd);
    const config: InspectorConfig = { ...inspectorConfig, suppressTitleSubstrings: [...inspectorConfig.suppressTitleSubstrings, ...pluginSuppress] };

    const prCommentScopePaths = await resolvePrCommentScope(resolvedOptions, cwd);

    // Fast path: full cache reuse
    if (fileState.cacheMode === 'full-reuse' && cache.previousMerged !== undefined) {
      status('Using cached result...');
      const polyglotIssues = await runPolyglotEngine(cwd);
      const previousWithPoly = { ...cache.previousMerged, codeSmell: { ...cache.previousMerged.codeSmell, issues: [...cache.previousMerged.codeSmell.issues, ...polyglotIssues] } };
      const enriched = enrichAllIssues({ ...previousWithPoly, startedAt, finishedAt: new Date().toISOString(), profile });
      const gathered = gatherAllIssues(enriched);
      noteRawGatherIssueCount(gathered.length, metrics);
      const piped = applyIssuePipeline(gathered, config, cwd);
      const trusted = deduplicateIssues(piped);
      notePipelineAndDedupedCounts(piped.length, trusted.length, metrics);
      activateScanMetrics(metrics);
      const scores = computeScores(trusted, { testFileCount: enriched.tests.testFileCount, sourceFileCount: enriched.tests.sourceFileCount });
      const gateThresholds = gateThresholdsFromConfig(config);
      const productionDecision = buildProductionDecision({ ...enriched, gateThresholds }, trusted, scores);
      const baselineFile = await loadBaselineTrusted(outDir);
      const baselineComparison = compareTrustedToBaseline(cwd, trusted, baselineFile);
      const baselineHistory = await loadBaselineHistory(outDir);
      const reused: ScanResult = { ...enriched, gateThresholds, scores, scoreDiagnostics: buildScoreDiagnostics(trusted), hotspots: hotspotItems(computeHotspots(trusted, enriched.api.routes)), trustedIssues: trusted, productionDecision, ...(baselineComparison !== undefined ? { baselineComparison } : {}), ...(baselineHistory.length > 0 ? { baselineHistory } : {}), ...(prCommentScopePaths !== undefined ? { prCommentScopePaths } : {}) };
      await writeScanArtifacts(reused, outDir);
      await saveScanMeta(outDir, { version: 1, lastScanAt: reused.finishedAt, lastScanDurationMs: 0, cacheHit: true });
      await clearScanInterruptedMarker(outDir);
      progress.complete();
      return reused;
    }

    const raw = await runEngines(resolvedOptions, fileState, cache, config, profile, timings, status, progress);

    progress.status('Evaluating production readiness...', 92);
    logger.debug('Evaluating production readiness...');
    const result = await mergeAndScore(raw, resolvedOptions, config, profile, metrics, startedAt, prCommentScopePaths);
    const finalResult: ScanResult = { ...result, timings: timings.timings };

    progress.status('Writing report files...', 96);
    logger.debug('Writing report files...');
    await persistAndWrite(finalResult, resolvedOptions, fileState, raw.astAnalyses, cache.previousMerged, metrics, timings);

    progress.complete();
    return finalResult;
  } finally {
    process.off('SIGINT', handleSignal);
    process.off('SIGTERM', handleSignal);
  }
}

export function defaultReportDir(cwd: string): string {
  return join(resolve(cwd), 'project-report');
}
