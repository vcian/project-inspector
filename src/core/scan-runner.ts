import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
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
import { runOutdatedEngine } from '../engines/outdated-engine.js';
import { runPerformanceEngine } from '../engines/performance-engine.js';
import { runSecurityEngine, type SecurityEngineOptions } from '../engines/security-engine.js';
import { runSelfCheckEngine } from '../engines/self-check-engine.js';
import { runTestEngine } from '../engines/test-engine.js';
import { writeScanArtifacts, writeScanReports, writeScanReportsPartial, type ReportSection } from '../reports/writers.js';
import { runPool } from '../utils/async-pool.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { detectProjectProfile } from '../utils/detect-project.js';
import { getGitChangedPaths } from '../utils/git-incremental.js';
import { logger } from '../utils/logger.js';
import { createSerialQueue } from '../utils/serial-queue.js';
import { buildDependencySnapshot, snapshotsEqual, type DependencySnapshotV1 } from './dependency-snapshot.js';
import { buildEnvHashes } from './env-snapshot.js';
import { sha256File, sha256String } from './file-hash.js';
import { compareTrustedToBaseline, loadBaselineTrusted, saveBaselineTrusted } from './baseline.js';
import { buildAttackChainNarrative } from './attack-chain.js';
import { buildProductionDecision } from './decision-engine.js';
import { loadInspectorConfig, type InspectorConfig } from './inspector-config.js';
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
  buildScoreDiagnostics,
  computeHotspots,
  computeScores,
  deduplicateIssues,
  notePipelineAndDedupedCounts,
  noteRawGatherIssueCount,
  resetScanReportingMetrics,
} from './scoring-engine.js';
import type {
  ApiScanResult,
  ArchitectureScanResult,
  CodeSmellScanResult,
  DependencyScanResult,
  DatabaseAnalysisResult,
  EngineTiming,
  EnvScanResult,
  InventoryScanResult,
  Issue,
  LintScanResult,
  MemoryScanResult,
  PerformanceScanResult,
  ProjectProfile,
  ScanOptions,
  ScanResult,
  SecurityScanResult,
} from './types.js';
import { tryAutoUpdateVulnDb } from './vuln-auto-update.js';
import { redactScanResultForStorage } from '../report/redact-evidence.js';

const EMPTY_API: ApiScanResult = { issues: [], routes: [] };
const EMPTY_ENV: EnvScanResult = { issues: [], envFiles: [], keysFound: [] };
const EMPTY_PERFORMANCE: PerformanceScanResult = { issues: [] };
const EMPTY_MEMORY: MemoryScanResult = { issues: [] };
const EMPTY_CODE_SMELL: CodeSmellScanResult = { issues: [] };
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

type CacheMode = 'full-reuse' | 'shallow-reuse' | 'incremental' | 'cold-start';

interface TimingsRecorder {
  readonly timings: readonly EngineTiming[];
  readonly push: (entry: EngineTiming) => void;
  readonly record: <T>(name: string, work: () => Promise<T> | T) => Promise<T>;
}

function createTimingsRecorder(): TimingsRecorder {
  const timings: EngineTiming[] = [];
  return {
    timings,
    push(entry) {
      timings.push(entry);
    },
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

function hashObject(value: unknown): string {
  return sha256String(JSON.stringify(value));
}

function requireMergedScan(scan: ScanResult | undefined, context: string): ScanResult {
  if (scan === undefined) {
    throw new Error(`internal: ${context} requires a merged scan`);
  }
  return scan;
}

async function readDependencySnapshotAlias(outDir: string): Promise<DependencySnapshotV1 | undefined> {
  const primary = await loadDependencySnapshot(outDir);
  if (primary !== undefined) {
    return primary;
  }
  const aliasPath = join(outDir, '.cache', 'dep-snapshot.json');
  if (!existsSync(aliasPath)) {
    return undefined;
  }
  try {
    return JSON.parse(await readFile(aliasPath, 'utf8')) as DependencySnapshotV1;
  } catch {
    return undefined;
  }
}

async function warnOnVulnDbStaleness(outDir: string, offline: boolean | undefined): Promise<void> {
  if (offline === true) {
    return;
  }
  const metaPath = join(outDir, '.cache', 'vuln-db-meta.json');
  if (!existsSync(metaPath)) {
    return;
  }
  try {
    const raw = await readFile(metaPath, 'utf8');
    const parsed = JSON.parse(raw) as { fetchedAt?: string };
    if (typeof parsed.fetchedAt !== 'string') {
      return;
    }
    const fetchedAt = Date.parse(parsed.fetchedAt);
    if (Number.isNaN(fetchedAt) || Date.now() - fetchedAt <= SEVEN_DAYS_MS) {
      return;
    }
    logger.warn(
      { fetchedAt: parsed.fetchedAt },
      'vulnerability DB metadata is older than 7 days; run update-vuln-db or use --auto-update-db',
    );
  } catch (error) {
    logger.debug({ err: error }, 'failed to read vulnerability DB metadata');
  }
}

function verificationStepForHotspot(issue: Issue): string {
  if (issue.engine === 'lint') {
    return 'Run lint/typecheck until clean; re-scan.';
  }
  if (issue.engine === 'dependency' || issue.engine === 'outdated') {
    return 'Update dependency / lockfile; re-run audit and scan.';
  }
  return 'Add or run targeted tests for the module; re-run project-inspector.';
}

function hotspotItems(issues: readonly Issue[]): ScanResult['hotspots'] {
  return issues.map((issue, index) => ({
    rank: index + 1,
    severity: issue.severity,
    title: issue.title,
    file: issue.file,
    line: issue.line,
    engine: issue.engine,
    impact: issue.impact,
    fixHint: issue.fix,
    rootCause: issue.whyItMatters ?? issue.description,
    verifyStep: verificationStepForHotspot(issue),
    attackChain: buildAttackChainNarrative(issue),
  }));
}

function gateThresholdsFromConfig(config: InspectorConfig): NonNullable<ScanResult['gateThresholds']> {
  return {
    minProductionReadiness: config.gates?.minProductionReadiness ?? 48,
    minSecurityScore: config.gates?.minSecurityScore ?? 50,
  };
}

function scoreMetaForScan(result: Pick<ScanResult, 'tests'>): { readonly testFileCount: number; readonly sourceFileCount: number } {
  return {
    testFileCount: result.tests.testFileCount,
    sourceFileCount: result.tests.sourceFileCount,
  };
}

function mergeApi(
  previous: ApiScanResult | undefined,
  allFiles: ReadonlySet<string>,
  reanalyzedFiles: ReadonlySet<string>,
  fresh: ApiScanResult,
): ApiScanResult {
  if (previous === undefined) {
    return fresh;
  }
  return {
    routes: mergeApiRoutes(previous.routes, reanalyzedFiles, fresh.routes),
    issues: mergeIssuesByReanalyze(previous.issues, allFiles, reanalyzedFiles, fresh.issues),
  };
}

async function guarded<T>(engine: string, cwd: string, work: () => Promise<T>, fallback: (issue: Issue) => T): Promise<T> {
  try {
    return await work();
  } catch (error) {
    logger.warn({ engine, err: error }, 'engine failed');
    return fallback(issueFromCrash(engine, cwd, error));
  }
}

interface NamedTask {
  readonly name: string;
  readonly work: () => Promise<unknown>;
}

async function runNamedTasks(tasks: readonly NamedTask[], concurrency: number): Promise<ReadonlyMap<string, unknown>> {
  const pairs = await runPool(tasks, Math.min(concurrency, Math.max(tasks.length, 1)), async (task) => [
    task.name,
    await task.work(),
  ] as const);
  return new Map<string, unknown>(pairs);
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
    return new Set<ReportSection>([
      'summary',
      'production-decision',
      'security',
      'dependencies',
      'api',
      'architecture',
      'performance',
      'ast',
      'test',
      'database',
    ]);
  }

  const touched = new Set<ReportSection>(['summary', 'production-decision', 'security']);
  if (args.astDirty || args.partialFilesChanged) {
    touched.add('ast');
    touched.add('architecture');
    touched.add('security');
    if (args.mode !== 'quick') {
      touched.add('api');
      touched.add('performance');
      touched.add('database');
    }
  }
  if (args.depDirty) {
    touched.add('dependencies');
    touched.add('security');
  }
  if (args.envDirty) {
    touched.add('security');
  }
  touched.add('test');
  touched.add('database');
  return touched;
}

function defaultScores(): ScanResult['scores'] {
  return {
    security: 0,
    performance: 0,
    codeQuality: 0,
    compliance: 0,
    tests: 0,
    productionReadiness: 0,
  };
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const cwd = resolve(options.cwd);
  const outDir = resolve(options.outDir);
  const concurrency = Math.max(1, options.concurrency);
  const startedAt = new Date().toISOString();
  const timings = createTimingsRecorder();
  const online = options.mode === 'quick' ? false : options.online;
  const skipCache = options.rescan === true || options.useFileCache === false;
  const incrementalMode =
    options.rescan === true ? false : options.mode === 'diff' || options.incremental;

  await mkdir(outDir, { recursive: true });

  const handleSigInt = (): void => {
    void writeScanInterruptedMarker(outDir);
  };
  process.on('SIGINT', handleSigInt);

  try {
    resetScanReportingMetrics();
    const sourceFiles = await timings.record('discover-files', () => discoverSourceFiles(cwd));
    const normalizedFiles = sourceFiles.map((file) => normalize(file));
    const fileSet = new Set<string>(normalizedFiles);

    const [previousHashesFile, previousMergedRaw, previousEnvSnapshot, previousContents, interrupted, previousDepSnapshot, astByFileMap] =
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
    const previousHashes = previousHashesFile?.hashes ?? {};
    const coldStart = skipCache || previousMerged === undefined || interrupted;

    const profile: ProjectProfile = await timings.record('profile', () => detectProjectProfile(cwd));
    const inspectorConfig = await loadInspectorConfig(cwd);

    const hashPairs = await timings.record('file-hashes', () =>
      runPool(normalizedFiles, concurrency, async (file) => [relKey(cwd, file), await sha256File(file)] as const),
    );
    const currentHashes: Record<string, string> = Object.fromEntries(hashPairs);

    const dirtyFiles = new Set<string>();
    if (coldStart) {
      for (const file of normalizedFiles) {
        dirtyFiles.add(file);
      }
    } else {
      for (const file of normalizedFiles) {
        const key = relKey(cwd, file);
        if (previousHashes[key] !== currentHashes[key]) {
          dirtyFiles.add(file);
        }
      }
    }

    const removedFiles = Object.keys(previousHashes).some((key) => !(key in currentHashes));

    if (options.autoUpdateDb === true && options.offline !== true) {
      await tryAutoUpdateVulnDb(outDir);
    }
    await warnOnVulnDbStaleness(outDir, options.offline);

    const dependencySnapshotNow = await buildDependencySnapshot(cwd, outDir);
    const dependencyDirty =
      coldStart ||
      dependencySnapshotNow === null ||
      previousDepSnapshot === undefined ||
      !snapshotsEqual(previousDepSnapshot, dependencySnapshotNow) ||
      (online && options.mode !== 'quick');

    const envSnapshotNow = await buildEnvHashes(cwd);
    const envDirty = coldStart || JSON.stringify(envSnapshotNow) !== JSON.stringify(previousEnvSnapshot ?? {});

    let diffFilter: Set<string> | undefined;
    if (incrementalMode) {
      const gitChangedPaths = await getGitChangedPaths(cwd);
      if (gitChangedPaths !== null && gitChangedPaths.length > 0) {
        const filtered = gitChangedPaths.map((file) => normalize(file)).filter((file) => fileSet.has(file));
        if (filtered.length > 0) {
          diffFilter = new Set(filtered);
        }
      }
    }

    const effectiveDirty = new Set<string>();
    for (const file of dirtyFiles) {
      if (diffFilter === undefined || diffFilter.has(file)) {
        effectiveDirty.add(file);
      }
    }

    const reanalyzedFiles =
      coldStart || diffFilter === undefined
        ? new Set<string>(coldStart ? normalizedFiles : effectiveDirty)
        : new Set<string>([...diffFilter].filter((file) => effectiveDirty.has(file)));

    const fullReuse =
      !coldStart &&
      previousMerged.mode === options.mode &&
      !removedFiles &&
      dirtyFiles.size === 0 &&
      !dependencyDirty &&
      !envDirty &&
      !incrementalMode &&
      !online;

    const shallowReuse =
      !coldStart &&
      previousMerged.mode === options.mode &&
      !removedFiles &&
      reanalyzedFiles.size === 0 &&
      !online;

    const cacheMode: CacheMode = fullReuse
      ? 'full-reuse'
      : coldStart
        ? 'cold-start'
        : reanalyzedFiles.size > 0
          ? 'incremental'
          : 'shallow-reuse';
    logger.info({ cacheMode }, 'scan cache mode resolved');

    if (fullReuse) {
      const merged = requireMergedScan(previousMerged, 'fullReuse');
      const finishedAt = new Date().toISOString();
      const enriched = enrichAllIssues({ ...merged, startedAt, finishedAt, profile });
      const intel = await extractDatabaseIntelligence(cwd, enriched.inventory.files, enriched.database.ormSignals);
      const enrichedWithDb: ScanResult = { ...enriched, database: { ...enriched.database, intelligence: intel } };
      const gateThresholds = gateThresholdsFromConfig(inspectorConfig);
      const gathered = gatherAllIssues(enrichedWithDb);
      noteRawGatherIssueCount(gathered.length);
      const piped = applyIssuePipeline(gathered, inspectorConfig, cwd);
      const trusted = deduplicateIssues(piped);
      notePipelineAndDedupedCounts(piped.length, trusted.length);
      const scores = computeScores(trusted, scoreMetaForScan(enrichedWithDb));
      const scoreDiagnostics = buildScoreDiagnostics(trusted);
      const hotspots = hotspotItems(computeHotspots(trusted, enrichedWithDb.api.routes));
      const scanForDecision: ScanResult = { ...enrichedWithDb, gateThresholds };
      const productionDecision = buildProductionDecision(scanForDecision, trusted, scores);
      const baselineFile = await loadBaselineTrusted(outDir);
      const baselineComparison = compareTrustedToBaseline(cwd, trusted, baselineFile);
      if (options.saveBaseline === true) {
        await saveBaselineTrusted(outDir, trusted, cwd);
      }
      const reused: ScanResult = {
        ...scanForDecision,
        scores,
        scoreDiagnostics,
        hotspots,
        trustedIssues: trusted,
        productionDecision,
        ...(baselineComparison !== undefined ? { baselineComparison } : {}),
      };
      await saveScanMeta(outDir, {
        version: 1,
        lastScanAt: finishedAt,
        lastScanDurationMs: 0,
        cacheHit: true,
      });
      await writeScanArtifacts(reused, outDir);
      await clearScanInterruptedMarker(outDir);
      return reused;
    }

    const contents = new Map<string, string>();
    const sizes = new Map<string, number>();
    await timings.record('read-files', () =>
      runPool(normalizedFiles, concurrency, async (file) => {
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

    const getSourceText = (file: string): string | undefined => contents.get(normalize(file));
    const morphProject = new MorphProject({
      skipAddingFilesFromTsConfig: true,
      compilerOptions: {
        allowJs: true,
        checkJs: false,
        jsx: JsxEmit.ReactJSX,
        target: ScriptTarget.ES2022,
      },
    });
    const morph = {
      project: morphProject,
      runExclusive: createSerialQueue(),
      getSourceText,
    };

    const baseOptions = { sourceFiles: normalizedFiles, getSourceText };
    const filteredOptions = diffFilter ? { ...baseOptions, fileFilter: diffFilter } : baseOptions;
    const astOptions: AstEngineOptions = {
      ...filteredOptions,
      ...(diffFilter ? { partial: true } : {}),
      morph,
    };
    const securityOptions: SecurityEngineOptions = {
      ...filteredOptions,
      morph,
      profile,
    };

    const astRun = async (override?: Partial<AstEngineOptions>): Promise<AstEngineRun> =>
      guarded(
        'ast',
        cwd,
        () => runAstEngineWithAnalyses(cwd, concurrency, { ...astOptions, ...override }),
        (issue) => ({
          analyses: [],
          scan: {
            filesAnalyzed: 0,
            functions: [],
            issues: [issue],
            importGraph: [],
            circularDependencyChains: [],
          },
        }),
      );

    let ast = previousMerged?.ast ?? {
      filesAnalyzed: 0,
      functions: [],
      issues: [],
      importGraph: [],
      circularDependencyChains: [],
    };
    let astAnalyses: readonly FileAstAnalysis[] = [];
    let astDirty = coldStart || reanalyzedFiles.size > 0 || removedFiles;

    if (shallowReuse) {
      ast = requireMergedScan(previousMerged, 'shallowReuse-ast').ast;
      astDirty = false;
    } else if (
      !coldStart &&
      astByFileMap.size > 0 &&
      reanalyzedFiles.size > 0 &&
      diffFilter === undefined &&
      !removedFiles
    ) {
      const incrementalAst = await timings.record('ast', () =>
        astRun({ incremental: { dirtyPaths: reanalyzedFiles, cachedByFile: astByFileMap } }),
      );
      ast = incrementalAst.scan;
      astAnalyses = incrementalAst.analyses;
    } else {
      const fullAst = await timings.record('ast', () => astRun());
      ast = fullAst.scan;
      astAnalyses = fullAst.analyses;
    }

    let security: SecurityScanResult;
    if (shallowReuse) {
      security = requireMergedScan(previousMerged, 'shallowReuse-security').security;
    } else if (!coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length) {
      const fresh = await timings.record('security', () =>
        guarded(
          'security',
          cwd,
          () => runSecurityEngine(cwd, concurrency, { ...securityOptions, pathsOverride: reanalyzedFiles }),
          (issue) => ({ issues: [issue] }),
        ),
      );
      security = {
        issues: mergeIssuesByReanalyze(
          requireMergedScan(previousMerged, 'security-merge').security.issues,
          fileSet,
          reanalyzedFiles,
          fresh.issues,
        ),
      };
    } else {
      security = await timings.record('security', () =>
        guarded('security', cwd, () => runSecurityEngine(cwd, concurrency, securityOptions), (issue) => ({
          issues: [issue],
        })),
      );
    }

    const dependencyPromise =
      dependencyDirty
        ? timings.record('dependency', () =>
            guarded(
              'dependency',
              cwd,
              () => runDependencyEngine(cwd, online, { reportOutDir: outDir, offline: options.offline === true }),
              (issue): DependencyScanResult => ({
                issues: [issue],
                lockfileKind: 'none',
                directDependencyCount: 0,
              }),
            ),
          )
        : Promise.resolve(requireMergedScan(previousMerged, 'dependency-reuse').dependency);

    const outdatedPromise =
      dependencyDirty
        ? timings.record('outdated', () =>
            guarded('outdated', cwd, () => runOutdatedEngine(cwd), (issue) => ({
              ...EMPTY_OUTDATED,
              issues: [issue],
            })),
          )
        : Promise.resolve(requireMergedScan(previousMerged, 'outdated-reuse').outdated);

    const migrationPromise =
      dependencyDirty
        ? timings.record('migration', () =>
            guarded('migration', cwd, () => runMigrationEngine(cwd), (issue) => ({ issues: [issue] })),
          )
        : Promise.resolve(requireMergedScan(previousMerged, 'migration-reuse').migration);

    const testEngineOpts =
      inspectorConfig.testFileGlobs !== undefined && inspectorConfig.testFileGlobs.length > 0
        ? { testFileGlobs: inspectorConfig.testFileGlobs }
        : undefined;
    const testsPromise =
      coldStart || removedFiles || reanalyzedFiles.size > 0
        ? timings.record('tests', () =>
            guarded('tests', cwd, () => runTestEngine(cwd, normalizedFiles, testEngineOpts), (issue) => ({
              ...EMPTY_TESTS,
              issues: [issue],
            })),
          )
        : Promise.resolve(requireMergedScan(previousMerged, 'tests-reuse').tests);

    const groupedTasks = [
      ...(!shallowReuse
        ? [
            {
              name: 'api',
              work: async () =>
                guarded(
                  'api',
                  cwd,
                  () =>
                    runApiEngine(cwd, concurrency, {
                      ...filteredOptions,
                      ...(inspectorConfig.intentionalPublicRouteGlobs !== undefined &&
                      inspectorConfig.intentionalPublicRouteGlobs.length > 0
                        ? { intentionalPublicRouteGlobs: inspectorConfig.intentionalPublicRouteGlobs }
                        : {}),
                      ...(reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
                        ? { pathsOverride: reanalyzedFiles }
                        : {}),
                    }),
                  (issue) => ({ ...EMPTY_API, issues: [issue] }),
                ),
            },
          ]
        : []),
      ...(options.mode !== 'quick' && (envDirty || !shallowReuse)
        ? [
            {
              name: 'env',
              work: async () =>
                guarded('env', cwd, () => runEnvEngine(cwd, baseOptions), (issue) => ({
                  ...EMPTY_ENV,
                  issues: [issue],
                })),
            },
          ]
        : []),
      ...(options.mode !== 'quick' && !shallowReuse
        ? [
            {
              name: 'performance',
              work: async () =>
                guarded(
                  'performance',
                  cwd,
                  () =>
                    runPerformanceEngine(cwd, concurrency, {
                      ...filteredOptions,
                      ...(reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
                        ? { pathsOverride: reanalyzedFiles }
                        : {}),
                    }),
                  (issue) => ({ issues: [issue] }),
                ),
            },
            {
              name: 'memory',
              work: async () =>
                guarded(
                  'memory',
                  cwd,
                  () =>
                    runMemoryEngine(cwd, concurrency, {
                      ...filteredOptions,
                      ...(reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
                        ? { pathsOverride: reanalyzedFiles }
                        : {}),
                    }),
                  (issue) => ({ issues: [issue] }),
                ),
            },
            {
              name: 'codeSmell',
              work: async () =>
                guarded(
                  'code-smell',
                  cwd,
                  () =>
                    runCodeSmellEngine(cwd, concurrency, {
                      ...filteredOptions,
                      ...(reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
                        ? { pathsOverride: reanalyzedFiles }
                        : {}),
                    }),
                  (issue) => ({ issues: [issue] }),
                ),
            },
          ]
        : []),
    ] as const;

    const taskResults = groupedTasks.length > 0 ? await timings.record('parallel-engines', () => runNamedTasks(groupedTasks, concurrency)) : new Map<string, unknown>();

    let api: ApiScanResult = previousMerged?.api ?? EMPTY_API;
    let env: EnvScanResult = options.mode === 'quick' ? EMPTY_ENV : previousMerged?.env ?? EMPTY_ENV;
    let performance: PerformanceScanResult =
      options.mode === 'quick' ? EMPTY_PERFORMANCE : previousMerged?.performance ?? EMPTY_PERFORMANCE;
    let memory: MemoryScanResult = options.mode === 'quick' ? EMPTY_MEMORY : previousMerged?.memory ?? EMPTY_MEMORY;
    let codeSmell: CodeSmellScanResult =
      options.mode === 'quick' ? EMPTY_CODE_SMELL : previousMerged?.codeSmell ?? EMPTY_CODE_SMELL;

    if (groupedTasks.length > 0) {
      const nextApi = (taskResults.get('api') as ApiScanResult | undefined) ?? EMPTY_API;
      api =
        !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
          ? mergeApi(requireMergedScan(previousMerged, 'api-merge').api, fileSet, reanalyzedFiles, nextApi)
          : nextApi;

      env = (taskResults.get('env') as EnvScanResult | undefined) ?? EMPTY_ENV;

      const nextPerf = (taskResults.get('performance') as PerformanceScanResult | undefined) ?? EMPTY_PERFORMANCE;
      performance =
        !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
          ? {
              issues: mergeIssuesByReanalyze(
                requireMergedScan(previousMerged, 'performance-merge').performance.issues,
                fileSet,
                reanalyzedFiles,
                nextPerf.issues,
              ),
            }
          : nextPerf;

      const nextMemory = (taskResults.get('memory') as MemoryScanResult | undefined) ?? EMPTY_MEMORY;
      memory =
        !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
          ? {
              issues: mergeIssuesByReanalyze(
                requireMergedScan(previousMerged, 'memory-merge').memory.issues,
                fileSet,
                reanalyzedFiles,
                nextMemory.issues,
              ),
            }
          : nextMemory;

      const nextSmell = (taskResults.get('codeSmell') as CodeSmellScanResult | undefined) ?? EMPTY_CODE_SMELL;
      codeSmell =
        !coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length
          ? {
              issues: mergeIssuesByReanalyze(
                requireMergedScan(previousMerged, 'code-smell-merge').codeSmell.issues,
                fileSet,
                reanalyzedFiles,
                nextSmell.issues,
              ),
            }
          : nextSmell;
    }

    const architecturePromise: Promise<ArchitectureScanResult> =
      shallowReuse && !astDirty
        ? Promise.resolve(requireMergedScan(previousMerged, 'architecture-reuse').architecture)
        : timings.record('architecture', () =>
            guarded('architecture', cwd, () => runArchitectureEngine(cwd, ast, concurrency, filteredOptions), (issue) => ({
              issues: [issue],
            })),
          );

    const needDatabaseRescan = coldStart || removedFiles || reanalyzedFiles.size > 0;
    const databasePromise: Promise<DatabaseAnalysisResult> = needDatabaseRescan
      ? timings.record('database', () => {
          if (!coldStart && reanalyzedFiles.size > 0 && reanalyzedFiles.size < normalizedFiles.length) {
            return (async (): Promise<DatabaseAnalysisResult> => {
              const priorDb = requireMergedScan(previousMerged, 'database-merge').database;
              const fresh = mergeDatabaseResults(
                await runPool([...reanalyzedFiles], concurrency, (file) =>
                  Promise.resolve(runDatabaseEngineOnFile(file, contents.get(file) ?? '')),
                ),
              );
              const mergedIssues = mergeIssuesByReanalyze(
                priorDb.issues,
                fileSet,
                reanalyzedFiles,
                fresh.issues,
              );
              const ormSignals = [...new Set([...priorDb.ormSignals, ...fresh.ormSignals])];
              const rawSqlFileCount = new Set(
                mergedIssues
                  .filter((issue) => issue.title.toLowerCase().includes('raw sql'))
                  .map((issue) => normalize(issue.file)),
              ).size;
              return { issues: mergedIssues, ormSignals, rawSqlFileCount };
            })();
          }
          return runPool(normalizedFiles, concurrency, (file) =>
            Promise.resolve(runDatabaseEngineOnFile(file, contents.get(file) ?? '')),
          ).then((parts) => mergeDatabaseResults(parts));
        })
      : Promise.resolve(requireMergedScan(previousMerged, 'database-reuse').database);

    const inventoryPromise: Promise<InventoryScanResult> = timings.record('inventory', () =>
      guarded(
        'inventory',
        cwd,
        async () =>
          Promise.resolve(runInventoryEngine(cwd, {
            profile,
            files: normalizedFiles,
            contents,
            sizes,
          })),
        (issue) => ({
          ...EMPTY_INVENTORY,
          issues: [issue],
          profile,
        }),
      ),
    );

    const lintPromise: Promise<LintScanResult> =
      options.mode === 'quick' || options.skipLint === true
        ? Promise.resolve({
            ...EMPTY_LINT,
            skippedReason: options.mode === 'quick' ? 'quick mode skips lint engine' : 'skipLint flag was set',
          })
        : timings.record('lint', () =>
            guarded(
              'lint',
              cwd,
              () =>
                runLintEngine(cwd, {
                  budgetMs: Math.min(Math.max(options.budgetMs ?? 45_000, 15_000), 90_000),
                }),
              (issue) => ({ ...EMPTY_LINT, issues: [issue] }),
            ),
          );

    const [dependency, outdated, migration, testsBase, architecture, databaseBase, inventory, lint] =
      await Promise.all([
        dependencyPromise,
        outdatedPromise,
        migrationPromise,
        testsPromise,
        architecturePromise,
        databasePromise,
        inventoryPromise,
        lintPromise,
      ]);

    const databaseIntel = await extractDatabaseIntelligence(cwd, inventory.files, databaseBase.ormSignals);
    const database: DatabaseAnalysisResult = { ...databaseBase, intelligence: databaseIntel };

    const selfCheck = await runSelfCheckEngine(cwd);
    const tests =
      selfCheck.issues.length === 0
        ? testsBase
        : {
            ...testsBase,
            issues: [...testsBase.issues, ...selfCheck.issues],
          };

    const finishedAt = new Date().toISOString();
    const baseResult: ScanResult = {
      cwd,
      outDir,
      startedAt,
      finishedAt,
      mode: options.mode,
      incremental: incrementalMode,
      online,
      ast,
      security,
      dependency,
      outdated,
      tests,
      database,
      hotspots: [],
      api,
      env,
      architecture,
      performance,
      memory,
      codeSmell,
      migration,
      inventory,
      lint,
      scores: defaultScores(),
      timings: timings.timings,
      profile,
      totalDurationMs: Date.parse(finishedAt) - Date.parse(startedAt),
      ...(options.budgetMs !== undefined ? { budgetMs: options.budgetMs, budgetExceeded: Date.parse(finishedAt) - Date.parse(startedAt) > options.budgetMs } : {}),
    };

    const enriched = enrichAllIssues(baseResult);
    const gateThresholds = gateThresholdsFromConfig(inspectorConfig);
    const gathered = gatherAllIssues(enriched);
    noteRawGatherIssueCount(gathered.length);
    const piped = applyIssuePipeline(gathered, inspectorConfig, cwd);
    const trusted = deduplicateIssues(piped);
    notePipelineAndDedupedCounts(piped.length, trusted.length);
    const scores = computeScores(trusted, scoreMetaForScan(enriched));
    const scoreDiagnostics = buildScoreDiagnostics(trusted);
    const hotspots = hotspotItems(computeHotspots(trusted, enriched.api.routes));
    const scanForDecision: ScanResult = { ...enriched, gateThresholds };
    const productionDecision = buildProductionDecision(scanForDecision, trusted, scores);
    const baselineFile = await loadBaselineTrusted(outDir);
    const baselineComparison = compareTrustedToBaseline(cwd, trusted, baselineFile);
    if (options.saveBaseline === true) {
      await saveBaselineTrusted(outDir, trusted, cwd);
    }
    const result: ScanResult = {
      ...scanForDecision,
      scores,
      scoreDiagnostics,
      hotspots,
      trustedIssues: trusted,
      productionDecision,
      ...(baselineComparison !== undefined ? { baselineComparison } : {}),
    };

    const redactedResult = redactScanResultForStorage(result);
    const touchedSections = computeTouchedSections({
      coldStart,
      hadRemovedFiles: removedFiles,
      astDirty,
      depDirty: dependencyDirty,
      envDirty,
      partialFilesChanged: reanalyzedFiles.size > 0,
      mode: options.mode,
    });

    if (cacheMode === 'incremental' || cacheMode === 'shallow-reuse') {
      await writeScanReportsPartial(touchedSections, redactedResult, outDir);
    } else {
      await writeScanReports(redactedResult, outDir);
    }

    if (dependencySnapshotNow !== null) {
      await saveDependencySnapshot(outDir, dependencySnapshotNow);
      await writeFile(join(outDir, '.cache', 'dep-snapshot.json'), `${JSON.stringify(dependencySnapshotNow, null, 2)}\n`, 'utf8');
    }
    await saveFileHashes(outDir, currentHashes);
    await saveEnvSnapshot(outDir, envSnapshotNow);

    const contentBundle: Record<string, string> = {};
    for (const file of normalizedFiles) {
      contentBundle[relKey(cwd, file)] = contents.get(file) ?? '';
    }
    await saveFileContentsBundle(outDir, contentBundle);
    if (astAnalyses.length > 0) {
      await saveAstByFileMap(outDir, cwd, astAnalyses);
    }

    const previousMergedHash = previousMerged === undefined ? undefined : hashObject(redactScanResultForStorage(previousMerged));
    const nextMergedHash = hashObject(redactedResult);
    if (previousMergedHash !== nextMergedHash) {
      await saveMergedScan(outDir, redactedResult);
    }

    await saveScanMeta(outDir, {
      version: 1,
      lastScanAt: finishedAt,
      ...(redactedResult.totalDurationMs !== undefined
        ? { lastScanDurationMs: redactedResult.totalDurationMs }
        : {}),
      cacheHit: false,
    });
    await clearScanInterruptedMarker(outDir);
    return redactedResult;
  } finally {
    process.removeListener('SIGINT', handleSigInt);
  }
}

export function defaultReportDir(cwd: string): string {
  return join(resolve(cwd), 'project-report');
}
