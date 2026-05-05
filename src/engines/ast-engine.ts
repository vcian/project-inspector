import { readFile } from 'node:fs/promises';
import { basename, normalize } from 'node:path';
import type { Node } from 'ts-morph';
import { JsxEmit, ScriptTarget } from 'typescript';
import type { Project } from 'ts-morph';
import { Project as TsMorphProject, SyntaxKind } from 'ts-morph';

import type { AstScanResult, FunctionInfo, ImportEdge, Issue } from '../core/types.js';
import { discoverSourceFiles } from '../utils/discover-source-files.js';
import { resolveLocalImport } from '../utils/resolve-local-module.js';
import { runPool } from '../utils/async-pool.js';
import { estimateCyclomaticComplexity, maxBlockNestingDepth } from './ast/complexity.js';
import { findCircularDependencyChains } from './graph/circular-dependencies.js';

const MAX_COMPLEXITY = 15;
const MAX_NESTING = 5;
const MAX_FUNCTION_LINES = 120;
const CIRCULAR_CYCLE_CAP = 25;

export interface FileAstAnalysis {
  readonly file: string;
  readonly functions: FunctionInfo[];
  readonly issues: Issue[];
  readonly edges: ImportEdge[];
  readonly exports: {
    readonly named: readonly string[];
    readonly hasDefault: boolean;
  };
  readonly imports: ReadonlyArray<{
    readonly target: string | null;
    readonly named: readonly string[];
    readonly isNamespace: boolean;
    readonly isSideEffectOnly: boolean;
    readonly hasDefaultImport: boolean;
  }>;
}

function isEntryLikeFile(file: string): boolean {
  const base = basename(file).toLowerCase();
  return (
    base === 'index.ts' ||
    base === 'index.tsx' ||
    base === 'index.js' ||
    base === 'index.jsx' ||
    base === 'main.ts' ||
    base === 'main.js' ||
    base === 'cli.ts' ||
    base === 'server.ts' ||
    base === 'app.tsx' ||
    base === 'layout.tsx' ||
    base === 'page.tsx' ||
    base === 'route.ts'
  );
}

function issue(
  engine: string,
  severity: Issue['severity'],
  title: string,
  file: string,
  line: number,
  description: string,
  impact: string,
  fix: string,
  code?: string,
): Issue {
  const id = `${engine}:${file}:${String(line)}:${title}`.replaceAll(/\s+/g, '_');
  const base: Issue = {
    id,
    engine,
    severity,
    title,
    file,
    line,
    description,
    impact,
    fix,
  };
  if (code !== undefined) {
    return { ...base, code };
  }
  return base;
}

export interface AstMorphContext {
  readonly project: Project;
  /** Serialize ts-morph mutations on the shared `project`. */
  readonly runExclusive: <T>(fn: () => Promise<T>) => Promise<T>;
  /** Normalized absolute path → UTF-8 source (missing = unreadable). */
  readonly getSourceText: (normalizedAbs: string) => string | undefined;
}

async function analyzeFile(
  absPath: string,
  fileSet: ReadonlySet<string>,
  morph?: AstMorphContext,
): Promise<FileAstAnalysis> {
  const run = async (): Promise<FileAstAnalysis> => {
  const functions: FunctionInfo[] = [];
  const issues: Issue[] = [];
  const edges: ImportEdge[] = [];
  const namedExports: string[] = [];
  let hasDefaultExport = false;

  let sourceText: string | undefined;
  let project: Project;
  if (morph) {
    sourceText = morph.getSourceText(normalize(absPath));
    project = morph.project;
  } else {
    try {
      sourceText = await readFile(absPath, 'utf8');
    } catch {
      sourceText = undefined;
    }
    project = new TsMorphProject({
      skipAddingFilesFromTsConfig: true,
      compilerOptions: {
        allowJs: true,
        checkJs: false,
        jsx: JsxEmit.ReactJSX,
        target: ScriptTarget.ES2022,
      },
    });
  }

  if (sourceText === undefined) {
    return {
      file: absPath,
      functions,
      issues: [
        issue(
          'ast',
          'LOW',
          'Unreadable source file',
          absPath,
          1,
          'The file could not be read from disk.',
          'Analysis is incomplete for this path.',
          'Fix file permissions or encoding issues.',
        ),
      ],
      edges,
      exports: { named: namedExports, hasDefault: hasDefaultExport },
      imports: [],
    };
  }

  const sourceFile = project.createSourceFile(absPath, sourceText, { overwrite: true });

  // Imports / edges
  const imports: Array<{
    readonly target: string | null;
    readonly named: readonly string[];
    readonly isNamespace: boolean;
    readonly isSideEffectOnly: boolean;
    readonly hasDefaultImport: boolean;
  }> = [];
  for (const decl of sourceFile.getImportDeclarations()) {
    const spec = decl.getModuleSpecifierValue();
    const resolved = resolveLocalImport(absPath, spec);
    if (resolved) {
      const normalized = normalize(resolved);
      if (fileSet.has(normalized)) {
        edges.push({ from: normalize(absPath), to: normalized, specifier: spec });
      }
    }

    const named = decl
      .getNamedImports()
      .map((n) => n.getName())
      .filter((n) => n.length > 0);

    imports.push({
      target: resolved ? normalize(resolved) : null,
      named,
      isNamespace: decl.getNamespaceImport() !== undefined,
      isSideEffectOnly: decl.getNamedImports().length === 0 && decl.getDefaultImport() === undefined && decl.getNamespaceImport() === undefined,
      hasDefaultImport: decl.getDefaultImport() !== undefined,
    });
  }

  // Exports
  if (sourceFile.getExportAssignments().length > 0) {
    hasDefaultExport = true;
  }
  const defaultExportSymbol = sourceFile.getDefaultExportSymbol();
  if (defaultExportSymbol) {
    hasDefaultExport = true;
  }

  for (const name of sourceFile.getExportedDeclarations().keys()) {
    if (name === 'default') {
      hasDefaultExport = true;
    } else {
      namedExports.push(name);
    }
  }

  const visitCallable = (name: string, startLine: number, root: Node): void => {
    const complexity = estimateCyclomaticComplexity(root);
    const nesting = maxBlockNestingDepth(root);
    const endLine = root.getEndLineNumber();
    const lineCount = Math.max(1, endLine - startLine + 1);

    functions.push({
      name,
      file: absPath,
      line: startLine,
      complexity,
      maxNesting: nesting,
      lineCount,
    });

    if (complexity >= MAX_COMPLEXITY) {
      issues.push(
        issue(
          'ast',
          'MEDIUM',
          'High cyclomatic complexity',
          absPath,
          startLine,
          `Function "${name}" has estimated cyclomatic complexity ${String(complexity)} (threshold ${String(MAX_COMPLEXITY)}).`,
          'Harder to test and more defect-prone; changes risk regressions.',
          'Decompose into smaller functions, reduce branching, extract guards early.',
          name,
        ),
      );
    }

    if (nesting >= MAX_NESTING) {
      issues.push(
        issue(
          'ast',
          'MEDIUM',
          'Deep block nesting',
          absPath,
          startLine,
          `Function "${name}" reaches nesting depth ${String(nesting)} (threshold ${String(MAX_NESTING)}).`,
          'Harder to reason about control flow.',
          'Use early returns, extract nested logic into helpers, flatten conditionals.',
          name,
        ),
      );
    }

    if (lineCount >= MAX_FUNCTION_LINES) {
      issues.push(
        issue(
          'ast',
          'LOW',
          'Long function',
          absPath,
          startLine,
          `Function "${name}" spans ~${String(lineCount)} lines (threshold ${String(MAX_FUNCTION_LINES)}).`,
          'Harder maintenance and review load.',
          'Split responsibilities into smaller units with clear names.',
          name,
        ),
      );
    }
  };

  for (const fn of sourceFile.getFunctions()) {
    const name = fn.getName() ?? '<anonymous>';
    visitCallable(name, fn.getStartLineNumber(), fn);
  }

  for (const ctor of sourceFile.getClasses().flatMap((c) => c.getConstructors())) {
    visitCallable('constructor', ctor.getStartLineNumber(), ctor);
  }

  for (const m of sourceFile.getClasses().flatMap((c) => c.getMethods())) {
    const cls = m.getParentIfKind(SyntaxKind.ClassDeclaration);
    const className = cls?.getName() ?? '<anonymous>';
    const methodName = m.getName();
    visitCallable(`${className}.${methodName}`, m.getStartLineNumber(), m);
  }

  return {
    file: absPath,
    functions,
    issues,
    edges,
    exports: { named: namedExports, hasDefault: hasDefaultExport },
    imports,
  };
  };

  if (morph) {
    return morph.runExclusive(run);
  }
  return run();
}

function buildUnusedExportIssues(
  analyses: readonly FileAstAnalysis[],
  fileSet: ReadonlySet<string>,
): Issue[] {
  const issuesLocal: Issue[] = [];
  const usageByFile = new Map<string, { named: Set<string>; default: boolean; namespace: boolean }>();

  const bump = (file: string, patch: Partial<{ named: string; default: boolean; namespace: boolean }>): void => {
    const cur = usageByFile.get(file) ?? { named: new Set<string>(), default: false, namespace: false };
    if (patch.named) {
      cur.named.add(patch.named);
    }
    if (patch.default) {
      cur.default = true;
    }
    if (patch.namespace) {
      cur.namespace = true;
    }
    usageByFile.set(file, cur);
  };

  for (const a of analyses) {
    for (const imp of a.imports) {
      if (!imp.target || !fileSet.has(imp.target)) {
        continue;
      }

      if (imp.isSideEffectOnly) {
        continue;
      }

      if (imp.isNamespace) {
        bump(imp.target, { namespace: true });
      }

      if (imp.hasDefaultImport) {
        bump(imp.target, { default: true });
      }

      for (const n of imp.named) {
        bump(imp.target, { named: n });
      }
    }
  }

  for (const a of analyses) {
    const normalized = normalize(a.file);
    if (!fileSet.has(normalized)) {
      continue;
    }

    if (isEntryLikeFile(a.file)) {
      continue;
    }

    const usage = usageByFile.get(normalized) ?? { named: new Set<string>(), default: false, namespace: false };

    if (a.exports.hasDefault && !usage.default && !usage.namespace) {
      issuesLocal.push(
        issue(
          'ast',
          'LOW',
          'Possibly unused default export',
          a.file,
          1,
          'No other scanned file imported the default export from this module (heuristic).',
          'May indicate dead entrypoints or false positives for dynamic imports.',
          'Verify runtime usage (dynamic import/require). If unused, remove export.',
        ),
      );
    }

    const unusedNamed = a.exports.named.filter((exp) => !usage.named.has(exp) && !usage.namespace);
    if (unusedNamed.length > 0) {
      const preview = unusedNamed.slice(0, 25);
      const suffix =
        unusedNamed.length > preview.length
          ? ` (+${String(unusedNamed.length - preview.length)} more)`
          : '';
      issuesLocal.push(
        issue(
          'ast',
          'LOW',
          'Possibly unused named exports',
          a.file,
          1,
          `These exports were not imported by any scanned relative module (heuristic): ${preview.join(', ')}${suffix}`,
          'Dead code increases bundle and cognitive load; may be false positive across package boundaries.',
          'Confirm usage (public API, barrel files, dynamic imports). Remove or narrow exports if truly unused.',
        ),
      );
    }
  }

  return issuesLocal;
}

export interface AstEngineOptions {
  readonly fileFilter?: ReadonlySet<string>;
  /** When true, skip expensive cross-file heuristics that need a whole-repo view. */
  readonly partial?: boolean;
  /**
   * Reuse per-file AST payloads for unchanged paths; still recomputes graph-level
   * signals when any path in `dirtyPaths` was re-analyzed.
   */
  readonly incremental?: {
    readonly dirtyPaths: ReadonlySet<string>;
    readonly cachedByFile: ReadonlyMap<string, FileAstAnalysis>;
  };
  /** When set, use these normalized absolute paths instead of discovering again. */
  readonly sourceFiles?: readonly string[];
  /** Shared ts-morph project + in-memory sources (scan-runner orchestration). */
  readonly morph?: AstMorphContext;
}

export interface AstEngineRun {
  readonly scan: AstScanResult;
  readonly analyses: readonly FileAstAnalysis[];
}

export async function runAstEngineWithAnalyses(
  cwd: string,
  concurrency: number,
  options?: AstEngineOptions,
): Promise<AstEngineRun> {
  const files =
    options?.sourceFiles && options.sourceFiles.length > 0
      ? [...options.sourceFiles]
      : await discoverSourceFiles(cwd);
  const normalizedAll = files.map((f) => normalize(f));
  const fileSet = new Set(normalizedAll);

  const normalizedFiles = options?.fileFilter
    ? normalizedAll.filter((f) => options.fileFilter?.has(f))
    : normalizedAll;
  const targets = normalizedFiles.length > 0 ? normalizedFiles : normalizedAll;
  const partial = options?.partial === true && targets.length < normalizedAll.length;

  const sortedTargets = [...targets].sort((a, b) => a.localeCompare(b));
  const inc = options?.incremental;

  const morph = options?.morph;
  const morphArg = morph;

  let analyses: FileAstAnalysis[];
  if (inc && sortedTargets.length > 0) {
    const toAnalyze = sortedTargets.filter((f) => inc.dirtyPaths.has(f) || !inc.cachedByFile.has(f));
    const freshList = await runPool(toAnalyze, concurrency, (file) => analyzeFile(file, fileSet, morphArg));
    const freshByPath = new Map<string, FileAstAnalysis>();
    for (let i = 0; i < toAnalyze.length; i += 1) {
      const path = toAnalyze[i];
      const analysis = freshList[i];
      if (path !== undefined && analysis !== undefined) {
        freshByPath.set(path, analysis);
      }
    }
    analyses = await Promise.all(
      sortedTargets.map(async (f) => {
        if (!inc.dirtyPaths.has(f) && inc.cachedByFile.has(f)) {
          const cached = inc.cachedByFile.get(f);
          if (cached !== undefined) {
            return cached;
          }
        }
        const hit = freshByPath.get(f);
        if (hit !== undefined) {
          return hit;
        }
        return analyzeFile(f, fileSet, morphArg);
      }),
    );
  } else {
    analyses = await runPool(sortedTargets, concurrency, (file) => analyzeFile(file, fileSet, morphArg));
  }

  const functions = analyses.flatMap((a) => a.functions);
  const issues = [...analyses.flatMap((a) => a.issues)];
  const importGraph = analyses.flatMap((a) => a.edges);

  if (!partial) {
    issues.push(...buildUnusedExportIssues(analyses, fileSet));
  }

  const circularDependencyChains = findCircularDependencyChains(importGraph, CIRCULAR_CYCLE_CAP);
  const seenCycles = new Set<string>();
  for (const chain of circularDependencyChains) {
    const key = chain.join('->');
    if (seenCycles.has(key)) {
      continue;
    }
    seenCycles.add(key);
    const head = chain[0];
    const headLine = 1;
    issues.push(
      issue(
        'ast',
        'HIGH',
        'Circular dependency detected',
        head ?? cwd,
        headLine,
        `Import cycle: ${chain.join(' -> ')}`,
        'Tight coupling, harder refactors, potential initialization order bugs.',
        'Introduce boundaries, invert dependencies, or extract shared types/utilities.',
      ),
    );
  }

  const scan: AstScanResult = {
    filesAnalyzed: sortedTargets.length,
    functions,
    issues,
    importGraph,
    circularDependencyChains,
  };

  return { scan, analyses };
}

export async function runAstEngine(
  cwd: string,
  concurrency: number,
  options?: AstEngineOptions,
): Promise<AstScanResult> {
  const { scan } = await runAstEngineWithAnalyses(cwd, concurrency, options);
  return scan;
}
