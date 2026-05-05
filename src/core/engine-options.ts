export interface FileFilterOptions {
  readonly fileFilter?: ReadonlySet<string>;
  /** Normalized absolute paths (skip discovery when provided). */
  readonly sourceFiles?: readonly string[];
  /** In-memory UTF-8 contents keyed by normalized absolute path. */
  readonly getSourceText?: (normalizedAbs: string) => string | undefined;
}
