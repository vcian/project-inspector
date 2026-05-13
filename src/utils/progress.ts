import { relative, basename } from 'node:path';

import chalk from 'chalk';

/**
 * Unified 0→100% real-time scan progress.
 *
 * Each phase gets a pre-allocated percentage slice. Ticks within a phase
 * advance the global percentage through that slice — the number never resets.
 *
 * Output (TTY only):
 *   [Security ] [ 45%] Scanning file  90/200: src/auth/service.ts  ~8s remaining
 */
export class ScanProgress {
  private readonly cwd: string;
  private readonly tty: boolean;
  private readonly startMs: number;

  // Current displayed percentage — NEVER decreases.
  private displayPct = 0;

  // Active phase state.
  private phaseLabel = '';
  private phaseStart = 0;   // global pct at phase start
  private phaseEnd = 0;     // global pct at phase end
  private phaseFileTotal = 0;
  private phaseFileCurrent = 0;

  private lastRender = 0;
  private spinFrame = 0;

  private static readonly SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

  constructor(cwd: string) {
    this.cwd = cwd;
    this.tty = process.stdout.isTTY === true;
    this.startMs = Date.now();
  }

  /**
   * Start a new phase.
   * @param label      Short name shown in brackets, e.g. "Hashing"
   * @param fileTotal  Number of files this phase processes
   * @param pctStart   Global % where this phase begins (0–100)
   * @param pctEnd     Global % where this phase ends   (0–100)
   */
  beginPhase(label: string, fileTotal: number, pctStart: number, pctEnd: number): void {
    this.phaseLabel = label;
    this.phaseStart = pctStart;
    this.phaseEnd = pctEnd;
    this.phaseFileTotal = Math.max(fileTotal, 1);
    this.phaseFileCurrent = 0;
    // Jump display to phase start if we haven't reached it yet.
    if (this.displayPct < pctStart) this.displayPct = pctStart;
  }

  /** Advance by one file and redraw the progress line. */
  tick(filePath: string): void {
    this.phaseFileCurrent += 1;

    // Map phase-local progress into the global percentage slice.
    const phaseProgress = this.phaseFileCurrent / this.phaseFileTotal;
    const computed = Math.round(
      this.phaseStart + phaseProgress * (this.phaseEnd - this.phaseStart),
    );
    // Only ever advance — never go backwards.
    if (computed > this.displayPct) this.displayPct = computed;

    if (!this.tty) return;

    // Throttle to ~30 fps.
    const now = Date.now();
    if (this.phaseFileCurrent < this.phaseFileTotal && now - this.lastRender < 33) return;
    this.lastRender = now;

    this.renderFile(filePath, now);
  }

  /**
   * Show a status message (used between per-file phases).
   * @param message Human-readable phase description.
   * @param jumpTo  Optional global % to jump to (e.g. 50 for "now at 50%").
   */
  status(message: string, jumpTo?: number): void {
    if (jumpTo !== undefined && jumpTo > this.displayPct) {
      this.displayPct = jumpTo;
    }
    if (!this.tty) return;
    const spin = ScanProgress.SPIN[this.spinFrame % ScanProgress.SPIN.length] ?? '⠋';
    this.spinFrame += 1;
    const pctLabel = chalk.cyan(`[${String(this.displayPct).padStart(3)}%]`);
    process.stdout.write(`\r\x1b[K${chalk.cyan(spin)} ${pctLabel} ${chalk.dim(message)}`);
  }

  /** Erase the progress line (call after scan completes). */
  complete(): void {
    this.displayPct = 100;
    if (!this.tty) return;
    process.stdout.write('\r\x1b[K');
  }

  private renderFile(filePath: string, now: number): void {
    const elapsed = now - this.startMs;
    const remaining = 100 - this.displayPct;
    const etaMs =
      this.displayPct > 0 && remaining > 0
        ? (elapsed / this.displayPct) * remaining
        : -1;
    const etaStr =
      etaMs > 800
        ? chalk.dim(`  ~${String(Math.ceil(etaMs / 1000))}s remaining`)
        : '';

    const displayPath =
      this.cwd.length > 0
        ? relative(this.cwd, filePath).replaceAll('\\', '/')
        : basename(filePath);

    const totalStr = String(this.phaseFileTotal);
    const pad = totalStr.length;
    const pctLabel = chalk.cyan(`[${String(this.displayPct).padStart(3)}%]`);
    const phaseLabel = chalk.magenta(
      `[${this.phaseLabel.padEnd(8).slice(0, 8)}]`,
    );
    const counter = chalk.dim(
      `${String(this.phaseFileCurrent).padStart(pad)}/${totalStr}`,
    );

    process.stdout.write(
      `\r\x1b[K${phaseLabel} ${pctLabel} Scanning file ${counter}: ${chalk.yellow(displayPath)}${etaStr}`,
    );
  }
}
