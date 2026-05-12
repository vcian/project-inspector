import { basename } from 'node:path';

/** Real-time file-scan progress reporter for TTY output. */
export class ScanProgress {
  private readonly total: number;
  private current = 0;
  private readonly startMs: number;
  private readonly tty: boolean;

  constructor(total: number) {
    this.total = total;
    this.startMs = Date.now();
    this.tty = process.stdout.isTTY === true;
  }

  tick(filePath: string): void {
    this.current += 1;
    if (!this.tty) return;
    const pct = Math.round((this.current / Math.max(this.total, 1)) * 100);
    const elapsed = Date.now() - this.startMs;
    const etaMs =
      this.current > 0
        ? (elapsed / this.current) * (this.total - this.current)
        : -1;
    const etaStr = etaMs >= 0 ? `  ~${String(Math.round(etaMs / 1000))}s remaining` : '';
    process.stdout.write(
      `\r\x1b[K[${String(pct).padStart(3)}%] Scanning ${String(this.current)}/${String(this.total)}: ${basename(filePath)}${etaStr}`,
    );
  }

  status(message: string): void {
    if (!this.tty) return;
    process.stdout.write(`\r\x1b[K  ${message}`);
  }

  complete(): void {
    if (!this.tty) return;
    process.stdout.write('\r\x1b[K');
  }
}
