import { rm } from 'node:fs/promises';

export async function clearProjectReportDir(outDir: string): Promise<void> {
  await rm(outDir, { recursive: true, force: true });
}
