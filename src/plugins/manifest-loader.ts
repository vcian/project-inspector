import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

/** Plugin manifest v1 — JSON only, no arbitrary code execution. */
export interface PluginManifestV1 {
  readonly version: 1 | 2;
  readonly name: string;
  readonly pluginVersion?: string;
  readonly suppressTitleSubstrings?: readonly string[];
}

export async function collectPluginSuppressPatterns(projectRoot: string): Promise<readonly string[]> {
  const pluginsRoot = join(projectRoot, 'plugins');
  const patterns: string[] = [];
  try {
    const entries = await readdir(pluginsRoot, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) {
        continue;
      }
      const manifestPath = join(pluginsRoot, ent.name, 'plugin.manifest.json');
      try {
        const raw = await readFile(manifestPath, 'utf8');
        const parsed = JSON.parse(raw) as unknown;
        if (typeof parsed !== 'object' || parsed === null) {
          continue;
        }
        const m = parsed as Partial<PluginManifestV1> & Partial<{ readonly version: number }>;
        if ((m.version !== 1 && m.version !== 2) || typeof m.name !== 'string') {
          continue;
        }
        if (Array.isArray(m.suppressTitleSubstrings)) {
          for (const s of m.suppressTitleSubstrings) {
            if (typeof s === 'string' && s.length > 0) {
              patterns.push(s);
            }
          }
        }
      } catch {
        /* missing or invalid manifest */
      }
    }
  } catch {
    /* no plugins dir */
  }
  return patterns;
}
