import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export interface LoadedPlugin {
  readonly name: string;
  readonly rootDir: string;
}

/**
 * Plugin manifest contract v2 — JSON declarative rule packs only (no arbitrary JS execution).
 * Hooks are **intent markers** for downstream tooling; core honors suppress patterns only.
 */
export interface PluginManifestV2 {
  readonly version: 2;
  readonly name: string;
  /** SemVer pin reported in diagnostics / SBOM metadata. */
  readonly semver?: string;
  readonly suppressTitleSubstrings?: readonly string[];
  /** Lifecycle phases this pack participates in (documentation / CI orchestration). */
  readonly lifecycleHooks?: readonly ('scan:start' | 'scan:end' | 'report:emit')[];
  /** Optional pinned inspector peer range for CI drift detection (informational). */
  readonly inspectorPeerRange?: string;
}

export interface PluginSdkContract {
  readonly manifestPath: string;
  readonly manifest: PluginManifestV2;
}

export function isPluginManifestV2(raw: unknown): raw is PluginManifestV2 {
  if (typeof raw !== 'object' || raw === null) {
    return false;
  }
  const m = raw as Partial<PluginManifestV2>;
  return m.version === 2 && typeof m.name === 'string';
}

/**
 * Discover plugin folders under `<project>/plugins/*` without executing untrusted code.
 */
export async function loadPlugins(projectRoot: string): Promise<readonly LoadedPlugin[]> {
  const pluginsRoot = resolve(projectRoot, 'plugins');
  const loaded: LoadedPlugin[] = [];

  try {
    const entries = await readdir(pluginsRoot, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) {
        continue;
      }
      loaded.push({ name: ent.name, rootDir: join(pluginsRoot, ent.name) });
    }
  } catch {
    // Missing plugins directory is fine.
  }

  return loaded;
}

export async function resolvePluginManifest(pluginRoot: string): Promise<PluginSdkContract | undefined> {
  const manifestPath = join(pluginRoot, 'plugin.manifest.json');
  try {
    const { readFile } = await import('node:fs/promises');
    const raw = JSON.parse(await readFile(manifestPath, 'utf8')) as unknown;
    if (isPluginManifestV2(raw)) {
      return { manifestPath, manifest: raw };
    }
  } catch {
    /* invalid */
  }
  return undefined;
}
