import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export interface LoadedPlugin {
  readonly name: string;
  readonly rootDir: string;
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
