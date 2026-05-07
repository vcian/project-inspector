import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { InspectorConfig } from './inspector-config.js';

interface PolicyPackFile {
  readonly extraSuppressTitleSubstrings?: readonly string[];
  readonly extraIgnorePathGlobs?: readonly string[];
}

/**
 * Optional named policy overlay (HIPAA, SOC2, etc.) from `packs/<id>.json` or `project-inspector-packs/<id>.json`.
 */
export async function mergePolicyPack(cwd: string, base: InspectorConfig): Promise<InspectorConfig> {
  const id = base.policyPack?.trim();
  if (id === undefined || id.length === 0) {
    return base;
  }
  const candidates = [join(cwd, 'project-inspector-packs', `${id}.json`), join(cwd, 'packs', `${id}.json`)];
  let raw: string | undefined;
  for (const p of candidates) {
    try {
      raw = await readFile(p, 'utf8');
      break;
    } catch {
      /* try next */
    }
  }
  if (raw === undefined) {
    return base;
  }
  const parsed: unknown = JSON.parse(raw) as unknown;
  if (typeof parsed !== 'object' || parsed === null) {
    return base;
  }
  const pack = parsed as PolicyPackFile;
  const extraSub: string[] = Array.isArray(pack.extraSuppressTitleSubstrings)
    ? pack.extraSuppressTitleSubstrings.filter((x): x is string => typeof x === 'string' && x.length > 0)
    : [];
  const extraIgn: string[] = Array.isArray(pack.extraIgnorePathGlobs)
    ? pack.extraIgnorePathGlobs.filter((x): x is string => typeof x === 'string' && x.length > 0)
    : [];
  if (extraSub.length === 0 && extraIgn.length === 0) {
    return base;
  }
  return {
    ...base,
    suppressTitleSubstrings: [...base.suppressTitleSubstrings, ...extraSub],
    ignorePathGlobs: [...base.ignorePathGlobs, ...extraIgn],
  };
}
