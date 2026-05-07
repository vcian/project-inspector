import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/** Minimal CycloneDX 1.5 JSON SBOM from npm `package-lock.json` v2/v3. */
export async function writeCycloneDxSbom(cwd: string, outPath: string): Promise<boolean> {
  const lockPath = join(cwd, 'package-lock.json');
  try {
    const raw = await readFile(lockPath, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const lockVerRaw = parsed.lockfileVersion;
    const lockVerStr =
      typeof lockVerRaw === 'number' || typeof lockVerRaw === 'string'
        ? String(lockVerRaw)
        : 'unknown';
    const rootName = typeof parsed.name === 'string' ? parsed.name : 'project';
    const rootVersion = typeof parsed.version === 'string' ? parsed.version : '0.0.0';
    const pkgs = parsed.packages as Record<string, { name?: string; version?: string; license?: string }> | undefined;
    const components: unknown[] = [];
    if (pkgs !== undefined) {
      for (const [pathKey, meta] of Object.entries(pkgs)) {
        if (pathKey === '') {
          continue;
        }
        const name = meta.name ?? pathKey.split('node_modules/').pop() ?? pathKey;
        const version = meta.version ?? '0.0.0';
        const comp: Record<string, unknown> = {
          type: 'library',
          name,
          version,
          'bom-ref': `${name}@${version}`,
        };
        if (typeof meta.license === 'string') {
          comp.licenses = [{ license: { id: meta.license } }];
        }
        components.push(comp);
      }
    }
    const bom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          type: 'application',
          name: rootName,
          version: rootVersion,
        },
        properties: [{ name: 'project-inspector:lockfileVersion', value: lockVerStr }],
      },
      components,
    };
    const { writeFile, mkdir } = await import('node:fs/promises');
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, `${JSON.stringify(bom, null, 2)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}
