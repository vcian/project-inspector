import { mkdir, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

import { gatherAllIssues } from '../core/issue-collect.js';
import type { Issue, ScanResult } from '../core/types.js';

function levelForSeverity(severity: Issue['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return 'error';
  }
  if (severity === 'MEDIUM') {
    return 'warning';
  }
  return 'note';
}

export async function writeSarifReport(result: ScanResult, outDir: string): Promise<void> {
  const issues = result.trustedIssues !== undefined ? [...result.trustedIssues] : gatherAllIssues(result);
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();

  for (const issue of issues) {
    const ruleId = issue.code ?? issue.id;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: issue.title,
        shortDescription: { text: issue.description },
      });
    }
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0' as const,
    runs: [
      {
        tool: {
          driver: {
            name: 'project-inspector',
            version: '0.3.0',
            rules: [...rules.values()],
          },
        },
        results: issues.map((issue) => ({
          ruleId: issue.code ?? issue.id,
          level: levelForSeverity(issue.severity),
          message: {
            text: `${issue.title}: ${issue.description}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: relative(result.cwd, issue.file).replaceAll('\\', '/'),
                },
                region: {
                  startLine: Math.max(1, issue.line),
                },
              },
            },
          ],
        })),
      },
    ],
  };

  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'results.sarif'), `${JSON.stringify(sarif, null, 2)}\n`, 'utf8');
}
