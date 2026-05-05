import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Issue, ScanResult } from '../core/types.js';
import { gatherAllIssues } from '../core/issue-collect.js';

function severityToLevel(severity: Issue['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'CRITICAL' || severity === 'HIGH') {
    return 'error';
  }
  if (severity === 'MEDIUM') {
    return 'warning';
  }
  return 'note';
}

/** SARIF 2.1.0 export for GitHub Code Scanning and compatible viewers. */
export async function writeSarifResults(outDir: string, scan: ScanResult): Promise<void> {
  const issues = gatherAllIssues(scan);
  const results = issues.map((issue) => ({
    ruleId: issue.id,
    level: severityToLevel(issue.severity),
    message: { text: `${issue.title}: ${issue.description}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: issue.file.replaceAll('\\', '/') },
          region: { startLine: Math.max(1, issue.line) },
        },
      },
    ],
  }));

  const doc = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0' as const,
    runs: [
      {
        properties: { sarifSchemaVersion: '2.1.0' },
        tool: {
          driver: {
            name: 'project-inspector',
            version: '0.3.0',
            rules: [],
          },
        },
        results,
      },
    ],
  };

  await writeFile(join(outDir, 'results.sarif'), `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
}
