import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';
import { after, before, describe, it } from 'node:test';

import { runSecurityEngine } from './security-engine.js';

let testDir: string;

before(async () => {
  testDir = join(os.tmpdir(), `pi-sec-test-${randomUUID()}`);
  await mkdir(testDir, { recursive: true });
});

after(async () => {
  await rm(testDir, { recursive: true, force: true });
});

async function writeSource(name: string, source: string): Promise<string> {
  const filePath = join(testDir, name);
  await writeFile(filePath, source, 'utf8');
  return filePath;
}

describe('runSecurityEngine — eval detection', () => {
  it('flags eval() usage', async () => {
    const fp = await writeSource('eval-test.ts', `
const userInput = req.body.code;
const result = eval(userInput);
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    assert.ok(
      issues.some((i) => i.id.includes('eval')),
      `expected eval issue; got ids: ${JSON.stringify(issues.map((i) => i.id))}`,
    );
  });

  it('does not flag code that only mentions eval in natural language (no call site)', async () => {
    const fp = await writeSource('eval-comment.ts', `
// Avoid dynamic code generation patterns for security reasons.
const safeCompute = compute(input);
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    const evalIssues = issues.filter((i) => i.id.includes('security:eval:'));
    assert.equal(evalIssues.length, 0, 'natural-language mention without a call site should not trigger eval rule');
  });
});

describe('runSecurityEngine — hardcoded secrets', () => {
  it('flags a Slack token pattern', async () => {
    const fp = await writeSource('slack-secret.ts', `
const SLACK_TOKEN = 'xoxb-1234567890-ABCDEFGHIJ-abcdefghijklmnop';
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    assert.ok(
      issues.some((i) => i.id.includes('slack-token')),
      `expected slack-token; got: ${JSON.stringify(issues.map((i) => i.id))}`,
    );
    const issue = issues.find((i) => i.id.includes('slack-token'))!;
    assert.equal(issue.severity, 'CRITICAL');
  });

  it('flags a GitHub personal access token pattern', async () => {
    const fp = await writeSource('gh-token.ts', `
const token = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234';
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    assert.ok(
      issues.some((i) => i.id.includes('github-token')),
      `expected github-token; got: ${JSON.stringify(issues.map((i) => i.id))}`,
    );
  });
});

describe('runSecurityEngine — CORS wildcard', () => {
  it('flags a static wildcard origin', async () => {
    const fp = await writeSource('cors-wildcard.ts', `
app.use(cors({ origin: '*' }));
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    assert.ok(
      issues.some((i) => i.id.includes('cors-wildcard')),
      `expected cors-wildcard; got: ${JSON.stringify(issues.map((i) => i.id))}`,
    );
  });

  it('does not flag a specific allowed origin', async () => {
    const fp = await writeSource('cors-specific.ts', `
app.use(cors({ origin: 'https://app.example.com' }));
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    const corsIssues = issues.filter((i) => i.id.includes('cors-wildcard'));
    assert.equal(corsIssues.length, 0);
  });
});

describe('runSecurityEngine — no false positives', () => {
  it('produces no issues for clean code', async () => {
    const fp = await writeSource('clean.ts', `
import { hash, compare } from 'bcrypt';
import { readFile } from 'fs/promises';

export async function login(password: string, hash: string): Promise<boolean> {
  return compare(password, hash);
}
`);
    const { issues } = await runSecurityEngine(testDir, 1, { sourceFiles: [fp] });
    assert.equal(
      issues.length,
      0,
      `clean code should have 0 issues; got: ${JSON.stringify(issues.map((i) => i.id))}`,
    );
  });
});
