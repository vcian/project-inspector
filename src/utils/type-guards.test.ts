import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseJson, isRecord, isDependencySnapshotV1, isVulnDbMeta } from './type-guards.js';

describe('parseJson', () => {
  it('returns parsed value when the guard passes', () => {
    const result = parseJson<{ ok: boolean }>(
      '{"ok":true}',
      (v): v is { ok: boolean } => isRecord(v) && typeof v['ok'] === 'boolean',
      { ok: false },
    );
    assert.deepEqual(result, { ok: true });
  });

  it('returns the fallback when the guard fails', () => {
    const fallback = { ok: false };
    const result = parseJson<{ ok: boolean }>(
      '{"bad":1}',
      (v): v is { ok: boolean } => isRecord(v) && typeof v['ok'] === 'boolean',
      fallback,
    );
    assert.strictEqual(result, fallback);
  });

  it('returns the fallback on malformed JSON without throwing', () => {
    const fallback = { ok: false };
    const result = parseJson<{ ok: boolean }>(
      '{not json at all',
      (v): v is { ok: boolean } => isRecord(v),
      fallback,
    );
    assert.strictEqual(result, fallback);
  });

  it('returns the fallback when JSON is null', () => {
    const fallback = { ok: false };
    const result = parseJson<{ ok: boolean }>(
      'null',
      (v): v is { ok: boolean } => isRecord(v),
      fallback,
    );
    assert.strictEqual(result, fallback);
  });
});

describe('isDependencySnapshotV1', () => {
  const valid = {
    version: 1,
    packageJsonSha256: 'abc123',
    lockfileKind: 'npm',
    treeFingerprint: 'def456',
  };

  it('accepts a fully-valid snapshot', () => {
    assert.ok(isDependencySnapshotV1(valid));
  });

  it('rejects a snapshot with version !== 1', () => {
    assert.equal(isDependencySnapshotV1({ ...valid, version: 2 }), false);
  });

  it('rejects a snapshot missing packageJsonSha256', () => {
    const { packageJsonSha256: _, ...rest } = valid;
    assert.equal(isDependencySnapshotV1(rest), false);
  });

  it('rejects null', () => {
    assert.equal(isDependencySnapshotV1(null), false);
  });

  it('rejects a plain string', () => {
    assert.equal(isDependencySnapshotV1('snapshot'), false);
  });
});

describe('isVulnDbMeta', () => {
  it('accepts an empty object', () => {
    assert.ok(isVulnDbMeta({}));
  });

  it('accepts a record with a string fetchedAt', () => {
    assert.ok(isVulnDbMeta({ fetchedAt: '2025-01-01T00:00:00Z' }));
  });

  it('rejects a record where fetchedAt is a number', () => {
    assert.equal(isVulnDbMeta({ fetchedAt: 1234567890 }), false);
  });

  it('rejects null', () => {
    assert.equal(isVulnDbMeta(null), false);
  });

  it('rejects an array', () => {
    assert.equal(isVulnDbMeta([]), false);
  });
});
