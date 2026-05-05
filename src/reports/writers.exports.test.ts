import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ALL_REPORT_SECTIONS, inferApiOperationId } from './writers.js';

describe('writers exports', () => {
  it('inferApiOperationId produces stable snake_case ids', () => {
    const id = inferApiOperationId('GET', '/api/users/:id');
    assert.match(id, /^get_/);
    assert.ok(id.includes('users'), id);
  });

  it('ALL_REPORT_SECTIONS omits legacy split markdown sections', () => {
    const current = new Set<string>([...ALL_REPORT_SECTIONS]);
    const legacy = ['memory', 'migration', 'compliance', 'attack-scenarios', 'hotspots'] as const;
    for (const id of legacy) {
      assert.equal(current.has(id), false, `unexpected legacy section ${id}`);
    }
  });
});
