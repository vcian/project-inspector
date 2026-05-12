import assert from 'node:assert/strict';
import { join } from 'node:path';
import os from 'node:os';
import { describe, it } from 'node:test';

import { checkSafeOutDir, PathSafetyError } from './path-safety.js';

const tmp = os.tmpdir();

describe('checkSafeOutDir', () => {
  it('accepts an out dir that is a direct child of the project dir', () => {
    assert.doesNotThrow(() => checkSafeOutDir(join(tmp, 'proj'), join(tmp, 'proj', 'reports')));
  });

  it('accepts a deeply nested sub-directory', () => {
    assert.doesNotThrow(() =>
      checkSafeOutDir(join(tmp, 'proj'), join(tmp, 'proj', 'a', 'b', 'c')),
    );
  });

  it('throws PathSafetyError when out is a sibling (path traversal)', () => {
    assert.throws(
      () => checkSafeOutDir(join(tmp, 'proj'), join(tmp, 'evil')),
      PathSafetyError,
    );
  });

  it('throws PathSafetyError for explicit ../../ traversal', () => {
    assert.throws(
      () => checkSafeOutDir(join(tmp, 'proj'), join(tmp, 'proj', '..', '..', 'etc')),
      PathSafetyError,
    );
  });

  it('throws PathSafetyError for --out ../../../etc style attack', () => {
    assert.throws(
      () => checkSafeOutDir('/app/project', '/etc/passwd'),
      PathSafetyError,
    );
  });
});
