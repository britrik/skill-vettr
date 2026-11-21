import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isExcluded } from '../utils/vettrignore.js';

describe('vettrignore directory patterns', () => {
  it('anchors directory patterns with an internal slash to the scan root', () => {
    assert.equal(isExcluded('test/fixtures/payload.js', ['test/fixtures/']), true);
    assert.equal(isExcluded('src/test/fixtures/payload.js', ['test/fixtures/']), false);
  });

  it('matches bare directory names anywhere in the tree', () => {
    assert.equal(isExcluded('src/fixtures/payload.js', ['fixtures/']), true);
  });
});
