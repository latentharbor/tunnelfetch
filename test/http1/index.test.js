// The public surface of src/http1: a broken re-export would pass every deep test and still
// ship an unusable layer, so the barrel is asserted directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http1 from '../../src/http1/index.js';

test('http1 index exports the four entry points and nothing surprising', () => {
  assert.equal(typeof http1.serializeRequestHead, 'function');
  assert.equal(typeof http1.readResponseHead, 'function');
  assert.equal(typeof http1.bodyFraming, 'function');
  assert.equal(typeof http1.readResponseBody, 'function');
  assert.equal(typeof http1.decodeChunked, 'function');
  assert.deepEqual(Object.keys(http1).sort(), [
    'bodyFraming',
    'decodeChunked',
    'readResponseBody',
    'readResponseHead',
    'serializeRequestHead',
  ]);
});
