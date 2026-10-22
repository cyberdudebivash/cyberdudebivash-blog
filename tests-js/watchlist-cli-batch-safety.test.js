'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseBatchArg, MAX_GITHUB_EVALUATION_BATCH } = require('../scripts/evaluate-watchlist-changes');

test('default bridge evaluation batch remains unchanged', () => {
  assert.equal(parseBatchArg([]), undefined);
  assert.equal(MAX_GITHUB_EVALUATION_BATCH, 200);
});

test('accepts exact in-range positive decimal integers', () => {
  for (const n of [1, 2, 10, 50, 199, 200]) {
    assert.equal(parseBatchArg([`--batch=${n}`]), n);
  }
});

test('fail closed on malformed, oversized, duplicated, empty or partially numeric inputs', () => {
  const invalid = [
    ['--batch'], ['--batch='], ['--batch=0'], ['--batch=-1'], ['--batch=201'],
    ['--batch=9999999999999999999999999'], ['--batch=2abc'], ['--batch=2.5'],
    ['--batch=+2'], ['--batch= 2'], ['--batch=02'], ['--batch=1e2'],
    ['--batch=NaN'], ['--batch=Infinity'], ['--batch=1','--batch=2'],
    ['--batch=1','--batch'], ['--batch=1','--batch=1']
  ];
  for (const argv of invalid) {
    assert.throws(() => parseBatchArg(argv), /Invalid --batch/, JSON.stringify(argv));
  }
});

test('unrelated command arguments cannot bypass batch validation', () => {
  assert.equal(parseBatchArg(['--mode=read-only', '--batch=10']), 10);
  assert.throws(() => parseBatchArg(['--batch=201', '--mode=read-only']), /Invalid --batch/);
});
