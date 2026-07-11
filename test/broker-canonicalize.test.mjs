// Regression tests for two broker-parser bugs surfaced by the fuzz targets
// (fuzz/canonicalize.fuzz.js, fuzz/path_allowed.fuzz.js). These pin the fixes
// in the always-on unit suite; the fuzzers keep hunting for new ones in CI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, pathAllowed } from '../src/broker.mjs';

test('canonicalize clamps every `..` at root and always returns an anchored path', () => {
  // The fuzzer found `..` → `/..` — a `..` segment surviving canonicalization,
  // which could climb above an allowlisted prefix. Now clamped at `/`.
  assert.equal(canonicalize('..').path, '/');
  assert.equal(canonicalize('a/../..').path, '/');
  assert.equal(canonicalize('/..').path, '/');
  assert.equal(canonicalize('/../../etc').path, '/etc');
  assert.equal(canonicalize('/v1/chat/../admin/keys').path, '/v1/admin/keys'); // still resolves normal `..`
  assert.equal(canonicalize('').path, '/');
  assert.equal(canonicalize('.').path, '/');
  // invariant the fuzz target asserts: anchored, no residual `..`
  for (const s of ['..', '/..', 'a/b/../..', '%2e%2e', '/./..', '....//']) {
    const r = canonicalize(s);
    assert.ok(r.path.startsWith('/'), `not anchored: ${s} → ${r.path}`);
    assert.ok(!r.path.split('/').includes('..'), `residual '..': ${s} → ${r.path}`);
  }
});

test('pathAllowed never throws on a pattern with regex metacharacters (fail closed)', () => {
  // The fuzzer found a `?` in a --paths glob threw `SyntaxError: Nothing to
  // repeat` (the escape set missed `?`), 502-ing every request on that lease.
  // `?` is not a keeper wildcard (only `*` is) — it's now a literal, and any
  // un-compilable pattern matches nothing instead of throwing.
  assert.doesNotThrow(() => pathAllowed('/v1/models', ['/v1/models?']));
  assert.equal(pathAllowed('/v1/models', ['/v1/models?']), false, '`?` is a literal → no match on a `?`-free path');
  // in the real broker the path is canonicalized (query stripped) before this,
  // so a `?`-bearing pattern is effectively dead — it can never match a real path
  assert.equal(pathAllowed(canonicalize('/v1/models?token=x').path, ['/v1/models?']), false, 'canonicalized path has no query for the literal `?` to match');
  for (const bad of ['?', '+', '(', '[', '\\', '*?+', '{2,', 'a)b']) {
    assert.doesNotThrow(() => pathAllowed('/anything', [bad]), `threw on pattern ${JSON.stringify(bad)}`);
    assert.equal(typeof pathAllowed('/anything', [bad]), 'boolean');
  }
  // the normal glob semantics still hold
  assert.equal(pathAllowed('/v1/chat/completions', ['/v1/chat/*']), true);
  assert.equal(pathAllowed('/v1/admin/keys', ['/v1/chat/*']), false);
  assert.equal(pathAllowed('/v1/models', ['/v1/models']), true);
});
