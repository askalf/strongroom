#!/bin/bash -eu
# Build the Jazzer.js fuzz targets for ClusterFuzzLite / OSS-Fuzz.
# Each target is an ESM module exporting `fuzz(data)`; the invariants are the
# security-critical ones — the broker path canonicalizer/allowlist never throws
# and never leaves a climbing `..`, and the egress lease entry points always
# fail closed on a hostile id.
cd "$SRC/strongroom"
npm install --no-audit --no-fund

for target in canonicalize path_allowed lease_id; do
  compile_javascript_fuzzer strongroom "fuzz/${target}.fuzz.js" --sync
done
