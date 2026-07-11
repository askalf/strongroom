// Fuzz the broker's request-target canonicalizer. This is the parser that
// decides which path the allowlist authorizes AND which path leaves the box —
// a differential or a throw here is a security bug (allowlist bypass / broker
// crash). Invariants: it never throws on arbitrary bytes, and it always returns
// a normalized path that starts with '/' (so a `..`/percent-decode trick can't
// produce an un-anchored path the allowlist then mis-judges).
import { canonicalize } from '../src/broker.mjs';

export function fuzz(data) {
  const rest = data.toString('utf8');
  const r = canonicalize(rest);
  if (typeof r.path !== 'string' || !r.path.startsWith('/')) {
    throw new Error(`canonicalize produced a non-anchored path for ${JSON.stringify(rest)}: ${JSON.stringify(r)}`);
  }
  // The normalized path must not still contain a `..` segment that could climb
  // above an allowlisted prefix after authorization.
  if (r.path.split('/').includes('..')) {
    throw new Error(`canonicalize left a '..' segment in ${JSON.stringify(r.path)}`);
  }
}
