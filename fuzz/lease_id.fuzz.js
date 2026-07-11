// Fuzz the egress lease-handling entry points with arbitrary/hostile "lease
// ids". These are the functions an attacker-influenced id reaches at redeem
// time; the fail-safe contract is that they NEVER throw and ALWAYS fail closed
// (no secret, ok:false / falsey) on anything that isn't a real, valid lease.
// A hostile id here can never be a real one (ids are 144-bit and single-use),
// so every call in this harness must deny.
import { redeem, revoke } from '../src/index.mjs';
import { checkLease, peekLease } from '../src/lease.mjs';

export function fuzz(data) {
  const id = data.toString('utf8');

  const r = redeem(id);
  if (r.ok) throw new Error(`redeem accepted a fuzzed id: ${JSON.stringify(id)}`);
  if ('value' in r && r.value != null) throw new Error(`redeem leaked a value on a denied id: ${JSON.stringify(id)}`);

  const c = checkLease(id);
  if (c.ok) throw new Error(`checkLease accepted a fuzzed id: ${JSON.stringify(id)}`);

  const pk = peekLease(id);
  if (pk.ok) throw new Error(`peekLease accepted a fuzzed id: ${JSON.stringify(id)}`);

  // revoke must be a no-throw boolean (nothing to revoke → false)
  if (revoke(id) !== false) throw new Error(`revoke claimed to remove a fuzzed id: ${JSON.stringify(id)}`);
}
