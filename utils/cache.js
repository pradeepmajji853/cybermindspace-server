/**
 * In-memory TTL cache for scan results. Keyed by `${type}:${target}`.
 * Single-process only — fine for the ₹499 SaaS tier; swap for Redis at scale.
 */
const STORE = new Map();
const DEFAULT_TTL_MS = 10 * 60 * 1000;

function get(key) {
  const entry = STORE.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    STORE.delete(key);
    return null;
  }
  return entry.value;
}

function set(key, value, ttlMs = DEFAULT_TTL_MS) {
  STORE.set(key, { value, expiresAt: Date.now() + ttlMs });
  if (STORE.size > 500) {
    const oldestKey = STORE.keys().next().value;
    STORE.delete(oldestKey);
  }
  return value;
}

async function memo(key, ttlMs, producer) {
  const hit = get(key);
  if (hit) return { value: hit, cached: true };
  const value = await producer();
  set(key, value, ttlMs);
  return { value, cached: false };
}

module.exports = { get, set, memo };
