// In-memory rate limiting + brute-force lockout.
// For production, back these with Redis so limits survive restarts
// and apply across instances.

type Bucket = { timestamps: number[] };
const buckets = new Map<string, Bucket>();

/** Sliding-window rate limit. Returns true when the request is allowed. */
export function rateLimit(key: string, max: number, windowMs: number): boolean {
  const cutoff = Date.now() - windowMs;
  const bucket = buckets.get(key) ?? { timestamps: [] };
  bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
  if (bucket.timestamps.length >= max) {
    buckets.set(key, bucket);
    return false;
  }
  bucket.timestamps.push(Date.now());
  buckets.set(key, bucket);
  return true;
}

// Brute-force protection: lock an identity after repeated failed
// biometric verifications.
const failures = new Map<string, { count: number; lockedUntil: number }>();
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60 * 1000;

export function isLocked(identity: string): boolean {
  const f = failures.get(identity);
  return !!f && f.lockedUntil > Date.now();
}

export function recordFailure(identity: string): void {
  const f = failures.get(identity) ?? { count: 0, lockedUntil: 0 };
  f.count += 1;
  if (f.count >= MAX_FAILURES) {
    f.lockedUntil = Date.now() + LOCK_MS;
    f.count = 0;
  }
  failures.set(identity, f);
}

export function clearFailures(identity: string): void {
  failures.delete(identity);
}
