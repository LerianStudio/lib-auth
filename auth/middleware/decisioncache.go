package middleware

import (
	"crypto/sha256"
	"hash/fnv"
	"sync"
	"time"
)

// decisionCacheShards is the fixed shard count. Sharding spreads lock contention
// across the authorization hot path so a single mutex is not serialized on every
// authorized request. Fixed (not configurable) — 16 is ample for the expected
// concurrency and keeps the type dependency-free.
const decisionCacheShards = 16

// decisionCacheMaxPerShard bounds memory under a burst of distinct subjects.
// ponytail: soft cap with sweep-on-write + single eviction, not an LRU; the short
// TTL makes entries self-expire quickly, so this only guards a pathological
// cardinality spike. Raise it (or swap for an LRU) only if eviction pressure shows
// up in practice.
const decisionCacheMaxPerShard = 1024

// cacheKey identifies an authorization decision by the inputs that determine it —
// the exact fields sent to the authz service — PLUS the identity of the bearer token
// those inputs were derived from. It never holds the raw token, only its digest.
type cacheKey struct {
	// tokenDigest binds the entry to the exact token the authz service accepted.
	//
	// Without it the cache substitutes for authentication. Local JWT verification is
	// opt-in (AUTH_JWT_VERIFY_CERT / AUTH_JWT_VERIFY_CERT_PATH / WithKeySource) and
	// OFF by default; on that path claims come from ParseUnverified, so the authz
	// round-trip — which carries the raw token — is the only thing that ever checks
	// the signature. Keying on the derived claims alone means a caller can warm the
	// cache with a genuine token and then replay the same request with a forged or
	// payload-edited one: identical sub/resource/action/product/IP, identical key,
	// cache hit, authz service never consulted. Digesting the token makes a forged
	// token a cache MISS, so it reaches the verifier and is denied.
	//
	// It is a SHA-256 digest, not the token: a bearer secret must not sit in a map
	// key. The cost is hit rate — two tokens for the same subject no longer share an
	// entry — which is the correct trade against an authentication bypass.
	tokenDigest [sha256.Size]byte

	sub      string
	resource string
	action   string
	product  string
	// clientIP scopes the decision to the source IP it was made for. The
	// /v1/authorize decision is IP-dependent (tenant IP-allowlist), so omitting it
	// would let an "authorized" decision cached for an allowed IP be served to a
	// request from a blocked IP with the same {sub,resource,action,product} —
	// bypassing the allowlist. Empty (gRPC / no forwarded IP) keys as "", unchanged
	// from before. This trades a little hit rate for correctness, which is required.
	clientIP string
}

// cacheEntry is a cached authorization decision with its expiry.
type cacheEntry struct {
	authorized bool
	expiresAt  time.Time
}

type cacheShard struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
}

// decisionCache is a bounded, sharded, TTL authorization-decision cache. Expiry is
// lazy (checked on read, swept on write) so there is no background goroutine to
// leak. get never returns an expired entry, which is what keeps the breaker-open
// fallback fail-closed: a stale grant is never served.
type decisionCache struct {
	ttl    time.Duration
	shards [decisionCacheShards]*cacheShard
}

// newDecisionCache builds an enabled cache with the given TTL. ttl must be > 0
// (callers gate on that before constructing).
func newDecisionCache(ttl time.Duration) *decisionCache {
	c := &decisionCache{ttl: ttl}
	for i := range c.shards {
		c.shards[i] = &cacheShard{entries: make(map[cacheKey]cacheEntry)}
	}

	return c
}

// shardFor selects the shard for a key by hashing its fields with a separator, so
// distinct field boundaries cannot collide (e.g. {"a","b"} vs {"ab",""}).
func (c *decisionCache) shardFor(k cacheKey) *cacheShard {
	h := fnv.New32a()
	_, _ = h.Write(k.tokenDigest[:])
	_, _ = h.Write([]byte("\x00" + k.sub + "\x00" + k.resource + "\x00" + k.action + "\x00" + k.product + "\x00" + k.clientIP))

	return c.shards[h.Sum32()%decisionCacheShards]
}

// get returns the cached decision for k and whether a FRESH entry exists. An
// expired entry is treated as absent (and evicted); callers therefore never see a
// stale decision — critical for the breaker-open path, which must not serve
// expired grants.
func (c *decisionCache) get(k cacheKey) (authorized, ok bool) {
	shard := c.shardFor(k)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, found := shard.entries[k]
	if !found {
		return false, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(shard.entries, k)

		return false, false
	}

	return entry.authorized, true
}

// set stores a decision for k with the cache TTL. When the shard is at its soft
// cap it first sweeps expired entries and, if still full, evicts a single entry so
// the cache stays bounded.
func (c *decisionCache) set(k cacheKey, authorized bool) {
	shard := c.shardFor(k)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if len(shard.entries) >= decisionCacheMaxPerShard {
		evictShard(shard)
	}

	shard.entries[k] = cacheEntry{authorized: authorized, expiresAt: time.Now().Add(c.ttl)}
}

// evictShard drops expired entries; if none were expired it removes one arbitrary
// entry so an insert can proceed without unbounded growth. Caller holds shard.mu.
func evictShard(shard *cacheShard) {
	now := time.Now()
	evicted := false

	for key, entry := range shard.entries {
		if now.After(entry.expiresAt) {
			delete(shard.entries, key)

			evicted = true
		}
	}

	if evicted {
		return
	}

	for key := range shard.entries {
		delete(shard.entries, key)

		return
	}
}
