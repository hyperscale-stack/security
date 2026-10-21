// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/redis/go-redis/v9"
)

// Store is a Redis-backed [oauth2.Storage]. Single-use atomicity
// (ConsumeAuthorizationCode) and the token-family contract of
// [oauth2.Storage] rest on Lua scripts: a Redis script runs to completion
// without interleaving other commands, so each read-modify-write sequence
// is indivisible.
//
// ConsumeAuthorizationCode runs one script that flags the code consumed in
// its key, which keeps its TTL: a replay is recognized until the code
// expires, and the key expires with it.
//
// Each token family has one key, {prefix}fam:{id}, holding "active" or
// "revoked": the point every write into the family serializes on.
//
//   - SaveTokenPair runs one script that refuses a family in any state but
//     unknown or "active", records it active and writes both tokens.
//   - RotateRefreshToken runs one script that checks the old token and the
//     family — any state but "active" refuses the rotation — then consumes
//     the old token and writes the new pair. On reuse the script writes
//     nothing and the store runs the revocation script next: whatever
//     commits in between is ordered before the revocation, which covers it.
//   - RevokeRefreshFamily runs one script that writes that single key,
//     whether or not any token of the family exists.
//   - Lookups read the token, then its family key: unless that key holds
//     exactly "active", the token is reported revoked.
//
// The family key lives at least as long as every token of the family, and
// for [oauth2.FamilyRevocationRetention] after a revocation.
type Store struct {
	rdb    redis.UniversalClient
	prefix string
}

// Option configures the Store.
type Option func(*Store)

// WithKeyPrefix overrides the key namespace. Default: "oauth2:".
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// New returns a [Store] bound to the given Redis client. The caller owns
// the client's lifecycle. It refuses, with an error matching
// [ErrDeploymentRequirement], a *redis.ClusterClient or a *redis.Ring: the
// scripts touch keys those clients would spread over several hash slots or
// shards. A standalone server, or the primary of a Sentinel deployment
// (redis.NewFailoverClient), is served by a *redis.Client.
func New(rdb redis.UniversalClient, opts ...Option) (*Store, error) {
	if rdb == nil {
		return nil, errors.New("redisstore: New: nil redis client")
	}

	if err := shardedClient(rdb); err != nil {
		return nil, fmt.Errorf("redisstore: New: %w", err)
	}

	s := &Store{rdb: rdb, prefix: "oauth2:"}
	for _, o := range opts {
		o(s)
	}

	return s, nil
}

func (s *Store) codeKey(hash string) string { return s.prefix + "code:" + hash }
func (s *Store) atKey(hash string) string   { return s.prefix + "at:" + hash }
func (s *Store) rtKey(hash string) string   { return s.prefix + "rt:" + hash }
func (s *Store) famKey(id string) string    { return s.prefix + "fam:" + id }

// familyActive is the state of a family key that lets its tokens be used;
// the scripts write it, and "revoked", as Lua literals.
const familyActive = "active"

// The replies of the token scripts.
const (
	resultOK       = "ok"
	resultNotFound = "notfound"
	resultMismatch = "mismatch"
	resultContext  = "context"
	resultRevoked  = "revoked"
	resultReused   = "reused"
)

// --- Lua scripts ---------------------------------------------------------

// consumeCodeScript atomically flags an authorization code consumed,
// keeping the key's TTL, and returns the payload as it found it — false
// when the key is absent. A payload already flagged is returned unchanged:
// it is a replay, unless this very call flagged it, which the caller
// tells from the consumed_by nonce the script records. cjson decodes a
// JSON null as a truthy value, hence the explicit comparison.
//
//	KEYS[1] code; ARGV[1] the nonce of the call
var consumeCodeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
local c = cjson.decode(v)
if c.consumed == true then return v end
c.consumed = true
c.consumed_by = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(c), 'KEEPTTL')
return v
`)

// issuePairScript persists a newly issued pair into a family. It refuses a
// family whose key holds anything but "active" — a missing key is a new
// family — records the family active for at least the pair's lifetime,
// then writes the tokens.
//
//	KEYS[1] family; KEYS[2] access token; KEYS[3] refresh token (optional)
//	ARGV[1] family TTL (ms); ARGV[2] access JSON; ARGV[3] access TTL (ms);
//	ARGV[4] refresh JSON; ARGV[5] refresh TTL (ms) — with KEYS[3] only
//
// Returns 'ok', or 'revoked' without writing anything.
var issuePairScript = redis.NewScript(`
local state = redis.call('GET', KEYS[1])
if state and state ~= 'active' then return 'revoked' end
if redis.call('PTTL', KEYS[1]) < tonumber(ARGV[1]) then
  redis.call('SET', KEYS[1], 'active', 'PX', ARGV[1])
end
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3])
if KEYS[3] then redis.call('SET', KEYS[3], ARGV[4], 'PX', ARGV[5]) end
return 'ok'
`)

// rotatePairScript atomically consumes a refresh token and persists the
// pair replacing it. Every check runs before the first write, so a refusal
// — or a corrupt old token, which aborts the script — writes nothing.
//
//	KEYS[1] old refresh token; KEYS[2] family;
//	KEYS[3] new refresh token; KEYS[4] new access token
//	ARGV[1] family ID; ARGV[2] refresh JSON; ARGV[3] refresh TTL (ms);
//	ARGV[4] access JSON; ARGV[5] access TTL (ms); ARGV[6] family TTL (ms);
//	ARGV[7] issuer; ARGV[8] extension data — of the replacement
//
// Returns 'ok', 'notfound', 'mismatch' (the old token is in another
// family), 'context' (the replacement carries another issuer or other
// extension data than the old token; a field absent from the old payload,
// or null, reads as the empty string), 'revoked' (the family key is not
// 'active': rotations never create a family) or 'reused'. A consumed old
// token whose replacement already exists is a resend of this very rotation
// — the new refresh key comes from 256 random bits, only an earlier run of
// the same call can have written it — so it answers 'ok' rather than
// 'reused': go-redis resends a command whose reply was lost, which must not
// revoke the family the rotation just extended.
var rotatePairScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return 'notfound' end
local old = cjson.decode(raw)
if old.family_id ~= ARGV[1] then return 'mismatch' end
local issuer, data = old.issuer, old.extension_data
if type(issuer) ~= 'string' then issuer = '' end
if type(data) ~= 'string' then data = '' end
if issuer ~= ARGV[7] or data ~= ARGV[8] then return 'context' end
if redis.call('GET', KEYS[2]) ~= 'active' then return 'revoked' end
if old.consumed then
  if redis.call('EXISTS', KEYS[3]) == 1 then return 'ok' end
  return 'reused'
end
old.consumed = true
redis.call('SET', KEYS[1], cjson.encode(old), 'KEEPTTL')
redis.call('SET', KEYS[3], ARGV[2], 'PX', ARGV[3])
redis.call('SET', KEYS[4], ARGV[4], 'PX', ARGV[5])
if redis.call('PTTL', KEYS[2]) < tonumber(ARGV[6]) then
  redis.call('SET', KEYS[2], 'active', 'PX', ARGV[6])
end
return 'ok'
`)

// revokeFamilyScript records a family revoked: its only write sets the
// family key, keeping the longer of its current TTL and the retention.
//
//	KEYS[1] family; ARGV[1] minimum retention (ms)
var revokeFamilyScript = redis.NewScript(`
local ttl = tonumber(ARGV[1])
local current = redis.call('PTTL', KEYS[1])
if current > ttl then ttl = current end
redis.call('SET', KEYS[1], 'revoked', 'PX', ttl)
return 'ok'
`)

// --- authorization codes -------------------------------------------------

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore] with a
// plain SET, which overwrites any record under the same hash: a consumed
// code saved again becomes redeemable again, so callers MUST save a given
// CodeHash at most once.
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	if code.CodeHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: empty code hash")
	}

	payload, err := encodeCode(code)
	if err != nil {
		return fmt.Errorf("redisstore: encode code: %w", err)
	}

	if err := s.rdb.Set(ctx, s.codeKey(code.CodeHash), payload, ttlUntil(code.ExpiresAt)).Err(); err != nil {
		return fmt.Errorf("redisstore: save authorization code: %w", err)
	}

	return nil
}

// ConsumeAuthorizationCode implements [oauth2.AuthorizationCodeStore] via
// consumeCodeScript: one atomic step flags the code consumed, and a replay
// gets an [*oauth2.CodeReplayError] carrying the record until the key
// expires with the code.
//
// Each call sends the script a fresh nonce, which the script records when
// it flags the code: go-redis resends a script whose reply was lost, and
// the resend — finding the code flagged under its own nonce — must not
// read as a replay of the exchange it is part of.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	nonce := rand.Text()

	res, err := consumeCodeScript.Run(ctx, s.rdb, []string{s.codeKey(codeHash)}, nonce).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, oauth2.ErrCodeAlreadyUsed
		}

		return nil, fmt.Errorf("redisstore: consume authorization code: %w", err)
	}

	str, ok := res.(string)
	if !ok {
		// Any other reply type: treat as an unknown code (a Lua false
		// arrives as redis.Nil, handled above).
		return nil, oauth2.ErrCodeAlreadyUsed
	}

	code, consumed, consumedBy, err := decodeCode(codeHash, []byte(str))
	if err != nil {
		return nil, fmt.Errorf("redisstore: decode code: %w", err)
	}

	// The payload is the one the script found: unconsumed when this call
	// consumed the code, or flagged by this very call when it was resent.
	if won := !consumed || (nonce != "" && consumedBy == nonce); !won {
		return nil, &oauth2.CodeReplayError{Record: code}
	}

	return code, nil
}

// --- access and refresh tokens -------------------------------------------

// SaveTokenPair implements [oauth2.Storage]. A pair of a family goes
// through issuePairScript; a pair outside any family is one SET.
func (s *Store) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	if err := pair.Validate(); err != nil {
		return fmt.Errorf("redisstore: save token pair: %w", err)
	}

	access, err := encodeAccess(&pair.Access)
	if err != nil {
		return fmt.Errorf("redisstore: encode access token: %w", err)
	}

	if pair.Access.FamilyID == "" {
		if err := s.rdb.Set(ctx, s.atKey(pair.Access.TokenHash), access, ttlUntil(pair.Access.ExpiresAt)).Err(); err != nil {
			return fmt.Errorf("redisstore: save access token: %w", err)
		}

		return nil
	}

	keys := []string{s.famKey(pair.Access.FamilyID), s.atKey(pair.Access.TokenHash)}
	args := []any{familyTTL(pair), access, ttlMillis(pair.Access.ExpiresAt)}

	if pair.Refresh != nil {
		refresh, err := encodeRefresh(pair.Refresh)
		if err != nil {
			return fmt.Errorf("redisstore: encode refresh token: %w", err)
		}

		keys = append(keys, s.rtKey(pair.Refresh.TokenHash))
		args = append(args, refresh, ttlMillis(pair.Refresh.ExpiresAt))
	}

	res, err := issuePairScript.Run(ctx, s.rdb, keys, args...).Text()
	if err != nil {
		return fmt.Errorf("redisstore: save token pair: %w", err)
	}

	switch res {
	case resultOK:
		return nil
	case resultRevoked:
		return oauth2.ErrTokenFamilyRevoked
	default:
		return fmt.Errorf("redisstore: save token pair: unexpected script result %q", res)
	}
}

// LookupAccessToken implements [oauth2.AccessTokenStore]. A token whose
// family key is not "active" is reported as [oauth2.ErrTokenFamilyRevoked].
func (s *Store) LookupAccessToken(ctx context.Context, tokenHash string) (*oauth2.AccessToken, error) {
	raw, err := s.rdb.Get(ctx, s.atKey(tokenHash)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("access token not found")
		}

		return nil, fmt.Errorf("redisstore: lookup access token: %w", err)
	}

	t, err := decodeAccess(tokenHash, raw)
	if err != nil {
		return nil, fmt.Errorf("redisstore: decode access token: %w", err)
	}

	active, err := s.familyActive(ctx, t.FamilyID)
	if err != nil {
		return nil, err
	}

	if !active {
		return nil, oauth2.ErrTokenFamilyRevoked
	}

	return t, nil
}

// RevokeAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	if err := s.rdb.Del(ctx, s.atKey(tokenHash)).Err(); err != nil {
		return fmt.Errorf("redisstore: revoke access token: %w", err)
	}

	return nil
}

// LookupRefreshToken implements [oauth2.RefreshTokenStore]. A token whose
// family key is not "active" comes back consumed — and so does a token
// stored without a family, which no valid pair carries.
func (s *Store) LookupRefreshToken(ctx context.Context, tokenHash string) (*oauth2.RefreshToken, error) {
	raw, err := s.rdb.Get(ctx, s.rtKey(tokenHash)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
		}

		return nil, fmt.Errorf("redisstore: lookup refresh token: %w", err)
	}

	t, err := decodeRefresh(tokenHash, raw)
	if err != nil {
		return nil, fmt.Errorf("redisstore: decode refresh token: %w", err)
	}

	active, err := s.familyActive(ctx, t.FamilyID)
	if err != nil {
		return nil, err
	}

	t.Consumed = t.Consumed || t.FamilyID == "" || !active

	return t, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore] via
// rotatePairScript. On reuse the script writes nothing and the store then
// revokes the family; a failure of that revocation is reported as
// [oauth2.ErrRefreshTokenReused] joined with
// [oauth2.ErrTokenFamilyRevocationFailed] and its cause.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	if err := validateRotation(next); err != nil {
		return err
	}

	refresh, err := encodeRefresh(next.Refresh)
	if err != nil {
		return fmt.Errorf("redisstore: encode refresh token: %w", err)
	}

	access, err := encodeAccess(&next.Access)
	if err != nil {
		return fmt.Errorf("redisstore: encode access token: %w", err)
	}

	familyID := next.Access.FamilyID
	keys := []string{
		s.rtKey(oldHash), s.famKey(familyID),
		s.rtKey(next.Refresh.TokenHash), s.atKey(next.Access.TokenHash),
	}
	args := []any{
		familyID,
		refresh, ttlMillis(next.Refresh.ExpiresAt),
		access, ttlMillis(next.Access.ExpiresAt),
		familyTTL(next),
		next.Access.Issuer, next.Access.ExtensionData,
	}

	res, err := rotatePairScript.Run(ctx, s.rdb, keys, args...).Text()
	if err != nil {
		return fmt.Errorf("redisstore: rotate refresh token: %w", err)
	}

	switch res {
	case resultOK:
		return nil
	case resultNotFound:
		return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	case resultMismatch:
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: rotation into another token family")
	case resultContext:
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: rotation into another grant context")
	case resultRevoked:
		return oauth2.ErrTokenFamilyRevoked
	case resultReused:
		return s.revokeReused(ctx, familyID)
	default:
		return fmt.Errorf("redisstore: rotate refresh token: unexpected script result %q", res)
	}
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore] via
// revokeFamilyScript: one write, recorded whether or not any token of the
// family exists. A failure wraps [oauth2.ErrTokenFamilyRevocationFailed].
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if err := checkFamilyID(familyID); err != nil {
		return err
	}

	return s.revokeFamily(ctx, familyID)
}

// revokeReused answers the reuse rotatePairScript detected by revoking the
// family, then reports the reuse.
func (s *Store) revokeReused(ctx context.Context, familyID string) error {
	if err := s.revokeFamily(ctx, familyID); err != nil {
		return fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused, err)
	}

	return oauth2.ErrRefreshTokenReused
}

// revokeFamily runs revokeFamilyScript.
func (s *Store) revokeFamily(ctx context.Context, familyID string) error {
	err := revokeFamilyScript.Run(ctx, s.rdb, []string{s.famKey(familyID)},
		oauth2.FamilyRevocationRetention.Milliseconds()).Err()
	if err != nil {
		return fmt.Errorf("redisstore: revoke family %q: %w: %w", familyID, oauth2.ErrTokenFamilyRevocationFailed, err)
	}

	return nil
}

// familyActive reports whether a token of familyID may be used: it is
// outside any family, or its family key holds exactly "active". A missing
// key — expired, evicted — or any other value reads as revoked; a key the
// store cannot read is an error, never an answer.
func (s *Store) familyActive(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return true, nil
	}

	state, err := s.rdb.Get(ctx, s.famKey(familyID)).Result()

	switch {
	case errors.Is(err, redis.Nil):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("redisstore: lookup token family: %w", err)
	default:
		return state == familyActive, nil
	}
}

// validateRotation refuses a malformed rotation target before any command
// runs: nil, failing [oauth2.TokenPair.Validate], or without the refresh
// token a rotation issues.
func validateRotation(next *oauth2.TokenPair) error {
	if err := next.Validate(); err != nil {
		return fmt.Errorf("redisstore: rotate refresh token: %w", err)
	}

	if next.Refresh == nil {
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: rotation without a refresh token")
	}

	return nil
}

// checkFamilyID refuses a family ID no family can have: empty, or longer
// than [oauth2.MaxFamilyIDLength].
func checkFamilyID(familyID string) error {
	switch {
	case familyID == "":
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: empty token family id")
	case len(familyID) > oauth2.MaxFamilyIDLength:
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: token family id too long")
	default:
		return nil
	}
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
