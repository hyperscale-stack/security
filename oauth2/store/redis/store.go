// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/redis/go-redis/v9"
)

// Store is a Redis-backed [oauth2.Storage]. Single-use atomicity
// (ConsumeAuthorizationCode, RotateRefreshToken) is provided by Lua
// scripts: a Redis Lua script runs to completion without interleaving
// other commands, so the read-modify-write sequence is indivisible.
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
// the client's lifecycle.
func New(rdb redis.UniversalClient, opts ...Option) (*Store, error) {
	if rdb == nil {
		return nil, errors.New("redisstore: New: nil redis client")
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
func (s *Store) famRTKey(fam string) string { return s.prefix + "famrt:" + fam }
func (s *Store) famATKey(fam string) string { return s.prefix + "famat:" + fam }

// --- Lua scripts ---------------------------------------------------------

// consumeCodeScript atomically reads-and-deletes an authorization code.
// Returns the JSON value, or false when the key is absent.
var consumeCodeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
redis.call('DEL', KEYS[1])
return v
`)

// rotateRefreshScript atomically rotates a refresh token.
//
//	KEYS[1] old refresh-token key
//	KEYS[2] new refresh-token key
//	KEYS[3] family set of refresh-token hashes
//	ARGV[1] new refresh-token JSON
//	ARGV[2] new refresh-token TTL (seconds)
//	ARGV[3] new refresh-token hash
//
// Returns: 'ok' on success, 'notfound' when the old key is absent,
// 'reused' when the old token was already consumed.
var rotateRefreshScript = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
if not old then return 'notfound' end
local decoded = cjson.decode(old)
if decoded.consumed then return 'reused' end
decoded.consumed = true
local ttl = redis.call('PTTL', KEYS[1])
if ttl and ttl > 0 then
  redis.call('SET', KEYS[1], cjson.encode(decoded), 'PX', ttl)
else
  redis.call('SET', KEYS[1], cjson.encode(decoded))
end
redis.call('SET', KEYS[2], ARGV[1], 'EX', tonumber(ARGV[2]))
redis.call('SADD', KEYS[3], ARGV[3])
return 'ok'
`)

// --- authorization codes -------------------------------------------------

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore].
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
// the consumeCode Lua script — atomic read+delete.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	res, err := consumeCodeScript.Run(ctx, s.rdb, []string{s.codeKey(codeHash)}).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, oauth2.ErrCodeAlreadyUsed
		}

		return nil, fmt.Errorf("redisstore: consume authorization code: %w", err)
	}

	str, ok := res.(string)
	if !ok {
		// The script returned false: key absent / already consumed.
		return nil, oauth2.ErrCodeAlreadyUsed
	}

	code, err := decodeCode(codeHash, []byte(str))
	if err != nil {
		return nil, fmt.Errorf("redisstore: decode code: %w", err)
	}

	return code, nil
}

// --- access tokens -------------------------------------------------------

// SaveAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) SaveAccessToken(ctx context.Context, t *oauth2.AccessToken) error {
	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: empty access token hash")
	}

	payload, err := encodeAccess(t)
	if err != nil {
		return fmt.Errorf("redisstore: encode access token: %w", err)
	}

	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, s.atKey(t.TokenHash), payload, ttlUntil(t.ExpiresAt))

	if t.FamilyID != "" {
		pipe.SAdd(ctx, s.famATKey(t.FamilyID), t.TokenHash)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisstore: save access token: %w", err)
	}

	return nil
}

// LookupAccessToken implements [oauth2.AccessTokenStore].
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

	return t, nil
}

// RevokeAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	if err := s.rdb.Del(ctx, s.atKey(tokenHash)).Err(); err != nil {
		return fmt.Errorf("redisstore: revoke access token: %w", err)
	}

	return nil
}

// --- refresh tokens ------------------------------------------------------

// SaveRefreshToken implements [oauth2.RefreshTokenStore].
func (s *Store) SaveRefreshToken(ctx context.Context, t *oauth2.RefreshToken) error {
	if t.TokenHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("redisstore: empty refresh token hash")
	}

	payload, err := encodeRefresh(t)
	if err != nil {
		return fmt.Errorf("redisstore: encode refresh token: %w", err)
	}

	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, s.rtKey(t.TokenHash), payload, ttlUntil(t.ExpiresAt))

	if t.FamilyID != "" {
		pipe.SAdd(ctx, s.famRTKey(t.FamilyID), t.TokenHash)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redisstore: save refresh token: %w", err)
	}

	return nil
}

// LookupRefreshToken implements [oauth2.RefreshTokenStore].
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

	return t, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore] via the
// rotateRefresh Lua script — the consumed-flag check and the new-token
// insert happen atomically. Reuse of a consumed token returns
// [oauth2.ErrRefreshTokenReused] and revokes the whole family.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.RefreshToken) error {
	payload, err := encodeRefresh(next)
	if err != nil {
		return fmt.Errorf("redisstore: encode rotated refresh token: %w", err)
	}

	keys := []string{
		s.rtKey(oldHash),
		s.rtKey(next.TokenHash),
		s.famRTKey(next.FamilyID),
	}
	args := []any{payload, int64(ttlUntil(next.ExpiresAt).Seconds()), next.TokenHash}

	res, err := rotateRefreshScript.Run(ctx, s.rdb, keys, args...).Result()
	if err != nil {
		return fmt.Errorf("redisstore: rotate refresh token: %w", err)
	}

	switch res {
	case "ok":
		return nil
	case "notfound":
		return oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	case "reused":
		// Reuse detected — revoke the whole family per BCP §8.10.3.
		_ = s.RevokeRefreshFamily(ctx, next.FamilyID)

		return oauth2.ErrRefreshTokenReused
	default:
		return fmt.Errorf("redisstore: rotate: unexpected script result %v", res)
	}
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore]: every refresh
// token of the family is marked consumed, every access token of the
// family is deleted.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	rtHashes, err := s.rdb.SMembers(ctx, s.famRTKey(familyID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redisstore: list family refresh tokens: %w", err)
	}

	for _, h := range rtHashes {
		if err := s.markConsumed(ctx, h); err != nil {
			return err
		}
	}

	atHashes, err := s.rdb.SMembers(ctx, s.famATKey(familyID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redisstore: list family access tokens: %w", err)
	}

	for _, h := range atHashes {
		if err := s.rdb.Del(ctx, s.atKey(h)).Err(); err != nil {
			return fmt.Errorf("redisstore: purge family access token: %w", err)
		}
	}

	return nil
}

// markConsumed flips the consumed flag of a single refresh token,
// preserving its TTL.
func (s *Store) markConsumed(ctx context.Context, hash string) error {
	raw, err := s.rdb.Get(ctx, s.rtKey(hash)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil // already gone — nothing to revoke
		}

		return fmt.Errorf("redisstore: get refresh token: %w", err)
	}

	rt, err := decodeRefresh(hash, raw)
	if err != nil {
		return fmt.Errorf("redisstore: decode refresh token: %w", err)
	}

	if rt.Consumed {
		return nil
	}

	rt.Consumed = true

	payload, err := encodeRefresh(rt)
	if err != nil {
		return fmt.Errorf("redisstore: encode refresh token: %w", err)
	}

	if err := s.rdb.Set(ctx, s.rtKey(hash), payload, redis.KeepTTL).Err(); err != nil {
		return fmt.Errorf("redisstore: mark refresh token consumed: %w", err)
	}

	return nil
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
