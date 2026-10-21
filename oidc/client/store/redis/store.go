// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package redisstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/redis/go-redis/v9"
)

// DefaultKeyPrefix is the key namespace of a Store without WithKeyPrefix.
const DefaultKeyPrefix = "oidcclient:"

// resultMismatch is the reply of consumeScript to a wrong binding.
const resultMismatch = "mismatch"

// consumeScript decides a consumption atomically, in the order the
// TransactionStore contract pins. It returns false for a missing key, a
// transaction consumed by another call, or an expired one — which it
// deletes, whatever the binding — 'mismatch' for a wrong binding, leaving
// the key untouched, and otherwise flags the transaction consumed by this
// call's nonce, keeping the key's TTL, and returns the payload as it
// found it. A transaction already flagged with this call's nonce is a
// resend of this very call — go-redis resends a command whose reply was
// lost — and returns the payload again, as the first run did.
//
//	KEYS[1] transaction; ARGV[1] binding hash; ARGV[2] now (Unix seconds);
//	ARGV[3] the nonce of the call
var consumeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
local tx = cjson.decode(v)
if type(tx.consumed_by) == 'string' then
  if tx.consumed_by == ARGV[3] then return v end
  return false
end
if tonumber(tx.expires_at) <= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return false
end
if tx.binding_hash ~= ARGV[1] then return 'mismatch' end
tx.consumed_by = ARGV[3]
redis.call('SET', KEYS[1], cjson.encode(tx), 'KEEPTTL')
return v
`)

// Store is a Redis [oidcclient.TransactionStore]: one key per
// transaction, {prefix}tx:{state hash}, holding a JSON payload and
// expiring with the transaction.
//
// Save is one SET … NX PX: it never overwrites, and the key lives as long
// as the transaction. Consume is one Lua script, which Redis runs without
// interleaving any other command: it reads the key, decides, and flags
// the transaction consumed. A consumed transaction stays, flagged, until
// its key expires, so that a consumption resent by go-redis after a lost
// reply still returns it — each call carries a fresh nonce the script
// records — while any other call finds nothing.
//
// A Save resent after a lost reply finds its own key and reports
// [oidcclient.ErrTransactionExists]: that login fails to start, closed.
type Store struct {
	rdb    redis.UniversalClient
	prefix string
}

// Option configures the Store.
type Option func(*Store)

// WithKeyPrefix overrides the key namespace. Default: [DefaultKeyPrefix].
func WithKeyPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// New returns a [Store] over rdb. The caller owns the client's lifecycle.
func New(rdb redis.UniversalClient, opts ...Option) (*Store, error) {
	if rdb == nil {
		return nil, errors.New("redisstore: New: nil redis client")
	}

	s := &Store{rdb: rdb, prefix: DefaultKeyPrefix}
	for _, o := range opts {
		o(s)
	}

	return s, nil
}

func (s *Store) key(stateHash string) string { return s.prefix + "tx:" + stateHash }

// Save implements [oidcclient.TransactionStore].
func (s *Store) Save(ctx context.Context, tx *oidcclient.Transaction) error {
	if err := tx.Validate(); err != nil {
		return fmt.Errorf("redisstore: %w", err)
	}

	set, err := s.rdb.SetNX(ctx, s.key(tx.StateHash), encodeTransaction(tx), tx.ExpiresAt.Sub(tx.CreatedAt)).Result()
	if err != nil {
		return fmt.Errorf("redisstore: save transaction: %w", err)
	}

	if !set {
		return oidcclient.ErrTransactionExists
	}

	return nil
}

// Consume implements [oidcclient.TransactionStore] with one script run
// (see [Store]), after refusing, before any I/O, keys
// [oidcclient.ValidateStoreKey] refuses.
func (s *Store) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	if err := oidcclient.ValidateStoreKey(stateHash); err != nil {
		return nil, fmt.Errorf("redisstore: consume transaction: state hash: %w", err)
	}

	if err := oidcclient.ValidateStoreKey(bindingHash); err != nil {
		return nil, fmt.Errorf("redisstore: consume transaction: binding hash: %w", err)
	}

	res, err := consumeScript.Run(ctx, s.rdb, []string{s.key(stateHash)}, bindingHash, now.Unix(), rand.Text()).Text()

	switch {
	case errors.Is(err, redis.Nil):
		return nil, oidcclient.ErrTransactionNotFound
	case err != nil:
		return nil, fmt.Errorf("redisstore: consume transaction: %w", err)
	case res == resultMismatch:
		return nil, oidcclient.ErrBindingMismatch
	}

	return decodeTransaction(stateHash, []byte(res))
}
