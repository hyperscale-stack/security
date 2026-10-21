// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/oidc/client/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forgingStore stores transactions in memory and, as an attacker with
// write access to a shared store could, relaxes the transaction it returns
// and recomputes its integrity MAC with forge — the attacker knows the
// algorithm and the binding secret of the login it runs itself.
type forgingStore struct {
	inner   oidcclient.TransactionStore
	relax   func(*oidcclient.Transaction)
	forge   func(binding string, tx *oidcclient.Transaction) string
	binding string // the attacker's own login, known once Begin returned
}

func (s *forgingStore) Save(ctx context.Context, tx *oidcclient.Transaction) error {
	return s.inner.Save(ctx, tx)
}

func (s *forgingStore) Consume(ctx context.Context, stateHash, bindingHash string, now time.Time) (*oidcclient.Transaction, error) {
	tx, err := s.inner.Consume(ctx, stateHash, bindingHash, now)
	if err == nil {
		s.relax(tx)
		tx.Integrity = s.forge(s.binding, tx)
	}

	return tx, err
}

// forgeWithKey recomputes the MAC the way the package does, under key.
func forgeWithKey(key []byte) func(string, *oidcclient.Transaction) string {
	return func(binding string, tx *oidcclient.Transaction) string {
		return oidcclient.ForgeIntegrity(key, binding, tx)
	}
}

// forgeV1 recomputes the MAC with the first published construction, keyed
// by the binding secret alone: HMAC-SHA256(HMAC-SHA256(binding secret,
// "oidcclient/integrity/v1"), netstrings of the fields).
func forgeV1(binding string, tx *oidcclient.Transaction) string {
	secret, err := base64.RawURLEncoding.DecodeString(binding)
	if err != nil {
		panic(err)
	}

	derived := hmac.New(sha256.New, secret)
	derived.Write([]byte("oidcclient/integrity/v1"))

	mac := hmac.New(sha256.New, derived.Sum(nil))

	for _, field := range []string{
		tx.StateHash, tx.BindingHash, tx.ConnectionID, tx.Issuer, tx.ClientID, tx.RedirectURI,
		string(tx.ResponseMode), strconv.FormatInt(tx.MaxAge, 10), tx.ACRValues, tx.AppState,
		strconv.FormatInt(tx.CreatedAt.Unix(), 10), strconv.FormatInt(tx.ExpiresAt.Unix(), 10),
	} {
		mac.Write([]byte(strconv.Itoa(len(field)) + ":" + field + ","))
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// TestStoreWriterCannotForgeIntegrity replays the store-write step-up
// bypass: an attacker who can write to the shared store runs a login in
// its own browser — so it holds the binding secret — strips the login's
// step-up requirements from the stored transaction and recomputes the
// integrity MAC. Without the server-held transaction key it cannot: the
// login fails before the code is redeemed. The control recomputes the MAC
// with the real key and is accepted, proving that the forgeries fail for
// the key alone, not for an algorithm the test got wrong.
func TestStoreWriterCannotForgeIntegrity(t *testing.T) {
	t.Parallel()

	maxAge := 5 * time.Minute
	attackerKey := bytes.Repeat([]byte{0xa7}, oidcclient.MinTransactionKeySize)

	steps := map[string]struct {
		opts   oidcclient.AuthOptions
		claims func(map[string]any)
		relax  func(*oidcclient.Transaction)
		check  func(*testing.T, *oidcclient.Identity)
	}{
		"acr_values stripped": {
			opts:   oidcclient.AuthOptions{ACRValues: []string{"urn:acr:gold"}},
			claims: func(c map[string]any) { c["acr"] = "urn:acr:bronze" },
			relax:  func(tx *oidcclient.Transaction) { tx.ACRValues = "" },
			check:  func(t *testing.T, id *oidcclient.Identity) { assert.Equal(t, "urn:acr:bronze", id.ACR) },
		},
		"max_age stripped": {
			opts:   oidcclient.AuthOptions{MaxAge: &maxAge},
			claims: func(c map[string]any) { c["auth_time"] = testNow.Add(-24 * time.Hour).Unix() },
			relax:  func(tx *oidcclient.Transaction) { tx.MaxAge = oidcclient.NoMaxAge },
			check:  func(t *testing.T, id *oidcclient.Identity) { assert.Equal(t, testNow.Add(-24*time.Hour), id.AuthTime) },
		},
	}

	forgeries := map[string]func(string, *oidcclient.Transaction) string{
		"attacker-chosen key":       forgeWithKey(attackerKey),
		"first construction (v1)":   forgeV1,
		"empty key":                 forgeWithKey(nil),
		"real key prefix truncated": forgeWithKey(testTransactionKey[:oidcclient.MinTransactionKeySize-1]),
	}

	for stepName, step := range steps {
		for forgeryName, forge := range forgeries {
			t.Run(stepName+"/"+forgeryName, func(t *testing.T) {
				t.Parallel()

				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.claimsHook = func(_ *grant, c map[string]any) { step.claims(c) } })

				store := &forgingStore{inner: memory.New(), relax: step.relax, forge: forge}
				c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

				ar, code := op.begin(t, c, step.opts)
				store.binding = ar.Binding.Reveal()

				id, err := c.Complete(context.Background(), callbackFor(ar, code))
				require.ErrorIs(t, err, oidcclient.ErrTransactionIntegrity)
				assert.Nil(t, id)
				assert.Zero(t, op.hitCount("/token"), "the code is never redeemed")
			})
		}

		t.Run(stepName+"/control: the real key", func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			op.set(func(op *fakeOP) { op.claimsHook = func(_ *grant, c map[string]any) { step.claims(c) } })

			store := &forgingStore{inner: memory.New(), relax: step.relax, forge: forgeWithKey(testTransactionKey)}
			c := op.client(t, func(cfg *oidcclient.Config) { cfg.Store = store })

			ar, code := op.begin(t, c, step.opts)
			store.binding = ar.Binding.Reveal()

			id, err := c.Complete(context.Background(), callbackFor(ar, code))
			require.NoError(t, err, "the forgery with the real key is the package's own MAC")
			step.check(t, id)
		})
	}
}

// TestTransactionKeyRotation checks the documented rotation — add the new
// key last, move it first, remove the old one once TransactionTTL has
// elapsed — against logins begun on one replica and completed on another,
// and that replicas configured with unrelated keys fail every login
// instead of accepting it.
func TestTransactionKeyRotation(t *testing.T) {
	t.Parallel()

	k1 := bytes.Repeat([]byte{0x11}, oidcclient.MinTransactionKeySize)
	k2 := bytes.Repeat([]byte{0x22}, oidcclient.MinTransactionKeySize)

	cases := []struct {
		name            string
		begin, complete [][]byte
		want            error
	}{
		{"one key", [][]byte{k1}, [][]byte{k1}, nil},
		{"new key added last", [][]byte{k1}, [][]byte{k1, k2}, nil},
		{"new key moved first", [][]byte{k1}, [][]byte{k2, k1}, nil},
		{"begun under the new key, old key removed", [][]byte{k2, k1}, [][]byte{k2}, nil},
		{"begun during the rotation, completed after", [][]byte{k1, k2}, [][]byte{k2, k1}, nil},
		{"old key removed too early", [][]byte{k1}, [][]byte{k2}, oidcclient.ErrTransactionIntegrity},
		{"replicas with unrelated keys", [][]byte{k2}, [][]byte{k1}, oidcclient.ErrTransactionIntegrity},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := newFakeOP(t)
			store := memory.New()
			starting := op.client(t, func(cfg *oidcclient.Config) { cfg.Store, cfg.TransactionKeys = store, secretKeys(tc.begin...) })
			completing := op.client(t, func(cfg *oidcclient.Config) {
				cfg.Store, cfg.TransactionKeys = store, secretKeys(tc.complete...)
			})

			ar, code := op.begin(t, starting, oidcclient.AuthOptions{})

			id, err := completing.Complete(context.Background(), callbackFor(ar, code))
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				assert.Nil(t, id)
				assert.Zero(t, op.hitCount("/token"))

				return
			}

			require.NoError(t, err)
			assert.Equal(t, testSubject, id.Subject)
		})
	}
}
