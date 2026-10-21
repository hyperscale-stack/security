// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// integrityHex is the documented TransactionRecord.Integrity of rec under
// key, computed independently of the package (Config.TransactionKeys).
func integrityHex(key []byte, rec *samlsp.TransactionRecord) string {
	kdf := hmac.New(sha256.New, key)
	_, _ = kdf.Write([]byte("samlsp/transaction-integrity/v1"))

	mac := hmac.New(sha256.New, kdf.Sum(nil))

	for _, f := range []string{rec.ID, rec.BindingHash, rec.Payload, strconv.FormatInt(rec.ExpiresAt.Unix(), 10)} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(f)) + ":" + f + ","))
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// tamper models write access to the transaction store (a database row or
// a Redis hash edited between BeginLogin and CompleteLogin): lookups
// return the stored record edited by its rewrite, while the store keeps the
// genuine one.
type tamper struct {
	mu      sync.Mutex
	rewrite func(rec *samlsp.TransactionRecord)
}

func (tp *tamper) set(f func(rec *samlsp.TransactionRecord)) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.rewrite = f
}

func (tp *tamper) get() func(rec *samlsp.TransactionRecord) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	return tp.rewrite
}

// newTamperingEnv is newEnv over the generated MockStorage delegating to a
// memory store, its lookups edited by the returned tamper.
func newTamperingEnv(t *testing.T) (*env, *tamper) {
	t.Helper()

	mem := newMemoryStore(atT0)
	tp := &tamper{}
	store := storageDouble(t, mem, func(m *samlsp.MockStorage) {
		m.EXPECT().LookupTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(ctx context.Context, id string) (*samlsp.TransactionRecord, error) {
				rec, err := mem.LookupTransaction(ctx, id)
				if f := tp.get(); err == nil && f != nil {
					f(rec)
				}

				return rec, err
			}).Maybe()
	})

	e := newEnv(t, withStorage(store))
	e.store = mem

	return e, tp
}

// TestCompleteLogin_TransactionIntegrity: a store writer can neither
// rebind a transaction to another browser or request nor relax its checks:
// the record's MAC under a server-held key (Config.TransactionKeys) covers
// every stored field and is verified before any of them is used (audit
// STORE-02; decision 11). Nothing is consumed, and the untampered login
// still completes.
func TestCompleteLogin_TransactionIntegrity(t *testing.T) {
	t.Parallel()

	const x509Class = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"

	staleAuthn := onAssertion(func(a *etree.Element) {
		child(a, "AuthnStatement").CreateAttr("AuthnInstant", ts(-time.Hour))
	})

	cases := []struct {
		name string
		opts samlsp.LoginOptions
		// tamper returns the edit of the records, given the login under
		// test (lr) and one of another browser (other); post returns the
		// request posted (default: lr's genuine response); genuine is the
		// genuine response of lr once the store is honest again.
		tamper  func(e *env, lr, other loginResult) func(rec *samlsp.TransactionRecord)
		post    func(t *testing.T, lr, other loginResult) (string, string, string)
		genuine respOpts
	}{
		{
			name: "request ID of the attacker's transaction pointed at the victim's (rebinding)",
			tamper: func(_ *env, lr, other loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) {
					if rec.ID == txKey(connID, other.relayState) {
						rec.Payload = strings.Replace(rec.Payload, other.requestID, lr.requestID, 1)
					}
				}
			},
			// The victim's response, posted by the attacker with her own
			// handle and cookie.
			post: func(t *testing.T, lr, other loginResult) (string, string, string) {
				return respond(t, lr.requestID, respOpts{}), other.relayState, other.cookie.Value
			},
		},
		{
			name: "binding rebound to the attacker's browser",
			tamper: func(_ *env, _, other loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.BindingHash = bindingKey(other.cookie.Value) }
			},
			post: func(t *testing.T, lr, other loginResult) (string, string, string) {
				return respond(t, lr.requestID, respOpts{}), lr.relayState, other.cookie.Value
			},
		},
		{
			name: "binding rewritten, posted with the owner's cookie (integrity before binding)",
			tamper: func(_ *env, _, other loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.BindingHash = bindingKey(other.cookie.Value) }
			},
		},
		{
			name: "ForceAuthn dropped", opts: samlsp.LoginOptions{ForceAuthn: true},
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.Payload = strings.Replace(rec.Payload, `,"fa":true`, "", 1) }
			},
			post: func(t *testing.T, lr, _ loginResult) (string, string, string) {
				return respond(t, lr.requestID, staleAuthn), lr.relayState, lr.cookie.Value
			},
		},
		{
			name: "requested context dropped", opts: samlsp.LoginOptions{RequestedAuthnContext: []string{x509Class}},
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) {
					rec.Payload = regexp.MustCompile(`,"ac":\[[^\]]*\]`).ReplaceAllString(rec.Payload, "")
				}
			},
			genuine: onAssertion(func(a *etree.Element) {
				path(a, "AuthnStatement", "AuthnContext", "AuthnContextClassRef").SetText(x509Class)
			}),
		},
		{
			name: "AppState rewritten", opts: samlsp.LoginOptions{AppState: "/projects/42"},
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) {
					rec.Payload = strings.Replace(rec.Payload, "/projects/42", "/admin", 1)
				}
			},
		},
		{
			name: "expiry moved to the past (integrity before expiry)",
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.ExpiresAt = t0.Add(-time.Hour) }
			},
		},
		{
			name: "expiry extended",
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.ExpiresAt = rec.ExpiresAt.Add(time.Hour) }
			},
		},
		{
			name: "payload undecodable (integrity before decoding)",
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.Payload = "{" }
			},
		},
		{
			name: "integrity removed",
			tamper: func(*env, loginResult, loginResult) func(rec *samlsp.TransactionRecord) {
				return func(rec *samlsp.TransactionRecord) { rec.Integrity = "" }
			},
		},
		{
			name: "integrity of another record",
			tamper: func(e *env, _, other loginResult) func(rec *samlsp.TransactionRecord) {
				another, err := e.store.LookupTransaction(context.Background(), txKey(connID, other.relayState))
				if err != nil {
					panic(err)
				}

				return func(rec *samlsp.TransactionRecord) { rec.Integrity = another.Integrity }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, store := newTamperingEnv(t)
			lr := begin(t, e, tc.opts)
			other := begin(t, e, samlsp.LoginOptions{})

			body, handle, cookie := respond(t, lr.requestID, tc.genuine), lr.relayState, lr.cookie.Value
			if tc.post != nil {
				body, handle, cookie = tc.post(t, lr, other)
			}

			store.set(tc.tamper(e, lr, other))

			res, err := e.sp.CompleteLogin(context.Background(), acsRequest(body, handle, cookie), connID)
			assert.Nil(t, res)
			require.ErrorIs(t, err, samlsp.ErrTransactionIntegrity)
			require.ErrorIs(t, err, samlsp.ErrRejected)

			for _, l := range []loginResult{lr, other} {
				_, lerr := e.store.LookupTransaction(context.Background(), txKey(connID, l.relayState))
				require.NoError(t, lerr, "a tampered record consumes nothing")
			}

			// The genuine record still completes its login.
			store.set(nil)

			res, err = complete(e, lr, respond(t, lr.requestID, tc.genuine))
			require.NoError(t, err)
			assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
			assert.Equal(t, tc.opts.AppState, res.AppState)
		})
	}

	t.Run("the record of another transaction served under this key", func(t *testing.T) {
		t.Parallel()

		e, store := newTamperingEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})
		other := begin(t, e, samlsp.LoginOptions{}, lr.cookie) // same browser: same binding

		genuine, err := e.store.LookupTransaction(context.Background(), txKey(connID, other.relayState))
		require.NoError(t, err)

		store.set(func(rec *samlsp.TransactionRecord) {
			if rec.ID == txKey(connID, lr.relayState) {
				*rec = *genuine // a valid record and MAC, of another ID
			}
		})

		// The response to other's request, delivered under lr's handle.
		_, err = complete(e, lr, respond(t, other.requestID, respOpts{}))
		require.ErrorIs(t, err, samlsp.ErrTransactionIntegrity)
	})
}

// TestCompleteLogin_ExpiryIsWholeSeconds: the MAC covers ExpiresAt in Unix
// seconds; a store returning a fraction more cannot extend the transaction,
// and the replay retention derived from it stays whole seconds (plan review
// F4).
func TestCompleteLogin_ExpiryIsWholeSeconds(t *testing.T) {
	t.Parallel()

	e, store := newTamperingEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	store.set(func(rec *samlsp.TransactionRecord) { rec.ExpiresAt = rec.ExpiresAt.Add(999 * time.Millisecond) })

	// A confirmation window beyond the transaction: the replay retention is
	// the transaction expiry plus the margin.
	long := onAssertion(func(a *etree.Element) {
		scd(a).CreateAttr("NotOnOrAfter", ts(30*time.Minute))
		child(a, "Conditions").CreateAttr("NotOnOrAfter", ts(30*time.Minute))
	})

	_, err := complete(e, lr, respond(t, lr.requestID, long))
	require.NoError(t, err, "the replay cache refuses a sub-second expiry: the SP must use the whole second")

	// At the expiry second, the transaction is over whatever the fraction.
	lr2 := begin(t, e, samlsp.LoginOptions{})
	e.clock.set(t0.Add(samlsp.DefaultTransactionTTL))

	_, err = complete(e, lr2, respond(t, lr2.requestID, respOpts{issued: t0.Add(samlsp.DefaultTransactionTTL - time.Minute)}))
	require.ErrorIs(t, err, samlsp.ErrTransactionExpired)
}

// TestCompleteLogin_TransactionKeyRotation: TransactionKeys[0] protects the
// new transactions, every key verifies; a transaction protected by a key no
// longer configured fails its login.
func TestCompleteLogin_TransactionKeyRotation(t *testing.T) {
	t.Parallel()

	k1 := []byte("first transaction key of 32 bytes or more")
	k2 := []byte("second transaction key of 32 bytes or more")

	store := newMemoryStore(atT0)
	withKeys := func(e *env, keys ...[]byte) *samlsp.ServiceProvider {
		sp, err := samlsp.New(samlsp.Config{
			Connections: e.resolver, Transactions: store, ReplayCache: store, Now: e.clock.Now, TransactionKeys: keys,
		})
		require.NoError(t, err)

		return sp
	}

	e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) {
		c.Transactions, c.ReplayCache, c.TransactionKeys = store, store, [][]byte{k1}
	})
	e.store = store

	// Begun under k1, completed during the rotation.
	lr := begin(t, e, samlsp.LoginOptions{})
	rotating := &env{sp: withKeys(e, k2, k1), store: store, resolver: e.resolver, clock: e.clock, conn: e.conn}

	_, err := complete(rotating, lr, respond(t, lr.requestID, respOpts{}))
	require.NoError(t, err)

	// New transactions are protected by the first key.
	lr = begin(t, rotating, samlsp.LoginOptions{})
	rec, err := store.LookupTransaction(context.Background(), txKey(connID, lr.relayState))
	require.NoError(t, err)
	assert.Equal(t, integrityHex(k2, rec), rec.Integrity)

	// Begun under k1, completed once k1 is gone.
	lr = begin(t, e, samlsp.LoginOptions{})
	rotated := &env{sp: withKeys(e, k2), store: store, resolver: e.resolver, clock: e.clock, conn: e.conn}

	_, err = complete(rotated, lr, respond(t, lr.requestID, respOpts{}))
	require.ErrorIs(t, err, samlsp.ErrTransactionIntegrity)

	// The ServiceProvider keeps its own copy of the keys (a store of its
	// own: the fixture's assertion ID is already recorded in the other).
	k3 := []byte("third transaction key of 32 bytes or more!")
	keys := [][]byte{k3}
	e3 := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) { c.TransactionKeys = keys })
	lr = begin(t, e3, samlsp.LoginOptions{})
	keys[0][0] ^= 0xff

	_, err = complete(e3, lr, respond(t, lr.requestID, respOpts{}))
	require.NoError(t, err, "mutating the caller's slice after New changes nothing")
}

// TestCompleteLogin_ConsumesWithThePresentedBinding: the store's own
// binding comparison receives the digest of the cookie the browser
// presented and the ID derived from the connection and the handle — not
// the stored values, which it would compare with themselves (audit
// SAML-I8). The ID field a store returns is never used: the lookup key is
// the record's identity, and the MAC covers it.
func TestCompleteLogin_ConsumesWithThePresentedBinding(t *testing.T) {
	t.Parallel()

	// The store returns every record with the ID field of another
	// transaction of the same browser (whose binding check would pass).
	mem := newMemoryStore(atT0)

	var otherID string

	store := storageDouble(t, mem, func(m *samlsp.MockStorage) {
		m.EXPECT().LookupTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(ctx context.Context, id string) (*samlsp.TransactionRecord, error) {
				rec, err := mem.LookupTransaction(ctx, id)
				if err == nil && otherID != "" {
					rec.ID = otherID
				}

				return rec, err
			}).Maybe()
	})

	e := newEnv(t, withStorage(store))
	e.store = mem

	lr := begin(t, e, samlsp.LoginOptions{})
	other := begin(t, e, samlsp.LoginOptions{}, lr.cookie)
	otherID = txKey(connID, other.relayState)

	_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
	require.NoError(t, err)

	store.AssertNumberOfCalls(t, "ConsumeTransaction", 1)
	store.AssertCalled(t, "ConsumeTransaction", mock.Anything, txKey(connID, lr.relayState), bindingKey(lr.cookie.Value))

	_, err = mem.LookupTransaction(context.Background(), otherID)
	require.NoError(t, err, "the transaction named by the returned ID field is not consumed")
}
