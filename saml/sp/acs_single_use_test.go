// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// consumeCounter counts the consumptions a store is asked for, those it
// grants, and the replay marks.
type consumeCounter struct {
	*memory.Store

	calls, granted, marks atomic.Int32
}

func (c *consumeCounter) ConsumeTransaction(ctx context.Context, id, bindingHash string) error {
	c.calls.Add(1)

	err := c.Store.ConsumeTransaction(ctx, id, bindingHash)
	if err == nil {
		c.granted.Add(1)
	}

	return err
}

func (c *consumeCounter) MarkAssertionUsed(ctx context.Context, key string, expiresAt time.Time) error {
	c.marks.Add(1)

	return c.Store.MarkAssertionUsed(ctx, key, expiresAt)
}

// newCountingEnv is newEnv over a consumeCounter.
func newCountingEnv(t *testing.T, opts ...envOption) (*env, *consumeCounter) {
	t.Helper()

	c := &consumeCounter{Store: memory.New()}
	e := newEnv(t, append(opts, func(cfg *samlsp.Config, _ *samlsp.Connection) { cfg.Transactions, cfg.ReplayCache = c, c })...)
	e.store = c.Store

	return e, c
}

// concurrently runs fn on n goroutines released together and returns
// their errors by index.
func concurrently(n int, fn func(i int) error) []error {
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		errs  = make([]error, n)
	)

	start.Add(1)

	for i := range n {
		done.Add(1)

		go func() {
			defer done.Done()

			start.Wait()
			errs[i] = fn(i)
		}()
	}

	start.Done()
	done.Wait()

	return errs
}

// digestMismatch is a response whose SignedInfo the trusted IdP key signed,
// over an element changed afterwards: the costliest refusal (the whole
// element is canonicalized and digested before the mismatch).
func digestMismatch(t *testing.T, requestID string) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(worstCaseResponse(t, requestID, sigOpts{signer: keys(t).idpA}, 16))
	require.NoError(t, err)

	tampered := strings.Replace(string(raw), ">g7<", ">h7<", 1)
	require.NotEqual(t, string(raw), tampered)

	return encodeString(tampered)
}

// TestCompleteLogin_OneVerificationPerTransaction: a transaction buys one
// verification (audit SAML-01). The first response that passes the
// browser binding, the transaction and the status checks consumes it
// before any signature work: refused, the login is over — the same POST
// again and even the genuine response are refused as consumed, without
// reaching the verifier — and a new login completes.
func TestCompleteLogin_OneVerificationPerTransaction(t *testing.T) {
	t.Parallel()

	k := keys(t)
	three := trustKeys(k.idpA, k.idpB, newRSAPair(2048, "rollover-x", t0.Add(-time.Hour), t0.Add(24*time.Hour)))

	forgeries := map[string]func(t *testing.T, requestID string) string{
		"untrusted signer without KeyInfo, three trusted certificates": func(t *testing.T, requestID string) string {
			return worstCaseResponse(t, requestID, sigOpts{signer: k.attacker, noKeyInfo: true}, 16)
		},
		"trusted SignedInfo over an altered element": digestMismatch,
	}

	for name, forge := range forgeries {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e, c := newCountingEnv(t, three)
			lr := begin(t, e, samlsp.LoginOptions{})
			forged := forge(t, lr.requestID)

			_, err := complete(e, lr, forged)
			requireRejectedConsumed(t, e, lr, err, samlsp.ErrInvalidSignature)

			_, err = complete(e, lr, forged)
			requireRejectedConsumed(t, e, lr, err, samlsp.ErrTransactionConsumed)

			_, err = complete(e, lr, respond(t, lr.requestID, respOpts{}))
			requireRejectedConsumed(t, e, lr, err, samlsp.ErrTransactionConsumed)

			assert.EqualValues(t, 1, c.calls.Load(), "the later POSTs stop at the lookup")
			assert.Zero(t, c.marks.Load())

			fresh := begin(t, e, samlsp.LoginOptions{})
			res, err := complete(e, fresh, respond(t, fresh.requestID, respOpts{}))
			require.NoError(t, err)
			assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
		})
	}
}

// TestCompleteLogin_ConcurrentForgeriesVerifyOnce: 32 concurrent POSTs of a
// forged response on one transaction reach the verifier once: one
// ErrInvalidSignature, 31 ErrTransactionConsumed.
func TestCompleteLogin_ConcurrentForgeriesVerifyOnce(t *testing.T) {
	t.Parallel()

	e, c := newCountingEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	forged := respond(t, lr.requestID, respOpts{assertionSig: sigOpts{signer: keys(t).attacker}})

	errs := concurrently(32, func(int) error {
		_, err := complete(e, lr, forged)

		return err
	})

	var invalid, consumed int

	for _, err := range errs {
		switch {
		case errors.Is(err, samlsp.ErrInvalidSignature):
			invalid++
		case errors.Is(err, samlsp.ErrTransactionConsumed):
			consumed++
		default:
			t.Fatalf("unexpected outcome %v", err)
		}
	}

	assert.Equal(t, 1, invalid, "verified once")
	assert.Equal(t, 31, consumed)
	assert.EqualValues(t, 1, c.granted.Load())
}

// TestCompleteLogin_MixedConcurrentPostsVerifyOnce: the genuine response
// and seven forged ones posted concurrently from the owner's browser (a
// page forcing forged POSTs, review F5): exactly one request gets past the
// consumption — either the genuine one succeeds or a forged one is refused
// as such — and every other one is refused as consumed.
func TestCompleteLogin_MixedConcurrentPostsVerifyOnce(t *testing.T) {
	t.Parallel()

	e, c := newCountingEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	genuine := respond(t, lr.requestID, respOpts{})
	forged := respond(t, lr.requestID, respOpts{assertionSig: sigOpts{signer: keys(t).attacker}})

	errs := concurrently(8, func(i int) error {
		body := forged
		if i == 0 {
			body = genuine
		}

		_, err := complete(e, lr, body)

		return err
	})

	var past, consumed int

	for _, err := range errs {
		switch {
		case err == nil, errors.Is(err, samlsp.ErrInvalidSignature):
			past++
		case errors.Is(err, samlsp.ErrTransactionConsumed):
			consumed++
		default:
			t.Fatalf("unexpected outcome %v", err)
		}
	}

	assert.Equal(t, 1, past, "one request verified")
	assert.Equal(t, 7, consumed)
	assert.EqualValues(t, 1, c.granted.Load())
}

// TestCompleteLogin_DoubleSubmit: the owner's browser posting the genuine
// response eight times at once logs in once.
func TestCompleteLogin_DoubleSubmit(t *testing.T) {
	t.Parallel()

	e, c := newCountingEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	genuine := respond(t, lr.requestID, respOpts{})

	errs := concurrently(8, func(int) error {
		_, err := complete(e, lr, genuine)

		return err
	})

	var ok, consumed int

	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, samlsp.ErrTransactionConsumed):
			consumed++
		default:
			t.Fatalf("unexpected outcome %v", err)
		}
	}

	assert.Equal(t, 1, ok)
	assert.Equal(t, 7, consumed)
	assert.EqualValues(t, 1, c.marks.Load(), "one assertion recorded")
}

// TestCompleteLogin_OtherBrowsersNeverConsume: 31 browsers posting the
// owner's handle with their own cookies, concurrently with the owner's
// genuine response, never reach the consumption: the owner logs in.
func TestCompleteLogin_OtherBrowsersNeverConsume(t *testing.T) {
	t.Parallel()

	e, c := newCountingEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	genuine := respond(t, lr.requestID, respOpts{})

	errs := concurrently(32, func(i int) error {
		cookie := lr.cookie.Value
		if i > 0 {
			cookie = strings.Repeat("Z", 41) + fmt.Sprintf("%02d", i) // another browser's handle
		}

		_, err := e.sp.CompleteLogin(context.Background(), acsRequest(genuine, lr.relayState, cookie), connID)

		return err
	})

	require.NoError(t, errs[0], "the owner logs in")

	for _, err := range errs[1:] {
		assert.True(t, errors.Is(err, samlsp.ErrBrowserBindingMismatch) || errors.Is(err, samlsp.ErrTransactionConsumed),
			"another browser: %v", err)
	}

	assert.EqualValues(t, 1, c.calls.Load(), "only the owner reaches the consumption")
}

// TestCompleteLogin_ForcedForgeryBurnsTheLogin pins a residual risk (review
// F3): a page that knows the victim's in-flight handle and request ID —
// leaked with the IdP redirect URL (audit SAML-02) — can make her browser,
// which attaches its binding cookie, post a forged response: it is refused,
// and it consumes the transaction, so her genuine response is refused too.
// Connection.ResponseOrigins refuses such a POST before the consumption.
func TestCompleteLogin_ForcedForgeryBurnsTheLogin(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	forged := respond(t, lr.requestID, respOpts{assertionSig: sigOpts{signer: keys(t).attacker}})
	_, err := complete(e, lr, forged)
	requireRejectedConsumed(t, e, lr, err, samlsp.ErrInvalidSignature)

	_, err = complete(e, lr, respond(t, lr.requestID, respOpts{}))
	requireRejectedConsumed(t, e, lr, err, samlsp.ErrTransactionConsumed)
}

// TestCompleteLogin_LastGoodCertificateFirst: without KeyInfo, the trusted
// certificate that verified the connection's last such signature is tried
// first, so the IdP's current key costs one verification instead of up to
// three (audit SAML-01). Not parallel: it measures allocations.
func TestCompleteLogin_LastGoodCertificateFirst(t *testing.T) {
	k := keys(t)
	newest := newRSAPair(2048, "rollover-newest", t0.Add(-time.Hour), t0.Add(24*time.Hour))

	// Candidates, newest first: rollover-newest, idp-a, idp-b. The IdP
	// signs with idp-b, the last one tried.
	e := newEnv(t, trustKeys(k.idpA, k.idpB, newest))

	measure := func(assertionID string) uint64 {
		lr := begin(t, e, samlsp.LoginOptions{})
		body := respond(t, lr.requestID, respOpts{
			assertionSig:    sigOpts{signer: k.idpB, noKeyInfo: true},
			beforeAssertion: func(a *etree.Element) { a.CreateAttr("ID", assertionID) },
		})

		var err error

		_, alloc := cost(func() { _, err = complete(e, lr, body) })
		require.NoError(t, err)

		return alloc
	}

	first, second := measure("_first-login"), measure("_second-login")
	t.Logf("KeyInfo-less login signed by the third candidate: %d KiB, then %d KiB", first>>10, second>>10)
	require.Less(t, float64(second), 0.75*float64(first), "the certificate that verified last is tried first")
}

// TestCompleteLogin_LostConsumptionRaceIsFinal: another instance consumed
// the transaction between this instance's lookup, which still saw it
// pending, and its consumption. The store's refusal ends the request:
// no identity, and neither the verifier nor the replay cache is reached
// (the mock has no MarkAssertionUsed expectation). The consumption is
// asked with the derived ID and the presented binding (audit SAML-01,
// SAML-I8; code review finding 1).
func TestCompleteLogin_LostConsumptionRaceIsFinal(t *testing.T) {
	t.Parallel()

	for _, lost := range []error{samlsp.ErrTransactionConsumed, samlsp.ErrTransactionNotFound, samlsp.ErrBrowserBindingMismatch} {
		t.Run(lost.Error(), func(t *testing.T) {
			t.Parallel()

			mem := memory.New()
			store := samlsp.NewMockStorage(t)
			store.EXPECT().SaveTransaction(mock.Anything, mock.Anything).RunAndReturn(mem.SaveTransaction).Once()
			store.EXPECT().LookupTransaction(mock.Anything, mock.Anything).RunAndReturn(mem.LookupTransaction).Once()

			e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) { c.Transactions, c.ReplayCache = store, store })
			e.store = mem

			lr := begin(t, e, samlsp.LoginOptions{})
			store.EXPECT().ConsumeTransaction(mock.Anything, txKey(connID, lr.relayState), bindingKey(lr.cookie.Value)).
				Return(lost).Once()

			res, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
			assert.Nil(t, res, "a lost consumption race never logs in")
			require.ErrorIs(t, err, lost)
			require.ErrorIs(t, err, samlsp.ErrRejected)
		})
	}
}
