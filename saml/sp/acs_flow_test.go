// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/beevik/etree"
	"github.com/hyperscale-stack/security"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/hyperscale-stack/security/saml/sp/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func replayKeyHex(conn, issuer, id string) string {
	return digestHex("samlsp-v2/assertion", conn, issuer, id)
}

// requireRejected asserts err matches target and ErrRejected, and that the
// transaction of lr was not consumed.
func requireRejected(t *testing.T, e *env, lr loginResult, err error, target error) {
	t.Helper()

	require.ErrorIs(t, err, target)
	require.ErrorIs(t, err, samlsp.ErrRejected)
	require.ErrorIs(t, err, security.ErrInvalidCredentials)

	_, lerr := e.store.LookupTransaction(context.Background(), txKey(connID, lr.relayState))
	require.NoError(t, lerr, "a rejected response consumes nothing")
}

// reject runs a full flow with o and asserts the rejection.
func reject(t *testing.T, o respOpts, target error, opts ...envOption) {
	t.Helper()

	e := newEnv(t, opts...)
	lr := begin(t, e, samlsp.LoginOptions{})

	res, err := complete(e, lr, respond(t, lr.requestID, o))
	assert.Nil(t, res)
	requireRejected(t, e, lr, err, target)
}

func TestCompleteLogin_Success(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{AppState: "/projects/42"})

	res, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
	require.NoError(t, err)

	id := res.Identity
	assert.Equal(t, "/projects/42", res.AppState)
	assert.Equal(t, connID, id.ConnectionID)
	assert.Equal(t, idpEntity, id.Issuer)
	assert.Equal(t, spEntityID, id.Audience)
	assert.Equal(t, samlsp.NameID{
		Value: nameIDValue, Format: samlsp.NameIDFormatPersistent,
		NameQualifier: idpEntity, SPNameQualifier: spEntityID,
	}, id.NameID)
	assert.Equal(t, "_session-42", id.SessionIndex)
	assert.True(t, id.AuthnInstant.Equal(t0))
	assert.True(t, id.SessionNotOnOrAfter.Equal(t0.Add(8*time.Hour)))
	assert.Equal(t, pptClass, id.AuthnContextClassRef)
	assert.Equal(t, assertionID, id.AssertionID)
	assert.Nil(t, id.ProxyRestriction)
	assert.Equal(t, []samlsp.Attribute{
		{Name: "mail", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", Values: []string{"alice@example.com"}},
		{Name: "groups", Values: []string{"admins", "devs"}},
		{Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", FriendlyName: "eduPersonTargetedID", Values: []string{"targeted-7"}},
	}, id.Attributes)

	// The transaction is consumed and the assertion recorded.
	_, err = e.store.LookupTransaction(context.Background(), txKey(connID, lr.relayState))
	require.ErrorIs(t, err, samlsp.ErrTransactionConsumed)
	require.ErrorIs(t, e.store.MarkAssertionUsed(context.Background(), replayKeyHex(connID, idpEntity, assertionID), t0.Add(time.Hour)),
		samlsp.ErrAssertionReplayed)
}

func TestCompleteLogin_SignatureLevels(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name string
		o    respOpts
		opts []envOption
	}{
		{"assertion signed (Profiles §4.1.4.5)", respOpts{}, nil},
		{"response signed covering the assertion (errata E26/E93)", respOpts{unsignedAssert: true, signResponse: true}, nil},
		{"both signed", respOpts{signResponse: true}, nil},
		{"exclusive C14N with comments", respOpts{assertionSig: sigOpts{canon: exclusiveWithComments()}}, nil},
		{"ECDSA P-256 key (goxmldsig DER encoding)", respOpts{assertionSig: sigOpts{signer: k.idpEC}}, []envOption{trustKeys(k.idpEC)}},
		{"rsa-sha512", respOpts{assertionSig: sigOpts{method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"}}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := flow(t, newEnv(t, tc.opts...), tc.o)
			require.NoError(t, err)
			assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
		})
	}
}

// trustKeys replaces the connection's trusted keys.
func trustKeys(pairs ...keyPair) envOption {
	return func(_ *samlsp.Config, c *samlsp.Connection) {
		c.IdentityProvider.SigningCertificates = nil
		for _, p := range pairs {
			c.IdentityProvider.SigningCertificates = append(c.IdentityProvider.SigningCertificates, p.cert)
		}
	}
}

func TestCompleteLogin_Replay(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, respOpts{})

	_, err := complete(e, lr, resp)
	require.NoError(t, err)

	// The same POST again: the transaction is gone.
	_, err = complete(e, lr, resp)
	require.ErrorIs(t, err, samlsp.ErrTransactionConsumed)
	require.ErrorIs(t, err, samlsp.ErrRejected)
}

// spyCache records MarkAssertionUsed calls and can fail them.
type spyCache struct {
	samlsp.ReplayCache
	mu   sync.Mutex
	keys []string
	exps []time.Time
	err  error
}

func (s *spyCache) MarkAssertionUsed(ctx context.Context, key string, exp time.Time) error {
	s.mu.Lock()
	s.keys = append(s.keys, key)
	s.exps = append(s.exps, exp)
	s.mu.Unlock()

	if s.err != nil {
		return s.err
	}

	return s.ReplayCache.MarkAssertionUsed(ctx, key, exp)
}

// withReplayCache wraps the replay cache with a spy.
func newSpyEnv(t *testing.T, spy *spyCache, opts ...envOption) *env {
	t.Helper()

	e := newEnv(t, opts...)
	spy.ReplayCache = e.store

	sp, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: e.store, ReplayCache: spy, Now: e.clock.Now})
	require.NoError(t, err)

	e.sp = sp

	return e
}

func TestCompleteLogin_ReplayCacheKeyAndRetention(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		scdNOA  time.Duration // SubjectConfirmationData NotOnOrAfter, relative to t0
		wantExp time.Time
	}{
		// min(ceil(SCD NotOnOrAfter + skew), transaction expiry) + 1 minute.
		{"short confirmation window", 5 * time.Minute, t0.Add(5*time.Minute + samlsp.DefaultClockSkew + time.Minute)},
		{"window beyond the transaction", 30 * time.Minute, t0.Add(samlsp.DefaultTransactionTTL + time.Minute)},
		{"window of years is capped (review F10)", 5 * 365 * 24 * time.Hour, t0.Add(samlsp.DefaultTransactionTTL + time.Minute)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &spyCache{}
			e := newSpyEnv(t, spy)
			lr := begin(t, e, samlsp.LoginOptions{})

			_, err := complete(e, lr, respond(t, lr.requestID, respOpts{beforeAssertion: func(a *etree.Element) {
				exp := t0.Add(tc.scdNOA).Format("2006-01-02T15:04:05Z")
				path(a, "Subject", "SubjectConfirmation", "SubjectConfirmationData").CreateAttr("NotOnOrAfter", exp)
				path(a, "Conditions").CreateAttr("NotOnOrAfter", exp)
			}}))
			require.NoError(t, err)

			require.Len(t, spy.keys, 1)
			assert.Equal(t, replayKeyHex(connID, idpEntity, assertionID), spy.keys[0], "keyed per connection and issuer (Profiles §4.1.4.5)")
			assert.True(t, spy.exps[0].Equal(tc.wantExp), "got %s, want %s", spy.exps[0], tc.wantExp)
		})
	}
}

func TestCompleteLogin_ReplayedAssertionRejected(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	require.NoError(t, e.store.MarkAssertionUsed(context.Background(), replayKeyHex(connID, idpEntity, assertionID), t0.Add(time.Hour)))

	lr := begin(t, e, samlsp.LoginOptions{})
	_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
	require.ErrorIs(t, err, samlsp.ErrAssertionReplayed)
	require.ErrorIs(t, err, samlsp.ErrRejected)

	// The transaction was consumed before the replay check: fail closed.
	_, err = e.store.LookupTransaction(context.Background(), txKey(connID, lr.relayState))
	require.ErrorIs(t, err, samlsp.ErrTransactionConsumed)
}

func TestCompleteLogin_ConcurrentConsumptionAcrossInstances(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	other, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: e.store, ReplayCache: e.store, Now: e.clock.Now})
	require.NoError(t, err)

	instances := []*samlsp.ServiceProvider{e.sp, other}
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, respOpts{})

	const racers = 50

	var (
		wg        sync.WaitGroup
		start     = make(chan struct{})
		mu        sync.Mutex
		successes int
	)

	for i := 0; i < racers; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			<-start

			_, err := instances[i%2].CompleteLogin(context.Background(), acsRequest(resp, lr.relayState, lr.cookie.Value), connID)

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				successes++

				return
			}

			if !errors.Is(err, samlsp.ErrTransactionConsumed) && !errors.Is(err, samlsp.ErrAssertionReplayed) {
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	assert.Equal(t, 1, successes, "at most one consumption across instances")
}

func TestCompleteLogin_FailureSemantics(t *testing.T) {
	t.Parallel()

	t.Run("a rejected response consumes nothing", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{beforeAssertion: func(a *etree.Element) {
			path(a, "Conditions", "AudienceRestriction", "Audience").SetText("https://evil.example/\n injected")
		}}))
		require.ErrorIs(t, err, samlsp.ErrAudienceMismatch)
		assert.NotContains(t, err.Error(), "evil", "error messages never echo message content")

		_, err = complete(e, lr, respond(t, lr.requestID, respOpts{}))
		require.NoError(t, err, "the transaction survived the forged response")
	})

	t.Run("replay cache failure after consumption", func(t *testing.T) {
		t.Parallel()

		boom := errors.New("cache down")
		e := newSpyEnv(t, &spyCache{err: boom})
		lr := begin(t, e, samlsp.LoginOptions{})

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
		require.ErrorIs(t, err, boom)
		require.NotErrorIs(t, err, samlsp.ErrRejected, "an infrastructure failure is not a rejection")

		_, err = e.store.LookupTransaction(context.Background(), txKey(connID, lr.relayState))
		require.ErrorIs(t, err, samlsp.ErrTransactionConsumed, "fail closed: the transaction stays consumed")
	})

	t.Run("lookup failure", func(t *testing.T) {
		t.Parallel()

		boom := errors.New("store down")
		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		sp, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: lookupFailing{e.store, boom}, ReplayCache: e.store, Now: e.clock.Now})
		require.NoError(t, err)

		_, err = sp.CompleteLogin(context.Background(), acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value), connID)
		require.ErrorIs(t, err, boom)
		require.NotErrorIs(t, err, samlsp.ErrRejected)
	})

	t.Run("consume failure", func(t *testing.T) {
		t.Parallel()

		boom := errors.New("store down")
		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		sp, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: consumeFailing{e.store, boom}, ReplayCache: e.store, Now: e.clock.Now})
		require.NoError(t, err)

		_, err = sp.CompleteLogin(context.Background(), acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value), connID)
		require.ErrorIs(t, err, boom)
		require.NotErrorIs(t, err, samlsp.ErrRejected)
	})

	t.Run("corrupt transaction payload", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		// A payload the SP cannot decode, under a valid MAC: written with
		// the key, so a store failure, not a rejection.
		store := memory.New()
		rec := &samlsp.TransactionRecord{
			ID: txKey(connID, lr.relayState), BindingHash: bindingKey(lr.cookie.Value),
			Payload: `{"v":99}`, ExpiresAt: t0.Add(time.Hour),
		}
		rec.Integrity = integrityHex(testTransactionKeys[0], rec)
		require.NoError(t, store.SaveTransaction(context.Background(), rec))

		sp, err := samlsp.New(samlsp.Config{TransactionKeys: testTransactionKeys, Connections: e.resolver, Transactions: store, ReplayCache: store, Now: e.clock.Now})
		require.NoError(t, err)

		_, err = sp.CompleteLogin(context.Background(), acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value), connID)
		require.Error(t, err)
		require.NotErrorIs(t, err, samlsp.ErrRejected, "store corruption is not a rejection")
	})
}

type lookupFailing struct {
	samlsp.Storage
	err error
}

func (f lookupFailing) LookupTransaction(context.Context, string) (*samlsp.TransactionRecord, error) {
	return nil, f.err
}

type consumeFailing struct {
	samlsp.Storage
	err error
}

func (f consumeFailing) ConsumeTransaction(context.Context, string, string) error { return f.err }

func TestCompleteLogin_TransactionStates(t *testing.T) {
	t.Parallel()

	t.Run("unknown handle", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})
		resp := respond(t, lr.requestID, respOpts{})

		_, err := e.sp.CompleteLogin(context.Background(), acsRequest(resp, newHandleLike("x"), lr.cookie.Value), connID)
		require.ErrorIs(t, err, samlsp.ErrTransactionNotFound)
	})

	t.Run("expiry boundaries", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			at   time.Duration
			want error
		}{
			{samlsp.DefaultTransactionTTL - time.Second, nil},
			{samlsp.DefaultTransactionTTL, samlsp.ErrTransactionExpired},
		} {
			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})
			e.clock.set(t0.Add(tc.at))

			// The IdP answered just before the transaction expiry.
			_, err := complete(e, lr, respond(t, lr.requestID, respOpts{issued: t0.Add(tc.at - time.Minute)}))
			if tc.want == nil {
				require.NoError(t, err, "one second before expiry")

				continue
			}

			requireRejected(t, e, lr, err, tc.want)
		}
	})
}

// newHandleLike returns a syntactically valid handle that was never issued.
func newHandleLike(seed string) string {
	return strings.Repeat(seed, 43)[:43]
}

func TestCompleteLogin_BrowserBinding(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, respOpts{})

	cases := []struct {
		name   string
		cookie string
		want   error
	}{
		{"no cookie (e.g. a Lax cookie on the cross-site POST)", "", samlsp.ErrMissingBrowserBinding},
		{"malformed cookie", "garbage", samlsp.ErrMissingBrowserBinding},
		{"another browser", newHandleLike("B"), samlsp.ErrBrowserBindingMismatch},
	}

	for _, tc := range cases {
		_, err := e.sp.CompleteLogin(context.Background(), acsRequest(resp, lr.relayState, tc.cookie), connID)
		requireRejected(t, e, lr, err, tc.want)
	}

	// The legitimate browser still completes: nothing was consumed.
	_, err := complete(e, lr, resp)
	require.NoError(t, err)
}

func TestCompleteLogin_CrossConnectionSubstitution(t *testing.T) {
	t.Parallel()

	globex := func() *samlsp.Connection {
		c := newConnection(t)
		c.ID = "globex"
		c.SPEntityID = "https://sp.example.com/saml/globex"
		c.ACSURL = "https://sp.example.com/saml/globex/acs"

		return c
	}

	t.Run("handle presented at another connection's ACS", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		e.resolver.set(globex())
		lr := begin(t, e, samlsp.LoginOptions{})

		req := acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value)
		req.URL.Path = "/saml/globex/acs"

		_, err := e.sp.CompleteLogin(context.Background(), req, "globex")
		requireRejected(t, e, lr, err, samlsp.ErrTransactionNotFound)
	})

	t.Run("response of the right connection posted to another path", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})

		req := acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value)
		req.URL.Path = "/elsewhere"

		_, err := e.sp.CompleteLogin(context.Background(), req, connID)
		requireRejected(t, e, lr, err, samlsp.ErrDestinationMismatch)
	})

	mutations := []struct {
		name   string
		mutate func(*samlsp.Connection)
		want   error
	}{
		{"connection deleted", nil, samlsp.ErrUnknownConnection},
		{"IdP entity ID changed", func(c *samlsp.Connection) { c.IdentityProvider.EntityID = "https://other-idp.example.com" }, samlsp.ErrTransactionMismatch},
		{"SP entity ID changed", func(c *samlsp.Connection) { c.SPEntityID = "https://sp.example.com/saml/v2" }, samlsp.ErrTransactionMismatch},
		{"metadata expired", func(c *samlsp.Connection) { c.IdentityProvider.ValidUntil = t0 }, samlsp.ErrMetadataExpired},
		{"connection became invalid", func(c *samlsp.Connection) { c.IdentityProvider.SigningCertificates = nil }, samlsp.ErrInvalidConnection},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})
			resp := respond(t, lr.requestID, respOpts{})

			if m.mutate == nil {
				e.resolver.remove(connID)
			} else {
				c := newConnection(t)
				m.mutate(c)
				e.resolver.set(c)
			}

			_, err := complete(e, lr, resp)
			require.ErrorIs(t, err, m.want)
			require.ErrorIs(t, err, samlsp.ErrRejected, "met during CompleteLogin, it rejects the login")
		})
	}

	t.Run("resolver failure is not a rejection", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t)
		lr := begin(t, e, samlsp.LoginOptions{})
		e.resolver.err = errors.New("db down")

		_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
		require.Error(t, err)
		require.NotErrorIs(t, err, samlsp.ErrRejected)
	})
}

func TestCompleteLogin_MalformedRequest(t *testing.T) {
	t.Parallel()

	e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) { c.MaxResponseSize = samlsp.MinMaxResponseSize })
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, respOpts{})

	post := func(method, contentType, body string) error {
		req := httptest.NewRequest(method, acsURL, strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: lr.cookie.Value})

		_, err := e.sp.CompleteLogin(context.Background(), req, connID)

		return err
	}

	form := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			v.Add(kv[i], kv[i+1])
		}

		return v.Encode()
	}

	const ct = "application/x-www-form-urlencoded"

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"GET", post(http.MethodGet, ct, form("SAMLResponse", resp, "RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"JSON body", post(http.MethodPost, "application/json", `{}`), samlsp.ErrMalformedRequest},
		{"bad content type", post(http.MethodPost, ";;", ""), samlsp.ErrMalformedRequest},
		{"form sent as text/plain", post(http.MethodPost, "text/plain", form("SAMLResponse", resp, "RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"missing SAMLResponse", post(http.MethodPost, ct, form("RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"empty SAMLResponse", post(http.MethodPost, ct, form("SAMLResponse", "", "RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"two SAMLResponse", post(http.MethodPost, ct, form("SAMLResponse", resp, "SAMLResponse", resp, "RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"two RelayState", post(http.MethodPost, ct, form("SAMLResponse", resp, "RelayState", lr.relayState, "RelayState", lr.relayState)), samlsp.ErrMalformedRequest},
		{"bad form encoding", post(http.MethodPost, ct, "SAMLResponse=%zz"), samlsp.ErrMalformedRequest},
		{"body over MaxResponseSize", post(http.MethodPost, ct, form("SAMLResponse", resp+strings.Repeat("A", samlsp.MinMaxResponseSize))), samlsp.ErrResponseTooLarge},
		// The body is capped as it is read, whatever the field.
		{"other fields over MaxResponseSize", post(http.MethodPost, ct, form("SAMLResponse", resp, "RelayState", lr.relayState,
			"padding", strings.Repeat("A", samlsp.MinMaxResponseSize))), samlsp.ErrResponseTooLarge},
	}

	for _, tc := range cases {
		requireRejected(t, e, lr, tc.err, tc.want)
	}

	// A charset parameter is accepted (mime.ParseMediaType), and so is a
	// form the application already parsed.
	require.NoError(t, post(http.MethodPost, ct+"; charset=UTF-8", form("SAMLResponse", resp, "RelayState", lr.relayState)))

	_, err := e.sp.CompleteLogin(context.Background(), nil, connID)
	require.ErrorIs(t, err, samlsp.ErrInvalidConfig)
}

func TestCompleteLogin_UnreadableBody(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	req := httptest.NewRequest(http.MethodPost, acsURL, iotest.ErrReader(errors.New("connection reset")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: lr.cookie.Value})

	_, err := e.sp.CompleteLogin(context.Background(), req, connID)
	requireRejected(t, e, lr, err, samlsp.ErrMalformedRequest)
}

func TestCompleteLogin_PreParsedForm(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	req := acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value)
	require.NoError(t, req.ParseForm())

	_, err := e.sp.CompleteLogin(context.Background(), req, connID)
	require.NoError(t, err)
}

func TestCompleteLogin_PreParsedFormIsBounded(t *testing.T) {
	t.Parallel()

	e := newEnv(t) // MaxResponseSize = 256 KiB
	lr := begin(t, e, samlsp.LoginOptions{})

	// The application or a middleware parsed the form first (Go's own limit
	// is 10 MB): the SAMLResponse itself must stay within MaxResponseSize
	// (code review F2), here 256 KiB, below the 1 MiB the lexical gate
	// admits whatever the configuration.
	big := respond(t, lr.requestID, respOpts{raw: func(s string) string {
		return strings.Replace(s, "<samlp:Status>", "<!--"+strings.Repeat("x", 512<<10)+"--><samlp:Status>", 1)
	}})

	req := acsRequest(big, lr.relayState, lr.cookie.Value)
	require.NoError(t, req.ParseForm())

	_, err := e.sp.CompleteLogin(context.Background(), req, connID)
	requireRejected(t, e, lr, err, samlsp.ErrResponseTooLarge)

	// Within the limit, a parsed form is used as it is.
	req = acsRequest(respond(t, lr.requestID, respOpts{}), lr.relayState, lr.cookie.Value)
	require.NoError(t, req.ParseForm())

	_, err = e.sp.CompleteLogin(context.Background(), req, connID)
	require.NoError(t, err)
}

// nilLookupStore is a non-conformant store whose LookupTransaction returns
// neither a record nor an error.
type nilLookupStore struct{ samlsp.TransactionStore }

func (nilLookupStore) LookupTransaction(context.Context, string) (*samlsp.TransactionRecord, error) {
	return nil, nil //nolint:nilnil // the non-conformance under test
}

func TestCompleteLogin_NilTransactionRecord(t *testing.T) {
	t.Parallel()

	// A store returning (nil, nil) means "not found", never a panic (code
	// review F9).
	e := newEnv(t, func(c *samlsp.Config, _ *samlsp.Connection) { c.Transactions = nilLookupStore{c.Transactions} })
	lr := begin(t, e, samlsp.LoginOptions{})

	_, err := complete(e, lr, respond(t, lr.requestID, respOpts{}))
	require.ErrorIs(t, err, samlsp.ErrTransactionNotFound)
	require.ErrorIs(t, err, samlsp.ErrRejected)
}

func TestCompleteLogin_RejectsUnsolicited(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	resp := respond(t, lr.requestID, respOpts{})

	for _, relayState := range []string{"", "https://app.example.com/after", lr.relayState + "x", lr.relayState[:42] + "!"} {
		_, err := e.sp.CompleteLogin(context.Background(), acsRequest(resp, relayState, lr.cookie.Value), connID)
		requireRejected(t, e, lr, err, samlsp.ErrUnsolicitedResponse)
	}

	// IdP-initiated: no InResponseTo anywhere, posted with a valid handle.
	unsolicited := respond(t, lr.requestID, respOpts{
		beforeAssertion: func(a *etree.Element) {
			path(a, "Subject", "SubjectConfirmation", "SubjectConfirmationData").RemoveAttr("InResponseTo")
		},
		before: func(resp, _ *etree.Element) { resp.RemoveAttr("InResponseTo") },
	})

	_, err := complete(e, lr, unsolicited)
	requireRejected(t, e, lr, err, samlsp.ErrUnsolicitedResponse)
}

func TestCompleteLogin_StatusError(t *testing.T) {
	t.Parallel()

	statusResponse := func(requestID string, sub, msg string) string {
		r := buildResponse(respParams{requestID: requestID, issued: t0})
		sc := path(r, "Status", "StatusCode")
		sc.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")

		if sub != "" {
			sc.CreateElement("samlp:StatusCode").CreateAttr("Value", sub)
		}

		if msg != "" {
			child(r, "Status").CreateElement("samlp:StatusMessage").SetText(msg)
		}

		return encodeElement(t, r)
	}

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{AppState: "/back", IsPassive: true})

	_, err := complete(e, lr, statusResponse(lr.requestID, "urn:oasis:names:tc:SAML:2.0:status:NoPassive", "user\t\u009b[31m not\nsigned in"))
	requireRejected(t, e, lr, err, samlsp.ErrResponseStatus)

	var se *samlsp.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Responder", se.Code)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:NoPassive", se.SubCode)
	assert.Equal(t, "user[31m notsigned in", se.Message, "control characters stripped")
	assert.Equal(t, connID, se.ConnectionID)
	assert.Equal(t, "/back", se.AppState)

	// Hostile codes are sanitized in the fields, which keep visible ASCII
	// only, at most 256 bytes, and Error() names none (code review F5).
	hostile := buildResponse(respParams{requestID: lr.requestID, issued: t0})
	sc := path(hostile, "Status", "StatusCode")
	sc.CreateAttr("Value", "level=error msg=admin user=root "+strings.Repeat("x", 400))
	sc.CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:x \u0085sub\tcode")

	_, err = complete(e, lr, encodeElement(t, hostile))
	requireRejected(t, e, lr, err, samlsp.ErrResponseStatus)
	require.ErrorAs(t, err, &se)
	assert.True(t, strings.HasPrefix(se.Code, "level=errormsg=adminuser=rootxxx"), se.Code)
	assert.Len(t, se.Code, 256)
	assert.Equal(t, "urn:xsubcode", se.SubCode)
	assert.NotContains(t, err.Error(), "level")
	assert.NotContains(t, err.Error(), "urn:x")

	// An error status is only reported for the bound browser (review F8).
	_, err = e.sp.CompleteLogin(context.Background(), acsRequest(statusResponse(lr.requestID, "", ""), lr.relayState, newHandleLike("Z")), connID)
	requireRejected(t, e, lr, err, samlsp.ErrBrowserBindingMismatch)

	// A present InResponseTo must match.
	_, err = complete(e, lr, statusResponse("_other", "", ""))
	requireRejected(t, e, lr, err, samlsp.ErrInResponseToMismatch)

	// An error response MUST NOT carry assertions (Profiles §4.1.4.2).
	withAssertion := respond(t, lr.requestID, respOpts{before: func(resp, _ *etree.Element) {
		path(resp, "Status", "StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Requester")
	}})
	_, err = complete(e, lr, withAssertion)
	requireRejected(t, e, lr, err, samlsp.ErrMalformedResponse)

	// A message longer than 256 bytes is capped.
	_, err = complete(e, lr, statusResponse(lr.requestID, "", strings.Repeat("é", 300)))
	require.ErrorAs(t, err, &se)
	assert.LessOrEqual(t, len(se.Message), 256)
}

// TestCompleteLogin_SuccessStatusIsExact: Success is decided on the exact
// status code (Core §3.2.2.2). A code that is Success only once white space
// or control characters are stripped is malformed: neither a login (gosaml2
// compares the raw value) nor a *StatusError claiming "Success" (audit
// SAML-I6). It is refused before any signature work and consumes nothing.
func TestCompleteLogin_SuccessStatusIsExact(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"trailing tab":      `status:Success&#x9;"`,
		"trailing newline":  `status:Success&#xA;"`,
		"trailing space":    `status:Success "`,
		"carriage return":   `status:Success&#xD;"`,
		"non-breaking byte": "status:Success\u0085\"",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})

			xml := respondXML(t, lr.requestID, respOpts{})
			require.Contains(t, xml, `status:Success"`)

			res, err := complete(e, lr, encodeString(strings.Replace(xml, `status:Success"`, value, 1)))
			assert.Nil(t, res)
			requireRejected(t, e, lr, err, samlsp.ErrMalformedResponse)
			require.NotErrorIs(t, err, samlsp.ErrResponseStatus)
			assert.Equal(t, samlsp.ErrMalformedResponse.Error()+" (malformed Success status code)", err.Error())
		})
	}

	// A non-Success code with white space stays an IdP error status.
	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})
	r := buildResponse(respParams{requestID: lr.requestID, issued: t0})
	path(r, "Status", "StatusCode").CreateAttr("Value", " urn:oasis:names:tc:SAML:2.0:status:Requester\t")

	_, err := complete(e, lr, encodeElement(t, r))

	var se *samlsp.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Requester", se.Code)
}

// TestCompleteLogin_StatusMessageFormatCharacters: the StatusMessage comes
// from an unauthenticated message; Unicode format and separator characters
// (bidi overrides, zero-width characters, line and paragraph separators)
// would let it spoof a log line or a rendering, so they are stripped like
// control characters, while letters of every script stay (audit SAML-I7).
func TestCompleteLogin_StatusMessageFormatCharacters(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	lr := begin(t, e, samlsp.LoginOptions{})

	r := buildResponse(respParams{requestID: lr.requestID, issued: t0})
	path(r, "Status", "StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
	child(r, "Status").CreateElement("samlp:StatusMessage").SetText(
		"Échec\u202e\u2066 認証\u200b\u200c\u200d\u200e\u200f\u2028level=error\u2029\ufeff\u00ad\u2060\u061c ok")

	_, err := complete(e, lr, encodeElement(t, r))

	var se *samlsp.StatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "Échec 認証level=error ok", se.Message)
}

// encodeElement serializes and base64-encodes an element.
func encodeElement(t testing.TB, el *etree.Element) string {
	t.Helper()

	doc := etree.NewDocument()
	doc.SetRoot(el)

	s, err := doc.WriteToString()
	require.NoError(t, err)

	return encodeString(s)
}

// TestCompleteLogin_ACSLocation: a response is accepted only where the
// connection's ACS URL says it is delivered — same path (escaped form), same
// host (r.Host, case-insensitively, the scheme's default port filled in) and
// no query string (Core §3.2.2 Destination: "the actual recipient MUST
// check that the URI reference identifies the location at which the message
// was received"; Bindings §3.5.5.2; Profiles §4.1.4.3; audit SAML-I9).
// Each refusal comes before any signature work and consumes nothing.
func TestCompleteLogin_ACSLocation(t *testing.T) {
	t.Parallel()

	request := func(target string, lr loginResult, body string) *http.Request {
		form := url.Values{"SAMLResponse": {body}, "RelayState": {lr.relayState}}
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: lr.cookie.Value})

		return req
	}

	const (
		hostDetail  = "request received at another host than the connection's ACS URL"
		queryDetail = "request received with a query string"
		pathDetail  = "request received outside the connection's ACS path"
	)

	refused := []struct {
		name, target, host, detail string
	}{
		{"another host", "https://other.example.com/saml/acme/acs", "", hostDetail},
		{"another port", "https://sp.example.com:8443/saml/acme/acs", "", hostDetail},
		{"a sibling host", "https://evil.sp.example.com/saml/acme/acs", "", hostDetail},
		{"a trailing dot", acsURL, "sp.example.com.", hostDetail},
		{"no Host", acsURL, "-", hostDetail},
		{"a query string", acsURL + "?x=1", "", queryDetail},
		{"an empty query string", acsURL + "?", "", queryDetail},
		{"an escaped slash in the path", "https://sp.example.com/saml/acme%2Facs", "", pathDetail},
		{"another path", "https://sp.example.com/saml/acme/acs2", "", pathDetail},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})

			req := request(tc.target, lr, respond(t, lr.requestID, respOpts{}))

			switch tc.host {
			case "-":
				req.Host = ""
			case "":
			default:
				req.Host = tc.host
			}

			res, err := e.sp.CompleteLogin(context.Background(), req, connID)
			assert.Nil(t, res)
			requireRejected(t, e, lr, err, samlsp.ErrDestinationMismatch)
			assert.Equal(t, samlsp.ErrDestinationMismatch.Error()+" ("+tc.detail+")", err.Error())
		})
	}

	accepted := []struct {
		name, target, host string
	}{
		{"the ACS URL", acsURL, ""},
		{"the default port spelled out", "https://sp.example.com:443/saml/acme/acs", ""},
		{"an upper-case Host", acsURL, "SP.Example.COM"},
	}

	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t)
			lr := begin(t, e, samlsp.LoginOptions{})

			req := request(tc.target, lr, respond(t, lr.requestID, respOpts{}))
			if tc.host != "" {
				req.Host = tc.host
			}

			res, err := e.sp.CompleteLogin(context.Background(), req, connID)
			require.NoError(t, err)
			assert.Equal(t, nameIDValue, res.Identity.NameID.Value)
		})
	}
}

// TestCompleteLogin_ReplayCacheIsPerConnection: a tenant may configure a
// connection whose IdP claims another tenant's IdP entity ID (identities
// are unique within a connection only). Before the replay cache was scoped
// by connection, an assertion ID consumed at the squatting connection was
// then refused as a replay at the victim's (audit SAML-I2). An assertion
// cannot be accepted at two connections anyway: its Audience, Recipient
// and InResponseTo bind it to one transaction of one connection.
func TestCompleteLogin_ReplayCacheIsPerConnection(t *testing.T) {
	t.Parallel()

	e := newEnv(t) // connection acme trusts idpA for idpEntity
	k := keys(t)

	const evilID, evilSP, evilACS = "evil", "https://sp.example.com/saml/evil", "https://sp.example.com/saml/evil/acs"

	e.resolver.set(&samlsp.Connection{
		ID: evilID, SPEntityID: evilSP, ACSURL: evilACS,
		IdentityProvider: samlsp.IdentityProvider{
			EntityID: idpEntity, // collides with acme's IdP entity ID
			SSOURL:   "https://attacker.example/sso", SigningCertificates: []*x509.Certificate{k.attacker.cert},
		},
	})

	// The squatter signs in at her connection with an assertion whose ID is
	// the one acme's IdP uses next (here the fixture's fixed assertion ID).
	rec := httptest.NewRecorder()
	redirect, err := e.sp.BeginLogin(context.Background(), rec, httptest.NewRequest(http.MethodGet, "/login", nil), evilID,
		samlsp.LoginOptions{})
	require.NoError(t, err)

	u, err := url.Parse(redirect)
	require.NoError(t, err)

	evil := loginResult{url: u, relayState: u.Query().Get("RelayState"), cookie: rec.Result().Cookies()[0]}
	evil.request = decodeAuthnRequest(t, u)
	evil.requestID = evil.request.SelectAttrValue("ID", "")

	body := respond(t, evil.requestID, respOpts{
		assertionSig: sigOpts{signer: k.attacker},
		before: func(r, _ *etree.Element) {
			r.RemoveAttr("Destination")
			r.CreateAttr("Destination", evilACS)
		},
		beforeAssertion: func(a *etree.Element) {
			scd(a).CreateAttr("Recipient", evilACS)
			path(a, "Conditions", "AudienceRestriction", "Audience").SetText(evilSP)
		},
	})

	form := url.Values{"SAMLResponse": {body}, "RelayState": {evil.relayState}}
	post := httptest.NewRequest(http.MethodPost, evilACS, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: samlsp.DefaultCookieName, Value: evil.cookie.Value})

	res, err := e.sp.CompleteLogin(context.Background(), post, evilID)
	require.NoError(t, err)
	require.Equal(t, assertionID, res.Identity.AssertionID)

	// The victim's genuine login at acme, signed by acme's IdP key.
	victim := begin(t, e, samlsp.LoginOptions{})
	res, err = complete(e, victim, respond(t, victim.requestID, respOpts{}))
	require.NoError(t, err, "the squatter's consumption does not burn acme's assertion IDs")
	assert.Equal(t, assertionID, res.Identity.AssertionID)

	// The same assertion at the same connection is still a replay.
	again := begin(t, e, samlsp.LoginOptions{})
	_, err = complete(e, again, respond(t, again.requestID, respOpts{}))
	require.ErrorIs(t, err, samlsp.ErrAssertionReplayed)
}
