// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test doubles --------------------------------------------------------

type fakeStore struct {
	clients map[string]oauth2.Client
	err     error
}

func (s fakeStore) LoadClient(_ context.Context, id string) (oauth2.Client, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.clients[id], nil
}

// countingStore is a fakeStore that counts its LoadClient calls.
type countingStore struct {
	fakeStore
	calls atomic.Int32
}

func (s *countingStore) LoadClient(ctx context.Context, id string) (oauth2.Client, error) {
	s.calls.Add(1)

	return s.fakeStore.LoadClient(ctx, id)
}

// noMatcherClient implements oauth2.Client but NOT oauth2.SecretMatcher.
type noMatcherClient struct {
	id      string
	typ     oauth2.ClientType
	methods []string
}

func (c noMatcherClient) ID() string              { return c.id }
func (c noMatcherClient) Type() oauth2.ClientType { return c.typ }
func (c noMatcherClient) RedirectURIs() []string  { return nil }
func (c noMatcherClient) GrantTypes() []string    { return nil }
func (c noMatcherClient) Scopes() []string        { return nil }
func (c noMatcherClient) AuthMethods() []string   { return c.methods }

func confidentialClient(methods ...string) *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		IDValue:          "c1",
		Secret:           "s3cr3t",
		TypeValue:        oauth2.ClientConfidential,
		AuthMethodValues: methods,
	}
}

func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// assertInvalidClient asserts err carries the invalid_client OAuth2 code.
// The authenticators return WithDescription / WithCause copies of the
// sentinel, so the stable check is the embedded code, not pointer identity.
func assertInvalidClient(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	assert.Equal(t, oauth2.CodeInvalidClient, oauth2.IsCode(err))
}

func postReq(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}

// --- helpers -------------------------------------------------------------

func TestDecodeBasic(t *testing.T) {
	t.Parallel()

	id, secret, ok := decodeBasic(basicHeader("alice", "pw:with:colons"))
	require.True(t, ok)
	assert.Equal(t, "alice", id)
	assert.Equal(t, "pw:with:colons", secret)

	for _, bad := range []string{
		"",
		"Bearer xyz",
		"Basic !!!not-base64!!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon")),
	} {
		_, _, ok := decodeBasic(bad)
		assert.False(t, ok, bad)
	}
}

func TestAllowsMethod(t *testing.T) {
	t.Parallel()

	// Empty AuthMethods means "any method".
	assert.True(t, allowsMethod(confidentialClient(), "client_secret_basic"))
	// Listed method matches case-insensitively.
	assert.True(t, allowsMethod(confidentialClient("Client_Secret_Basic"), "client_secret_basic"))
	// Unlisted method is refused.
	assert.False(t, allowsMethod(confidentialClient("none"), "client_secret_basic"))
}

func TestErrInvalid(t *testing.T) {
	t.Parallel()

	// A nil cause returns the bare sentinel.
	assert.ErrorIs(t, errInvalid(nil), oauth2.ErrInvalidClient)

	// A non-nil cause returns an invalid_client error wrapping the cause.
	cause := errors.New("db down")
	got := errInvalid(cause)
	assert.Equal(t, oauth2.CodeInvalidClient, oauth2.IsCode(got))
	assert.ErrorIs(t, got, cause)
}

// --- client_secret_basic -------------------------------------------------

func TestBasicMethodAndMatch(t *testing.T) {
	t.Parallel()

	b := NewBasic()
	assert.Equal(t, "client_secret_basic", b.Method())

	assert.False(t, b.Match(nil))
	assert.False(t, b.Match(httptest.NewRequest(http.MethodPost, "/", nil)))

	withBasic := httptest.NewRequest(http.MethodPost, "/", nil)
	withBasic.Header.Set("Authorization", basicHeader("c1", "s3cr3t"))
	assert.True(t, b.Match(withBasic))
}

func TestBasicAuthenticate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient()}}

	req := func(header string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}

		return r
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		c, err := NewBasic().Authenticate(ctx, req(basicHeader("c1", "s3cr3t")), store)
		require.NoError(t, err)
		assert.Equal(t, "c1", c.ID())
	})

	t.Run("malformed header", func(t *testing.T) {
		t.Parallel()

		_, err := NewBasic().Authenticate(ctx, req("Basic not-base64!"), store)
		assertInvalidClient(t, err)
	})

	t.Run("unknown client", func(t *testing.T) {
		t.Parallel()

		_, err := NewBasic().Authenticate(ctx, req(basicHeader("ghost", "x")), store)
		assertInvalidClient(t, err)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		down := errors.New("db down")
		_, err := NewBasic().Authenticate(ctx, req(basicHeader("c1", "s3cr3t")), fakeStore{err: down})
		assertStoreFailure(t, err, down)

		_, err = NewBasic().Authenticate(ctx, req(basicHeader("c1", "s3cr3t")), fakeStore{err: oauth2.ErrInvalidClient})
		assertInvalidClient(t, err)
	})

	t.Run("method not allowed", func(t *testing.T) {
		t.Parallel()

		only := fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient("none")}}
		_, err := NewBasic().Authenticate(ctx, req(basicHeader("c1", "s3cr3t")), only)
		assertInvalidClient(t, err)
	})

	t.Run("client cannot verify secret", func(t *testing.T) {
		t.Parallel()

		noMatcher := fakeStore{clients: map[string]oauth2.Client{
			"c1": noMatcherClient{id: "c1", typ: oauth2.ClientConfidential},
		}}
		_, err := NewBasic().Authenticate(ctx, req(basicHeader("c1", "s3cr3t")), noMatcher)
		assertInvalidClient(t, err)
	})

	t.Run("secret mismatch", func(t *testing.T) {
		t.Parallel()

		_, err := NewBasic().Authenticate(ctx, req(basicHeader("c1", "wrong")), store)
		assertInvalidClient(t, err)
	})
}

// --- client_secret_post --------------------------------------------------

func TestPostMethodAndMatch(t *testing.T) {
	t.Parallel()

	p := NewPost()
	assert.Equal(t, "client_secret_post", p.Method())

	assert.False(t, p.Match(nil))

	withForm := postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s"}})
	assert.True(t, p.Match(withForm))

	// An Authorization header makes post yield to basic.
	withHeader := postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s"}})
	withHeader.Header.Set("Authorization", "Basic xyz")
	assert.False(t, p.Match(withHeader))

	assert.False(t, p.Match(postReq(url.Values{"client_id": {"c1"}})))
}

func TestPostAuthenticate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient()}}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		c, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s3cr3t"}}), store)
		require.NoError(t, err)
		assert.Equal(t, "c1", c.ID())
	})

	t.Run("missing credentials", func(t *testing.T) {
		t.Parallel()

		_, err := NewPost().Authenticate(ctx, postReq(url.Values{}), store)
		assertInvalidClient(t, err)
	})

	t.Run("unknown client", func(t *testing.T) {
		t.Parallel()

		_, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"ghost"}, "client_secret": {"x"}}), store)
		assertInvalidClient(t, err)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		down := errors.New("db down")
		_, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s3cr3t"}}), fakeStore{err: down})
		assertStoreFailure(t, err, down)

		_, err = NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s3cr3t"}}), fakeStore{err: oauth2.ErrInvalidClient})
		assertInvalidClient(t, err)
	})

	t.Run("method not allowed", func(t *testing.T) {
		t.Parallel()

		only := fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient("none")}}
		_, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s3cr3t"}}), only)
		assertInvalidClient(t, err)
	})

	t.Run("client cannot verify secret", func(t *testing.T) {
		t.Parallel()

		noMatcher := fakeStore{clients: map[string]oauth2.Client{
			"c1": noMatcherClient{id: "c1", typ: oauth2.ClientConfidential},
		}}
		_, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"s3cr3t"}}), noMatcher)
		assertInvalidClient(t, err)
	})

	t.Run("secret mismatch", func(t *testing.T) {
		t.Parallel()

		_, err := NewPost().Authenticate(ctx,
			postReq(url.Values{"client_id": {"c1"}, "client_secret": {"wrong"}}), store)
		assertInvalidClient(t, err)
	})
}

// --- secret-based methods ------------------------------------------------

// TestSecretMethodsRefuseMissingCredentials pins that client_secret_basic
// and client_secret_post refuse a missing client_id or an empty secret
// before the client store is consulted, with the same answer whatever the
// client: an empty secret is no credential, even for a client registered
// without one (#94).
func TestSecretMethodsRefuseMissingCredentials(t *testing.T) {
	t.Parallel()

	clients := map[string]oauth2.Client{
		"c1":        confidentialClient(),
		"no-secret": &oauth2.DefaultClient{IDValue: "no-secret", TypeValue: oauth2.ClientConfidential},
		"public":    &oauth2.DefaultClient{IDValue: "public", TypeValue: oauth2.ClientPublic},
	}

	methods := []struct {
		name string
		auth ClientAuthenticator
		req  func(id, secret string) *http.Request
	}{
		{
			name: "basic",
			auth: NewBasic(),
			req: func(id, secret string) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/", nil)
				r.Header.Set("Authorization", basicHeader(id, secret))

				return r
			},
		},
		{
			name: "post",
			auth: NewPost(),
			req: func(id, secret string) *http.Request {
				return postReq(url.Values{"client_id": {id}, "client_secret": {secret}})
			},
		},
	}

	cases := []struct {
		name       string
		id, secret string
	}{
		{"client with a secret", "c1", ""},
		{"confidential client without a secret", "no-secret", ""},
		{"public client without a secret", "public", ""},
		{"unknown client", "ghost", ""},
		{"empty client_id", "", "s3cr3t"},
		{"empty client_id and secret", "", ""},
	}

	for _, m := range methods {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				// A store per subtest, so that the count is this request's.
				store := &countingStore{fakeStore: fakeStore{clients: clients}}

				c, err := m.auth.Authenticate(context.Background(), m.req(tc.id, tc.secret), store)
				assert.Nil(t, c)
				assertInvalidClient(t, err)

				var oe *oauth2.Error
				require.ErrorAs(t, err, &oe)
				assert.Equal(t, "missing client_id or client_secret", oe.Description)
				assert.Zero(t, store.calls.Load(), "the client store must not be consulted")
			})
		}
	}
}

// --- none ----------------------------------------------------------------

func TestNoneMethodAndMatch(t *testing.T) {
	t.Parallel()

	n := NewNone()
	assert.Equal(t, "none", n.Method())

	assert.False(t, n.Match(nil))
	assert.True(t, n.Match(postReq(url.Values{"client_id": {"pub"}})))
	// A secret present means this is a post request, not none.
	assert.False(t, n.Match(postReq(url.Values{"client_id": {"pub"}, "client_secret": {"s"}})))
	// An Authorization header makes none yield.
	withHeader := postReq(url.Values{"client_id": {"pub"}})
	withHeader.Header.Set("Authorization", "Basic xyz")
	assert.False(t, n.Match(withHeader))
}

func TestNoneAuthenticate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	publicClient := &oauth2.DefaultClient{IDValue: "pub", TypeValue: oauth2.ClientPublic}
	store := fakeStore{clients: map[string]oauth2.Client{"pub": publicClient}}

	t.Run("success for a public client", func(t *testing.T) {
		t.Parallel()

		c, err := NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"pub"}}), store)
		require.NoError(t, err)
		assert.Equal(t, "pub", c.ID())
	})

	t.Run("missing client_id", func(t *testing.T) {
		t.Parallel()

		_, err := NewNone().Authenticate(ctx, postReq(url.Values{}), store)
		assertInvalidClient(t, err)
	})

	t.Run("unknown client", func(t *testing.T) {
		t.Parallel()

		_, err := NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"ghost"}}), store)
		assertInvalidClient(t, err)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		down := errors.New("db down")
		_, err := NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"pub"}}), fakeStore{err: down})
		assertStoreFailure(t, err, down)

		_, err = NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"pub"}}), fakeStore{err: oauth2.ErrInvalidClient})
		assertInvalidClient(t, err)
	})

	t.Run("confidential client refused", func(t *testing.T) {
		t.Parallel()

		conf := fakeStore{clients: map[string]oauth2.Client{
			"pub": &oauth2.DefaultClient{IDValue: "pub", TypeValue: oauth2.ClientConfidential},
		}}
		_, err := NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"pub"}}), conf)
		assertInvalidClient(t, err)
	})

	t.Run("method not allowed", func(t *testing.T) {
		t.Parallel()

		only := fakeStore{clients: map[string]oauth2.Client{
			"pub": &oauth2.DefaultClient{
				IDValue: "pub", TypeValue: oauth2.ClientPublic,
				AuthMethodValues: []string{"client_secret_basic"},
			},
		}}
		_, err := NewNone().Authenticate(ctx, postReq(url.Values{"client_id": {"pub"}}), only)
		assertInvalidClient(t, err)
	})
}

// assertStoreFailure asserts that a client store failure is returned as the
// failure it is — wrapping cause, never invalid_client: the server answers
// an outage, not a wrong credential.
func assertStoreFailure(t *testing.T, err, cause error) {
	t.Helper()

	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Empty(t, oauth2.IsCode(err), "not an OAuth2 error: the server answers server_error")
}
