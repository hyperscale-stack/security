// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hyperscale-stack/security"
	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
)

// ecdsaTwin returns the other valid form of an ES256 token's signature: s
// replaced by n − s (RFC 7518 §3.4 has no low-S rule).
func ecdsaTwin(t *testing.T, tok string) string {
	t.Helper()

	parts := strings.Split(tok, ".")
	sig, err := b64.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64)

	s := new(big.Int).SetBytes(sig[32:])
	out := append([]byte(nil), sig[:32]...)
	out = append(out, new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(make([]byte, 32))...)

	twin := parts[0] + "." + parts[1] + "." + b64.EncodeToString(out)
	require.NotEqual(t, tok, twin)

	return twin
}

// checkCall records the calls of an ActiveTokenCheck.
type checkCall struct {
	token   string
	claims  *jwtsec.StandardClaims
	request any // the requestKey value of the check's context
}

// requestKey marks the context of a Verify call.
type requestKey struct{}

// TestActiveTokenCheckRunsLast pins the D-03 contract: the check runs only
// for a token that passed every other verification — signature, typ, iss,
// aud, exp, sub — once, with the raw token, its claims and the request's
// context.
func TestActiveTokenCheckRunsLast(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	var calls []checkCall

	tv := jwtsec.BearerVerifier(rsVerifier(pub), nil, jwtsec.WithActiveTokenCheck(
		func(ctx context.Context, tok string, c *jwtsec.StandardClaims) error {
			calls = append(calls, checkCall{tok, c, ctx.Value(requestKey{})})

			return nil
		}))

	for name, tok := range map[string]string{
		"bad signature": accessToken(t, priv)[:40] + "A" + accessToken(t, priv)[41:],
		"expired": accessToken(t, priv, func(c *token.AccessTokenClaims) {
			c.IssuedAt, c.ExpiresAt = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		}),
		"other audience": accessToken(t, priv, func(c *token.AccessTokenClaims) { c.Audience = "https://other.example" }),
		"empty sub":      forgeAccess(t, priv, `"sub":""`),
	} {
		_, err := tv.Verify(context.Background(), tok)
		require.Error(t, err, name)
	}

	require.Empty(t, calls, "never called for a token refused before")

	tok := accessToken(t, priv)

	a, err := tv.Verify(context.WithValue(context.Background(), requestKey{}, "req-1"), tok)
	require.NoError(t, err)
	assert.True(t, a.IsAuthenticated())

	require.Len(t, calls, 1)
	assert.Equal(t, "req-1", calls[0].request, "the check runs in the request's context")
	assert.Equal(t, tok, calls[0].token)
	assert.Equal(t, "alice", calls[0].claims.Subject)
	assert.Equal(t, "web", calls[0].claims.ClientID)
	assert.NotEmpty(t, calls[0].claims.JWTID)
}

// TestActiveTokenCheckErrors pins the error mapping (user decision C2/D-03):
// a refusal is ErrTokenInactive — security.ErrInvalidCredentials, 401
// invalid_token; a check that could not be made — an error wrapping
// security.ErrUnavailable, or the context ending — is security.ErrUnavailable
// (503) and never a credential failure. The token never appears in the
// error.
func TestActiveTokenCheckErrors(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	tok := accessToken(t, priv)

	cases := map[string]struct {
		err   error
		class string
	}{
		"inactive":          {errors.New("not found in the store"), security.ErrorClassInvalidCredentials},
		"store down":        {fmt.Errorf("lookup: %w", security.ErrUnavailable), security.ErrorClassUnavailable},
		"context canceled":  {fmt.Errorf("lookup: %w", context.Canceled), security.ErrorClassUnavailable},
		"deadline exceeded": {fmt.Errorf("lookup: %w", context.DeadlineExceeded), security.ErrorClassUnavailable},
	}

	for name, tc := range cases {
		tv := jwtsec.BearerVerifier(rsVerifier(pub), nil, jwtsec.WithActiveTokenCheck(
			func(context.Context, string, *jwtsec.StandardClaims) error { return tc.err }))

		a, err := tv.Verify(context.Background(), tok)
		require.Error(t, err, name)
		assert.Nil(t, a, name)
		require.ErrorIs(t, err, tc.err, name)
		assert.Equal(t, tc.class, security.ErrorClass(err), name)
		assert.NotContains(t, err.Error(), tok, name)

		if tc.class == security.ErrorClassUnavailable {
			require.ErrorIs(t, err, security.ErrUnavailable, name)
			assert.NotErrorIs(t, err, security.ErrInvalidCredentials, name)
			assert.NotErrorIs(t, err, jwtsec.ErrTokenInactive, name)
		} else {
			require.ErrorIs(t, err, jwtsec.ErrTokenInactive, name)
			require.ErrorIs(t, err, security.ErrInvalidCredentials, name)
			assert.NotErrorIs(t, err, security.ErrUnavailable, name)
		}
	}
}

// TestWithActiveTokenCheckRefusesNil: a nil check panics at construction.
func TestWithActiveTokenCheckRefusesNil(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "jwtsec.WithActiveTokenCheck: nil check", func() { jwtsec.WithActiveTokenCheck(nil) })
}

// TestActiveTokenCheckSpan (review nit 14): the check runs in its own span,
// which records the error class only — never the error text, which may
// carry the check's input. Not parallel: it installs the recording tracer
// provider.
func TestActiveTokenCheckSpan(t *testing.T) {
	priv, pub := genECDSA(t)
	tok := accessToken(t, priv)

	for _, tc := range []struct {
		err    error
		status codes.Code
		desc   string
	}{
		{nil, codes.Unset, ""},
		{errors.New("secret detail"), codes.Error, security.ErrorClassInvalidCredentials},
		{security.ErrUnavailable, codes.Error, security.ErrorClassUnavailable},
	} {
		tv := jwtsec.BearerVerifier(rsVerifier(pub), nil, jwtsec.WithActiveTokenCheck(
			func(context.Context, string, *jwtsec.StandardClaims) error { return tc.err }))

		spans := named(record(func() { _, _ = tv.Verify(context.Background(), tok) }), "jwtsec.BearerVerifier.ActiveTokenCheck")
		require.Len(t, spans, 1)
		assert.Equal(t, tc.status, spans[0].status)
		assert.Equal(t, tc.desc, spans[0].desc)
		assert.Equal(t, tc.desc, spans[0].attr(security.AttrErrorType))
		assert.Empty(t, spans[0].errs, "no error text recorded")
	}
}

// storeCheck is the documented recipe for a resource server sharing the
// authorization server's store: the token is active only when the store
// finds it — never a deny-list on the token string.
func storeCheck(store oauth2.AccessTokenStore) jwtsec.ActiveTokenCheck {
	return func(ctx context.Context, tok string, _ *jwtsec.StandardClaims) error {
		at, err := store.LookupAccessToken(ctx, oauth2.HashToken(nil, tok))

		switch {
		case oauth2.IsCode(err) == oauth2.CodeInvalidGrant, err == nil && at == nil:
			return errors.New("access token not active in the store")
		case err != nil:
			return fmt.Errorf("access token lookup: %w: %w", security.ErrUnavailable, err)
		default:
			return nil
		}
	}
}

// TestActiveTokenCheckAgainstTheStore runs the recipe end to end: a JWT
// access token stays usable while its record is active, is refused once
// revoked, and the ECDSA twin of an active token — the same claims under
// another valid signature — is refused, the store knowing only the string
// it issued.
func TestActiveTokenCheckAgainstTheStore(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	store := memory.New()

	g := grant.NewClientCredentials(grant.Config{
		Storage:      store,
		AccessTokens: token.NewJWTAccessTokenGenerator(mustAccessTokenSigner(t, priv)),
		AccessTTL:    time.Hour,
	})

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: &oauth2.DefaultClient{
			IDValue: "billing-svc", TypeValue: oauth2.ClientConfidential,
			GrantTypeValues: []string{oauth2.GrantTypeClientCredentials}, ScopeValues: []string{"read"},
		},
		Form: url.Values{"scope": {"read"}}, Issuer: rsIssuer, Audience: rsAudience, Now: time.Now(),
	})
	require.NoError(t, err)

	tok := resp.Pair.Access.Token
	tv := jwtsec.BearerVerifier(rsVerifier(pub), nil, jwtsec.WithActiveTokenCheck(storeCheck(store)))

	_, err = tv.Verify(context.Background(), tok)
	require.NoError(t, err, "active")

	_, err = jwtsec.BearerVerifier(rsVerifier(pub), nil).Verify(context.Background(), ecdsaTwin(t, tok))
	require.NoError(t, err, "the twin verifies offline (D-15)")

	_, err = tv.Verify(context.Background(), ecdsaTwin(t, tok))
	require.ErrorIs(t, err, jwtsec.ErrTokenInactive, "the store does not know the twin")

	require.NoError(t, store.RevokeAccessToken(context.Background(), oauth2.HashToken(nil, tok)))

	_, err = tv.Verify(context.Background(), tok)
	require.ErrorIs(t, err, jwtsec.ErrTokenInactive, "revoked")
	assert.Equal(t, security.ErrorClassInvalidCredentials, security.ErrorClass(err))
}
