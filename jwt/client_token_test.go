// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtsec "github.com/hyperscale-stack/security/jwt"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStandardClaimsClientID pins RFC 8693 §4.3 and RFC 9068 §2.2: the
// client_id claim is read into StandardClaims.ClientID — and into a
// caller's claims type embedding StandardClaims — and written by a Signer.
func TestStandardClaimsClientID(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	claims := shortClaims()
	claims.ClientID = "web"

	tok, err := mustSigner(t, priv).Sign(context.Background(), claims)
	require.NoError(t, err)

	var out struct {
		jwtsec.StandardClaims

		Extra string `json:"extra"`
	}

	std, err := jwtsec.NewVerifier(jwtsec.NewStaticJWKS([]jwtsec.PublicKey{pub})).Verify(context.Background(), tok, &out)
	require.NoError(t, err)
	assert.Equal(t, "web", std.ClientID)
	assert.Equal(t, "web", out.ClientID)
}

// TestOAuth2AccessTokenSignerPayload pins the RFC 9068 §2.2 payload of the
// access-token signer: exactly iss, sub, aud, exp, iat, jti, scope and
// client_id — StandardClaims now carries client_id, the wire format is
// unchanged.
func TestOAuth2AccessTokenSignerPayload(t *testing.T) {
	t.Parallel()

	priv, _ := genECDSA(t)
	c := accessClaims()

	tok, err := mustAccessTokenSigner(t, priv).SignAccessToken(context.Background(), c)
	require.NoError(t, err)

	raw, err := b64.DecodeString(strings.Split(tok, ".")[1])
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))

	jti, _ := payload["jti"].(string)
	assert.Len(t, jti, 22, "a 128-bit base64url jti")
	assert.Equal(t, map[string]any{
		"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience, "client_id": c.ClientID, "scope": c.Scope,
		"iat": float64(c.IssuedAt.Unix()), "exp": float64(c.ExpiresAt.Unix()), "jti": jti,
	}, payload)
}

// TestBearerVerifierDistinguishesClientTokens pins RFC 9700 §4.15.1 (audit
// F-08): a client_credentials token, whose sub is its client_id (RFC 9068
// §2.2), and a user token with the same sub were indistinguishable at the
// resource server — same name, same authorities, no client_id anywhere.
// The principal now carries the client_id and SubjectIsClient tells them
// apart; the authority resolver sees ClientID too.
func TestBearerVerifierDistinguishesClientTokens(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	var seen []string

	tv := jwtsec.BearerVerifier(rsVerifier(pub), func(c *jwtsec.StandardClaims) []string {
		seen = append(seen, c.ClientID)

		return jwtsec.DefaultAuthorityResolver(c)
	})

	user := accessToken(t, priv, func(c *token.AccessTokenClaims) { c.Subject, c.ClientID = "u-42", "web" })
	// What grant.ClientCredentials mints for a client registered as "u-42".
	m2m := accessToken(t, priv, func(c *token.AccessTokenClaims) { c.Subject, c.ClientID = "u-42", "u-42" })

	a, err := tv.Verify(context.Background(), user)
	require.NoError(t, err)

	p, ok := a.Principal().(jwtsec.AccessTokenPrincipal)
	require.True(t, ok, "the principal is an AccessTokenPrincipal")
	assert.Equal(t, "u-42", p.Subject())
	assert.Equal(t, "web", p.ClientID())
	assert.False(t, p.SubjectIsClient(), "a user token")

	a, err = tv.Verify(context.Background(), m2m)
	require.NoError(t, err)

	p, ok = a.Principal().(jwtsec.AccessTokenPrincipal)
	require.True(t, ok)
	assert.Equal(t, "u-42", p.Subject())
	assert.Equal(t, "u-42", p.ClientID())
	assert.True(t, p.SubjectIsClient(), "a client_credentials token")

	assert.Equal(t, []string{"web", "u-42"}, seen, "the resolver sees client_id")
}

// TestBearerVerifierWithoutClientID: a token without client_id (another
// authorization server's, through WithAccessTokenType) is still accepted —
// RFC 9068 §4 does not make the resource server check it — and its subject
// is never taken for a client.
func TestBearerVerifierWithoutClientID(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)
	tok := forge(t, jwtsec.ES256, priv.Key, `{"alg":"ES256","kid":"ec-1","typ":"at+jwt"}`,
		fmt.Sprintf(`{"iss":%q,"sub":"svc","aud":%q,"exp":%d}`, rsIssuer, rsAudience, in(time.Hour)))

	a, err := jwtsec.BearerVerifier(rsVerifier(pub), nil).Verify(context.Background(), tok)
	require.NoError(t, err)

	p, ok := a.Principal().(jwtsec.AccessTokenPrincipal)
	require.True(t, ok)
	assert.Empty(t, p.ClientID())
	assert.False(t, p.SubjectIsClient())
}

// TestAccessTokenPrincipalZeroValue: the zero value designates no client.
func TestAccessTokenPrincipalZeroValue(t *testing.T) {
	t.Parallel()

	var p jwtsec.AccessTokenPrincipal

	assert.Empty(t, p.Subject())
	assert.Empty(t, p.ClientID())
	assert.False(t, p.SubjectIsClient())
}

// TestClientCredentialsTokenIsTheClient runs the authorization server and
// the resource server end to end: the client_credentials grant mints a JWT
// access token whose principal, at BearerVerifier, is its client.
func TestClientCredentialsTokenIsTheClient(t *testing.T) {
	t.Parallel()

	priv, pub := genECDSA(t)

	g := grant.NewClientCredentials(grant.Config{
		Storage:      memory.New(),
		AccessTokens: token.NewJWTAccessTokenGenerator(mustAccessTokenSigner(t, priv)),
		AccessTTL:    time.Hour,
	})

	client := &oauth2.DefaultClient{
		IDValue: "billing-svc", TypeValue: oauth2.ClientConfidential,
		GrantTypeValues: []string{oauth2.GrantTypeClientCredentials}, ScopeValues: []string{"read"},
	}

	resp, err := g.Handle(context.Background(), grant.Request{
		Client: client, Form: url.Values{"scope": {"read"}}, Issuer: rsIssuer, Audience: rsAudience, Now: time.Now(),
	})
	require.NoError(t, err)

	a, err := jwtsec.BearerVerifier(rsVerifier(pub), nil).Verify(context.Background(), resp.Pair.Access.Token)
	require.NoError(t, err)

	p, ok := a.Principal().(jwtsec.AccessTokenPrincipal)
	require.True(t, ok)
	assert.Equal(t, "billing-svc", p.ClientID())
	assert.True(t, p.SubjectIsClient())
	assert.Equal(t, []string{"scope:read"}, a.Authorities())
}
