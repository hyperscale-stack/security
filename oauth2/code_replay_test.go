// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/hyperscale-stack/security/oauth2/clientauth"
	"github.com/hyperscale-stack/security/oauth2/grant"
	"github.com/hyperscale-stack/security/oauth2/storage/memory"
	"github.com/hyperscale-stack/security/oauth2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The extra clients of the code-replay tests.
const (
	replayOtherClientID = "other-client"
	replayOtherSecret   = "other-secret"
	replaySecondSPAID   = "spa-2"
	// replayWrongVerifier is a well-formed code_verifier that does not
	// match pkceChallenge.
	replayWrongVerifier = "a-well-formed-verifier-that-does-not-match-the-challenge"
)

// newCodeReplayServer builds a BCP server over store serving
// authorization_code and rotating refresh_token. Its clients are client-abc
// and other-client (confidential, client_secret_basic) and two public
// SPAs ("none"), all registered with redirectURI; both error hooks report
// to sink.
func newCodeReplayServer(t *testing.T, store oauth2.Storage, sink *errorSink) *oauth2.Server {
	t.Helper()

	gcfg := grant.Config{
		Storage:       store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    24 * time.Hour,
		OnError:       sink.hook,
	}

	client := func(id, secret string, typ oauth2.ClientType) oauth2.Client {
		return &oauth2.DefaultClient{
			IDValue: id, Secret: secret, TypeValue: typ,
			RedirectURIValues: []string{redirectURI}, ScopeValues: []string{"read"},
		}
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile: oauth2.Profile20BCP,
		Storage: store,
		ClientStore: &staticClientStore{clients: map[string]oauth2.Client{
			testClientID:        client(testClientID, testClientSecret, oauth2.ClientConfidential),
			replayOtherClientID: client(replayOtherClientID, replayOtherSecret, oauth2.ClientConfidential),
			spaClientID:         client(spaClientID, "", oauth2.ClientPublic),
			replaySecondSPAID:   client(replaySecondSPAID, "", oauth2.ClientPublic),
		}},
		IssuerResolver: oauth2.StaticIssuer("https://auth.example", "api"),
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg), grant.NewRefreshToken(gcfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic(), clientauth.NewNone()},
		OnError:        sink.hook,
	})
	require.NoError(t, err)

	return srv
}

// issueCode runs /authorize for clientID — S256 PKCE with pkceChallenge —
// and returns the code it redirects with.
func issueCode(t *testing.T, srv *oauth2.Server, clientID string) string {
	t.Helper()

	q := authorizeQuery()
	q.Set("client_id", clientID)

	rec := runAuthorize(srv, q, approve)
	require.Equal(t, http.StatusFound, rec.Code)

	code := mustLocation(t, rec).Query().Get("code")
	require.NotEmpty(t, code)

	return code
}

// codeForm is the /token form redeeming code with verifier; an empty
// verifier is left out.
func codeForm(code, verifier string) url.Values {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}

	return form
}

// asPublicClient builds the /token request posting form as the public
// client id ("none": client_id only).
func asPublicClient(id string, form url.Values) *http.Request {
	form.Set("client_id", id)

	return formRequest("/oauth2/token", form, false)
}

// TestTokenEndpointCodeReplayRevokesIssuedTokens is the reproduction of
// issue #80: a code is exchanged, then replayed. The replay is refused
// with invalid_grant (RFC 6749 §4.1.2), and the tokens the first exchange
// issued are revoked — for /introspect, for the store, and for a refresh.
func TestTokenEndpointCodeReplayRevokesIssuedTokens(t *testing.T) {
	t.Parallel()

	store := memory.New()
	sink := &errorSink{}
	srv := newCodeReplayServer(t, store, sink)
	code := issueCode(t, srv, testClientID)

	issued := decodeTokens(t, exchangeCode(srv, code, pkceVerifier))
	require.Equal(t, true, introspect(t, srv, issued.AccessToken)["active"])

	rec := exchangeCode(srv, code, pkceVerifier)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	errCode, desc := tokenError(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "authorization code already consumed", desc)

	inactive := map[string]any{"active": false}
	assert.Equal(t, inactive, introspect(t, srv, issued.AccessToken), "access token")
	assert.Equal(t, inactive, introspect(t, srv, issued.RefreshToken), "refresh token")

	_, err := store.LookupAccessToken(t.Context(), oauth2.HashToken(nil, issued.AccessToken))
	require.ErrorIs(t, err, oauth2.ErrTokenFamilyRevoked)

	rec = refreshExchange(t, srv, issued.RefreshToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, rec))

	assert.NotContains(t, sink.codes(), oauth2.CodeServerError)
}

// TestTokenEndpointUnprovenCodeReplayRevokesNothing replays a public
// client's consumed code with requests that could not have redeemed it:
// each one gets the very answer of any replay — nothing tells which check
// failed — and the tokens stay active, until a replay with the code's
// client, redirect_uri and PKCE verifier revokes them. A public client_id
// is no secret; the verifier is the proof.
func TestTokenEndpointUnprovenCodeReplayRevokesNothing(t *testing.T) {
	t.Parallel()

	sink := &errorSink{}
	srv := newCodeReplayServer(t, memory.New(), sink)
	code := issueCode(t, srv, spaClientID)

	issued := decodeTokens(t, serve(srv.TokenHandler(), asPublicClient(spaClientID, codeForm(code, pkceVerifier))))

	cases := []struct {
		name string
		req  *http.Request
	}{
		{"another public client", asPublicClient(replaySecondSPAID, codeForm(code, pkceVerifier))},
		{"no code_verifier", asPublicClient(spaClientID, codeForm(code, ""))},
		{"a wrong code_verifier", asPublicClient(spaClientID, codeForm(code, replayWrongVerifier))},
		{"a confidential client", basicForm("/oauth2/token", codeForm(code, pkceVerifier), replayOtherClientID, replayOtherSecret)},
		{"an unknown code", asPublicClient(spaClientID, codeForm("never-issued", pkceVerifier))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(srv.TokenHandler(), tc.req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)

			errCode, desc := tokenError(t, rec)
			assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
			assert.Equal(t, "authorization code already consumed", desc, "the answer of any replay: no oracle")
			assert.Equal(t, true, introspect(t, srv, issued.AccessToken)["active"])
		})
	}

	rec := serve(srv.TokenHandler(), asPublicClient(spaClientID, codeForm(code, pkceVerifier)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, map[string]any{"active": false}, introspect(t, srv, issued.AccessToken))
	assert.NotContains(t, sink.codes(), oauth2.CodeServerError)
}

// codeRaceStore runs beforeSave once, right before the first token pair is
// persisted, and records the pairs it is given.
type codeRaceStore struct {
	*memory.Store

	beforeSave func()
	saved      []oauth2.TokenPair
}

func (s *codeRaceStore) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	s.saved = append(s.saved, *pair)

	if hook := s.beforeSave; hook != nil {
		s.beforeSave = nil
		hook()
	}

	return s.Store.SaveTokenPair(ctx, pair)
}

// TestTokenEndpointCodeExchangeLosingReplayRaceIsInvalidGrant serves a
// proven replay of a code while its first exchange sits between the
// consumption of the code and the issuance of its tokens: the replay
// revokes the code's family first, so the first exchange issues nothing
// and answers invalid_grant.
func TestTokenEndpointCodeExchangeLosingReplayRaceIsInvalidGrant(t *testing.T) {
	t.Parallel()

	store := &codeRaceStore{Store: memory.New()}
	sink := &errorSink{}
	srv := newCodeReplayServer(t, store, sink)
	code := issueCode(t, srv, testClientID)

	var replay *httptest.ResponseRecorder

	store.beforeSave = func() { replay = exchangeCode(srv, code, pkceVerifier) }

	rec := exchangeCode(srv, code, pkceVerifier)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	errCode, desc := tokenError(t, rec)
	assert.Equal(t, oauth2.CodeInvalidGrant, errCode)
	assert.Equal(t, "token family revoked", desc)
	assert.NotContains(t, rec.Body.String(), "access_token")

	require.NotNil(t, replay, "the replay ran")
	assert.Equal(t, http.StatusBadRequest, replay.Code)
	assert.Equal(t, oauth2.CodeInvalidGrant, decodeError(t, replay))

	assert.Equal(t, []string{oauth2.CodeInvalidGrant, oauth2.CodeInvalidGrant}, sink.codes())

	require.Len(t, store.saved, 1)
	require.NotNil(t, store.saved[0].Refresh)

	_, err := store.LookupAccessToken(t.Context(), store.saved[0].Access.TokenHash)
	require.Error(t, err)
	assert.NotErrorIs(t, err, oauth2.ErrTokenFamilyRevoked, "the access token was never persisted")

	_, err = store.LookupRefreshToken(t.Context(), store.saved[0].Refresh.TokenHash)
	require.Error(t, err, "the refresh token was never persisted")
}
