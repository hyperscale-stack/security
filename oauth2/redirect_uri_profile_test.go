// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2_test

import (
	"net/http"
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

// strictProfiles are the profiles that follow RFC 9700 — and an unknown
// value, which fails closed like them.
var strictProfiles = []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile21Draft, oauth2.Profile(9)}

// TestValidateRedirectURIProfileTransport pins RFC 9700 §2.6 — "authorization
// servers MUST NOT allow redirection URIs that use the http scheme except for
// native clients that use loopback interface redirection as described in
// Section 7.3 of [RFC8252]" — under Profile20BCP and Profile21Draft (OAuth 2.1
// §1.5, §8.4.2): an http redirect URI is the loopback IP literal
// http://127.0.0.1 or http://[::1], any valid port — never localhost (RFC
// 8252 §8.3), another loopback address or another spelling of these ones.
// Profile20 keeps RFC 6749 §3.1.2.1, where TLS is a SHOULD.
func TestValidateRedirectURIProfileTransport(t *testing.T) {
	t.Parallel()

	everywhere := []string{
		"https://app.example/cb",
		"https://10.0.0.5/cb",
		"http://127.0.0.1/cb",
		"http://127.0.0.1",
		"http://127.0.0.1:51004/cb",
		"http://127.0.0.1:65535/cb?x=1",
		"http://[::1]/cb",
		"http://[::1]:61023/oauth2redirect/example-provider",
		"com.example.app:/oauth2redirect/example-provider",
	}

	// Each is valid for Profile20: only the transport rule refuses it.
	plainHTTP := []string{
		"http://app.example/cb",
		"http://10.0.0.5:8080/cb",
		"http://192.168.1.10/cb",
		"http://localhost/cb",
		"http://localhost:1337/callback",
		"http://127.0.0.2/cb",
		"http://127.0.0.1.nip.io/cb",
		"http://[0:0:0:0:0:0:0:1]/cb",
		"http://[::ffff:127.0.0.1]/cb",
		"http://[::1%25lo0]/cb",
		"http://127.1/cb",
		"http://2130706433/cb",
		"http://0x7f000001/cb",
		"HTTP://127.0.0.1/cb",
		"http://127.0.0.1:/cb",
		"http://[::1]:/cb",
		"http://127.0.0.1:080/cb",
	}

	for _, uri := range everywhere {
		for _, p := range append([]oauth2.Profile{oauth2.Profile20}, strictProfiles...) {
			assert.NoError(t, oauth2.ValidateRedirectURI(p, uri), "%s under %s", uri, p)
		}
	}

	for _, uri := range plainHTTP {
		assert.NoError(t, oauth2.ValidateRedirectURI(oauth2.Profile20, uri), "%s under oauth2.0", uri)

		for _, p := range strictProfiles {
			err := oauth2.ValidateRedirectURI(p, uri)
			require.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI, "%s under %s", uri, p)
			assert.ErrorContains(t, err, "http outside a loopback IP literal", "%s under %s", uri, p)
		}
	}
}

// transportEnv is a server of profile p, over a counting store, reporting to
// sink, whose client "machine" registers uris.
type transportEnv struct {
	srv   *oauth2.Server
	store *writeCountingStore
	sink  *errorSink
}

func newTransportEnv(t *testing.T, p oauth2.Profile, uris ...string) *transportEnv {
	t.Helper()

	env := &transportEnv{store: &writeCountingStore{Store: memory.New()}, sink: &errorSink{}}
	client := confidentialClient([]string{oauth2.GrantTypeAuthorizationCode}, []string{"read"})
	client.RedirectURIValues = uris

	gcfg := grant.Config{
		Storage:       env.store,
		AccessTokens:  token.NewOpaque(32),
		RefreshTokens: token.OpaqueRefreshAdapter{Opaque: token.NewOpaque(32)},
		AccessTTL:     time.Hour,
		RefreshTTL:    time.Hour,
	}

	srv, err := oauth2.NewServer(oauth2.ServerConfig{
		Profile:        p,
		Storage:        env.store,
		ClientStore:    &staticClientStore{clients: map[string]oauth2.Client{"machine": client}},
		IssuerResolver: oauth2.StaticIssuer(testIssuer, "api"),
		Grants:         []oauth2.Grant{grant.NewAuthorizationCode(gcfg)},
		ClientAuth:     []oauth2.ClientAuthenticator{clientauth.NewBasic()},
		OnError:        env.sink.hook,
	})
	require.NoError(t, err)

	env.srv = srv

	return env
}

// authorize runs an approved GET /authorize of "machine" to requested
// (omitted when empty), and reports whether the ConsentFunc ran.
func (env *transportEnv) authorize(requested string) (int, string, bool) {
	q := machineQuery()
	q.Del("redirect_uri")

	if requested != "" {
		q.Set("redirect_uri", requested)
	}

	consented := false
	rec := runAuthorize(env.srv, q, func(w http.ResponseWriter, r *http.Request, ar *oauth2.AuthorizeRequest) (*oauth2.Consent, error) {
		consented = true

		return approve(w, r, ar)
	})

	return rec.Code, rec.Header().Get("Location"), consented
}

// TestAuthorizeRefusesPlainHTTPRedirectURIsUnderBCP pins RFC 9700 §2.6 at
// the authorization endpoint: under Profile20BCP and Profile21Draft, a
// registered http redirect URI that is no loopback IP literal is an invalid
// redirection URI — a bare 400, never redirected to (RFC 6749 §3.1.2.4) —
// whether the request names it or omits it as the client's sole one; the
// https URI of the same client still gets its code, and so does a loopback
// IP literal on any port (RFC 8252 §7.3). Profile20 still redirects to http.
func TestAuthorizeRefusesPlainHTTPRedirectURIsUnderBCP(t *testing.T) {
	t.Parallel()

	for _, p := range []oauth2.Profile{oauth2.Profile20BCP, oauth2.Profile21Draft} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			for _, uri := range []string{"http://app.example/cb", "http://localhost:1337/callback"} {
				env := newTransportEnv(t, p, "https://app.example/cb", uri)

				status, location, consented := env.authorize(uri)
				assert.Equal(t, http.StatusBadRequest, status, uri)
				assert.Empty(t, location, "never redirected")
				assert.False(t, consented, "the ConsentFunc never runs")
				assert.True(t, env.sink.matches(oauth2.ErrInvalidRedirectURI), "the cause reaches the hook")

				status, location, _ = env.authorize("https://app.example/cb")
				assert.Equal(t, http.StatusFound, status)
				assert.Contains(t, location, "code=")
				assert.Equal(t, int32(1), env.store.writes.Load(), "only the https request saved a code")

				sole := newTransportEnv(t, p, uri)
				status, location, consented = sole.authorize("")
				assert.Equal(t, http.StatusBadRequest, status, "the omitted redirect_uri of %s", uri)
				assert.Empty(t, location)
				assert.False(t, consented)
				assert.Zero(t, sole.store.writes.Load())
			}

			env := newTransportEnv(t, p, "http://127.0.0.1/cb")
			status, location, _ := env.authorize("http://127.0.0.1:51004/cb")
			assert.Equal(t, http.StatusFound, status)
			assert.Contains(t, location, "http://127.0.0.1:51004/cb?code=")
		})
	}

	env := newTransportEnv(t, oauth2.Profile20, "http://app.example/cb")
	status, location, _ := env.authorize("http://app.example/cb")
	assert.Equal(t, http.StatusFound, status)
	assert.Contains(t, location, "http://app.example/cb?code=")
}
