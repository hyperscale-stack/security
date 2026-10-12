// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnection_Validate(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name   string
		mutate func(*samlsp.Connection)
	}{
		{"empty ID", func(c *samlsp.Connection) { c.ID = "" }},
		{"ID with space", func(c *samlsp.Connection) { c.ID = "a b" }},
		{"ID with non-ASCII", func(c *samlsp.Connection) { c.ID = "acmé" }},
		{"ID too long", func(c *samlsp.Connection) { c.ID = strings.Repeat("a", 257) }},
		{"empty SP entity ID", func(c *samlsp.Connection) { c.SPEntityID = "" }},
		{"relative SP entity ID", func(c *samlsp.Connection) { c.SPEntityID = "sp.example.com" }},
		{"SP entity ID with space", func(c *samlsp.Connection) { c.SPEntityID = "https://sp.example.com/a b" }},
		{"SP entity ID too long", func(c *samlsp.Connection) { c.SPEntityID = "urn:" + strings.Repeat("x", 1021) }},
		{"ACS over plain http", func(c *samlsp.Connection) { c.ACSURL = "http://sp.example.com/acs" }},
		{"ACS relative", func(c *samlsp.Connection) { c.ACSURL = "/acs" }},
		{"ACS with query", func(c *samlsp.Connection) { c.ACSURL = acsURL + "?x=1" }},
		{"ACS with empty query", func(c *samlsp.Connection) { c.ACSURL = acsURL + "?" }},
		{"ACS with fragment", func(c *samlsp.Connection) { c.ACSURL = acsURL + "#f" }},
		{"ACS with empty fragment", func(c *samlsp.Connection) { c.ACSURL = acsURL + "#" }},
		{"ACS with user info", func(c *samlsp.Connection) { c.ACSURL = "https://u:p@sp.example.com/acs" }},
		{"ACS without path", func(c *samlsp.Connection) { c.ACSURL = "https://sp.example.com" }},
		{"ACS other scheme", func(c *samlsp.Connection) { c.ACSURL = "ftp://sp.example.com/acs" }},
		{"ACS with space", func(c *samlsp.Connection) { c.ACSURL = "https://sp.example.com/a cs" }},
		{"ACS empty", func(c *samlsp.Connection) { c.ACSURL = "" }},
		{"ACS too long", func(c *samlsp.Connection) { c.ACSURL = "https://sp.example.com/" + strings.Repeat("a", 2048) }},
		{"ACS unparsable", func(c *samlsp.Connection) { c.ACSURL = "https://[::1/acs" }},
		{"bad NameID format", func(c *samlsp.Connection) { c.NameIDFormat = "persistent" }},
		{"empty IdP entity ID", func(c *samlsp.Connection) { c.IdentityProvider.EntityID = "" }},
		{"SSO over plain http", func(c *samlsp.Connection) { c.IdentityProvider.SSOURL = "http://idp.example.com/sso" }},
		{"SSO with SAMLRequest", func(c *samlsp.Connection) {
			c.IdentityProvider.SSOURL = "https://idp.example.com/sso?SAMLRequest=x"
		}},
		{"http on a host ending in localhost", func(c *samlsp.Connection) {
			c.IdentityProvider.SSOURL = "http://evillocalhost/sso"
		}},
		{"SSO with RelayState", func(c *samlsp.Connection) {
			c.IdentityProvider.SSOURL = "https://idp.example.com/sso?RelayState=x"
		}},
		{"SSO with Signature", func(c *samlsp.Connection) {
			c.IdentityProvider.SSOURL = "https://idp.example.com/sso?Signature=x"
		}},
		{"SSO with bad query", func(c *samlsp.Connection) {
			c.IdentityProvider.SSOURL = "https://idp.example.com/sso?a=%zz"
		}},
		{"negative cache duration", func(c *samlsp.Connection) { c.IdentityProvider.CacheDuration = -time.Second }},
		{"no signing certificate", func(c *samlsp.Connection) { c.IdentityProvider.SigningCertificates = nil }},
		{"nil signing certificate", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{nil}
		}},
		{"weak RSA key", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{k.weakRSA.cert}
		}},
		{"unsupported curve", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{p224Cert(t)}
		}},
		{"unsupported key type", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{ed25519Cert(t)}
		}},
		{"duplicate certificates", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{k.idpA.cert, k.idpA.cert}
		}},
		{"too many certificates", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{
				k.idpA.cert, k.idpB.cert, k.attacker.cert, k.sp.cert, k.spNext.cert,
				k.idpEC.cert, k.expired.cert, newRSAPair(2048, "x", t0, t0.Add(time.Hour)).cert,
				newRSAPair(2048, "y", t0, t0.Add(time.Hour)).cert,
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newConnection(t)
			tc.mutate(c)

			require.ErrorIs(t, c.Validate(), samlsp.ErrInvalidConnection)
		})
	}

	var nilConn *samlsp.Connection
	require.ErrorIs(t, nilConn.Validate(), samlsp.ErrInvalidConnection)

	var nilIdP *samlsp.IdentityProvider
	require.ErrorIs(t, nilIdP.Validate(), samlsp.ErrInvalidConnection)
}

func TestConnection_ValidateAccepts(t *testing.T) {
	t.Parallel()

	k := keys(t)

	cases := []struct {
		name   string
		mutate func(*samlsp.Connection)
	}{
		{"defaults", func(*samlsp.Connection) {}},
		{"URN entity IDs", func(c *samlsp.Connection) {
			c.SPEntityID = "urn:example:sp"
			c.IdentityProvider.EntityID = "urn:example:idp"
		}},
		{"loopback http endpoints", func(c *samlsp.Connection) {
			c.ACSURL = "http://localhost:8080/saml/acme/acs"
			c.IdentityProvider.SSOURL = "http://127.0.0.1:9000/sso"
		}},
		{"IPv6 loopback", func(c *samlsp.Connection) { c.ACSURL = "http://[::1]:8080/acs" }},
		{"ECDSA and RSA rollover keys", func(c *samlsp.Connection) {
			c.IdentityProvider.SigningCertificates = []*x509.Certificate{k.idpA.cert, k.idpB.cert, k.idpEC.cert}
		}},
		{"NameID format", func(c *samlsp.Connection) { c.NameIDFormat = samlsp.NameIDFormatPersistent }},
		{"SHA-1 opt-in", func(c *samlsp.Connection) { c.InsecureAllowSHA1 = true }},
		{"ID of 256 characters", func(c *samlsp.Connection) { c.ID = strings.Repeat("a", 256) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := newConnection(t)
			tc.mutate(c)

			require.NoError(t, c.Validate())
		})
	}
}

func TestConnectionResolverFunc(t *testing.T) {
	t.Parallel()

	want := newConnection(t)
	f := samlsp.ConnectionResolverFunc(func(_ context.Context, id string) (*samlsp.Connection, error) {
		if id == connID {
			return want, nil
		}

		return nil, samlsp.ErrUnknownConnection
	})

	got, err := f.ResolveConnection(context.Background(), connID)
	require.NoError(t, err)
	assert.Same(t, want, got)

	_, err = f.ResolveConnection(context.Background(), "other")
	require.ErrorIs(t, err, samlsp.ErrUnknownConnection)
}

func TestResolution_FailsClosed(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	ctx := context.Background()

	// Unknown and malformed connection IDs.
	_, err := e.sp.Metadata(ctx, "nope")
	require.ErrorIs(t, err, samlsp.ErrUnknownConnection)

	_, err = e.sp.Metadata(ctx, "bad id")
	require.ErrorIs(t, err, samlsp.ErrUnknownConnection)

	// A resolver answering with another connection.
	other := newConnection(t)
	other.ID = "other"
	e.resolver.conns[connID] = other

	_, err = e.sp.Metadata(ctx, connID)
	require.ErrorIs(t, err, samlsp.ErrInvalidConnection)

	// A resolver answering with an invalid connection.
	invalid := newConnection(t)
	invalid.ACSURL = "http://insecure.example.com/acs"
	e.resolver.set(invalid)

	_, err = e.sp.Metadata(ctx, connID)
	require.ErrorIs(t, err, samlsp.ErrInvalidConnection)

	// A resolver failure is not an unknown connection.
	boom := errors.New("database down")
	e.resolver.err = boom

	_, err = e.sp.Metadata(ctx, connID)
	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, samlsp.ErrUnknownConnection)
	require.NotErrorIs(t, err, samlsp.ErrRejected)
}

// nilResolver answers nil without error.
type nilResolver struct{}

func (nilResolver) ResolveConnection(context.Context, string) (*samlsp.Connection, error) {
	return nil, nil //nolint:nilnil // test double for a misbehaving resolver
}

func TestResolution_NilConnection(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Connections = nilResolver{}

	sp, err := samlsp.New(cfg)
	require.NoError(t, err)

	_, err = sp.Metadata(context.Background(), connID)
	require.ErrorIs(t, err, samlsp.ErrUnknownConnection)
}

func p224Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	return selfSigned(k, "p224", t0.Add(-time.Hour), t0.Add(time.Hour))
}

func ed25519Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return selfSigned(k, "ed25519", t0.Add(-time.Hour), t0.Add(time.Hour))
}
