// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	oidcclient "github.com/hyperscale-stack/security/oidc/client"
	"github.com/hyperscale-stack/security/outbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxErrorText bounds the text of every error below: provider-controlled
// values are cut to a few hundred bytes, after quoting.
const maxErrorText = 512

// longLocation answers with a redirect to a 60 KB Location.
func longLocation(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Location", "https://elsewhere.example/"+strings.Repeat("A", 60_000))
	w.WriteHeader(http.StatusFound)
}

// longContentType answers 200 with a content type of 30 KB of byte b.
func longContentType(b string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/"+strings.Repeat(b, 30_000))
		w.WriteHeader(http.StatusOK)
	}
}

// TestProviderTextInErrorsIsBounded checks that an error never carries
// provider-controlled text unbounded — an issuer, a media type, a Location,
// a JOSE header member, an endpoint's query — nor application input: each
// value is quoted, then cut, so control characters and invalid UTF-8
// cannot inflate it. The sentinels stay matchable.
func TestProviderTextInErrorsIsBounded(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		run  func(t *testing.T) error
		want []error
		head string // the beginning of the value, kept for diagnosis
	}{
		"metadata issuer": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadata["issuer"] = op.issuer + "/" + strings.Repeat("A", 900_000) })

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrIssuerMismatch},
			head: `got "https://127.0.0.1:`,
		},
		"metadata issuer of control characters": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadata["issuer"] = op.issuer + strings.Repeat("\x01", 2_000) })

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrIssuerMismatch},
		},
		"discovery redirect": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) {
					op.redirects = map[string]string{wellKnown: "https://elsewhere.example/" + strings.Repeat("A", 60_000)}
				})

				return newWithOP(t, op, maxRedirects(1))
			},
			want: []error{oidcclient.ErrDiscovery, outbound.ErrRedirectNotAllowed},
		},
		"discovery content type": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadataType = "text/" + strings.Repeat("x", 30_000) })

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrDiscovery},
			head: `unexpected content type "text/xxx`,
		},
		"discovery content type of obs-text": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadataType = "text/" + strings.Repeat("\xff", 30_000) })

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrDiscovery},
		},
		"JWK Set content type": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.jwksType = "text/" + strings.Repeat("x", 30_000) })
				_, err := op.login(t, op.client(t))

				return err
			},
			want: []error{oidcclient.ErrKeySet},
		},
		"endpoint URL": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.metadata["token_endpoint"] = "https://[::1/" + strings.Repeat("a", 2_000) })

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrInvalidMetadata},
		},
		"endpoint query name": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				name := strings.Repeat("n", 900)
				op.set(func(op *fakeOP) {
					op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?" + name + "=1&" + name + "=2"
				})

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrInvalidMetadata},
			head: `repeats "nnn`,
		},
		"endpoint query name of invalid UTF-8": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				name := strings.Repeat("%FF", 300)
				op.set(func(op *fakeOP) {
					op.metadata["authorization_endpoint"] = op.srv.URL + "/authorize?" + name + "=1&" + name + "=2"
				})

				return newWithOP(t, op)
			},
			want: []error{oidcclient.ErrInvalidMetadata},
		},
		"JOSE header member": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) {
					op.idTokenHook = func(*grant) string {
						b := base64.RawURLEncoding.EncodeToString
						header := `{"alg":"RS256","kid":` + strings.Repeat("9", 30_000) + `}`

						return b([]byte(header)) + "." + b([]byte(`{}`)) + "." + b([]byte("signature"))
					}
				})
				_, err := op.login(t, op.client(t))

				return err
			},
			want: []error{oidcclient.ErrIDTokenMalformed},
		},
		"token redirect": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.tokenHandler = longLocation })
				_, err := op.login(t, op.client(t, maxRedirects(5)))

				return err
			},
			want: []error{oidcclient.ErrTokenEndpoint, outbound.ErrRedirectNotAllowed},
			head: `Post "https://elsewhere.example/AAA`,
		},
		"token content type": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.tokenHandler = longContentType("x") })
				_, err := op.login(t, op.client(t))

				return err
			},
			want: []error{oidcclient.ErrInvalidTokenResponse},
		},
		"UserInfo redirect": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				op.set(func(op *fakeOP) { op.userinfo = longLocation })
				c, id := loggedIn(t, op)
				_, err := c.UserInfo(context.Background(), id)

				return err
			},
			want: []error{oidcclient.ErrUserInfo, outbound.ErrRedirectNotAllowed},
		},
		"discovery body read": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				issuer := goAwayServer(t, []byte(strings.Repeat("\xff", 16_000)))

				return newWithOP(t, op, func(c *oidcclient.Config) { c.Issuer = issuer })
			},
			want: []error{oidcclient.ErrDiscovery},
			head: "read body: ",
		},
		"token body read": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				endpoint := goAwayServer(t, []byte(strings.Repeat("\xff", 16_000)))
				op.set(func(op *fakeOP) { op.metadata["token_endpoint"] = endpoint + "/token" })
				_, err := op.login(t, op.client(t))

				return err
			},
			want: []error{oidcclient.ErrTokenEndpoint},
		},
		"UserInfo body read": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				endpoint := goAwayServer(t, []byte(strings.Repeat("\xff", 16_000)))
				op.set(func(op *fakeOP) { op.metadata["userinfo_endpoint"] = endpoint + "/userinfo" })
				c, id := loggedIn(t, op)
				_, err := c.UserInfo(context.Background(), id)

				return err
			},
			want: []error{oidcclient.ErrUserInfo},
		},
		"ExtraParams name": {
			run: func(t *testing.T) error {
				_, err := newFakeOP(t).client(t).Begin(context.Background(),
					oidcclient.AuthOptions{ExtraParams: map[string]string{strings.Repeat("\x01", 5_000): "x"}})

				return err
			},
			want: []error{oidcclient.ErrInvalidAuthRequest},
		},
		"callback response mode": {
			run: func(t *testing.T) error {
				op := newFakeOP(t)
				c := op.client(t)
				ar, code := op.begin(t, c, oidcclient.AuthOptions{})
				cb := callbackFor(ar, code)
				cb.Mode = oidcclient.ResponseMode(strings.Repeat("\x01", 5_000))
				_, err := c.Complete(context.Background(), cb)

				return err
			},
			want: []error{oidcclient.ErrInvalidCallback},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tc.run(t)
			for _, want := range tc.want {
				require.ErrorIs(t, err, want)
			}

			assert.LessOrEqual(t, len(err.Error()), maxErrorText, "error text: %.300s…", err.Error())
			assert.Contains(t, err.Error(), tc.head)
		})
	}
}

// TestConfigTextInErrorsIsBounded checks the same for the configuration
// values New echoes, which a tenant may supply.
func TestConfigTextInErrorsIsBounded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("\x01", 5_000)

	for name, mutate := range map[string]func(*oidcclient.Config){
		"scope":         func(c *oidcclient.Config) { c.Scopes = []string{long} },
		"auth method":   func(c *oidcclient.Config) { c.AuthMethod = oidcclient.AuthMethod(long) },
		"response mode": func(c *oidcclient.Config) { c.ResponseMode = oidcclient.ResponseMode(long) },
		"algorithm":     func(c *oidcclient.Config) { c.Algorithms = []oidcclient.Algorithm{oidcclient.Algorithm(long)} },
		"issuer URL":    func(c *oidcclient.Config) { c.Issuer = "https://[::1/" + strings.Repeat(`\"`, 1_000) },
		"redirect URL":  func(c *oidcclient.Config) { c.RedirectURL = "https://[::1/" + strings.Repeat(`\"`, 1_000) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := newWithOP(t, newFakeOP(t), mutate)
			require.ErrorIs(t, err, oidcclient.ErrInvalidConfig)
			assert.LessOrEqual(t, len(err.Error()), maxErrorText)
		})
	}
}
