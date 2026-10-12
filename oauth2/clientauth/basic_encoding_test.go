// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package clientauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodedBasicHeader builds the Authorization header RFC 6749 §2.3.1
// prescribes: client_id and client_secret are each encoded with the
// application/x-www-form-urlencoded algorithm (Appendix B) before they
// become the Basic user-id and password (RFC 7617).
func encodedBasicHeader(id, secret string) string {
	return basicHeader(url.QueryEscape(id), url.QueryEscape(secret))
}

func basicRequest(header string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	r.Header.Set("Authorization", header)

	return r
}

// TestBasicDecodesFormURLEncodedCredentials pins RFC 6749 §2.3.1: the
// server form-decodes the Basic user-id and password, so a client_id or
// client_secret holding reserved or non-ASCII characters authenticates.
func TestBasicDecodesFormURLEncodedCredentials(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, id, secret string
	}{
		{"percent", "c1", "50%off"},
		{"plus", "c1", "a+b"},
		{"colon in the secret", "c1", "pa:ss:word"},
		{"colon in the client_id", "urn:client:1", "s3cr3t"},
		{"space", "my client", "pass word"},
		{"slash equals and question mark", "c1", "a/b=c?d&e"},
		{"non-ASCII", "clïent", "sécret-🔑"},
		{"every reserved character", "id:+%/= &?", "%+:/=&? \"'<>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := &oauth2.DefaultClient{IDValue: tc.id, Secret: tc.secret, TypeValue: oauth2.ClientConfidential}
			store := fakeStore{clients: map[string]oauth2.Client{tc.id: client}}

			got, err := NewBasic().Authenticate(context.Background(), basicRequest(encodedBasicHeader(tc.id, tc.secret)), store)
			require.NoError(t, err)
			assert.Equal(t, tc.id, got.ID())
		})
	}
}

// TestBasicFormDecodingTellsPlusFromSpace pins Appendix B: "+" is an
// encoded space, "%2B" an encoded plus. A client sending its secret
// unencoded is answered invalid_client when the secret holds "+".
func TestBasicFormDecodingTellsPlusFromSpace(t *testing.T) {
	t.Parallel()

	withSpace := &oauth2.DefaultClient{IDValue: "space", Secret: "a b", TypeValue: oauth2.ClientConfidential}
	withPlus := &oauth2.DefaultClient{IDValue: "plus", Secret: "a+b", TypeValue: oauth2.ClientConfidential}
	store := fakeStore{clients: map[string]oauth2.Client{"space": withSpace, "plus": withPlus}}

	cases := []struct {
		name   string
		header string
		ok     bool
	}{
		{"encoded space", basicHeader("space", "a+b"), true},
		{"encoded plus", basicHeader("plus", "a%2Bb"), true},
		{"unencoded plus reads as a space", basicHeader("plus", "a+b"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewBasic().Authenticate(context.Background(), basicRequest(tc.header), store)
			if tc.ok {
				require.NoError(t, err)
				assert.NotNil(t, got)

				return
			}

			assert.Nil(t, got)
			assertInvalidClient(t, err)
		})
	}
}

// TestBasicRefusesMalformedEncoding pins that a user-id or password that is
// not valid application/x-www-form-urlencoded is a malformed header,
// refused before the client store is consulted.
func TestBasicRefusesMalformedEncoding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, id, secret string
	}{
		{"bad escape in the secret", "c1", "50%zz"},
		{"truncated escape in the secret", "c1", "abc%4"},
		{"lone percent in the secret", "c1", "%"},
		{"bad escape in the client_id", "c%G1", "s3cr3t"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &countingStore{fakeStore: fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient()}}}

			got, err := NewBasic().Authenticate(context.Background(), basicRequest(basicHeader(tc.id, tc.secret)), store)
			assert.Nil(t, got)
			assertInvalidClient(t, err)

			var oe *oauth2.Error
			require.ErrorAs(t, err, &oe)
			assert.Equal(t, "malformed Basic Authorization header", oe.Description)
			assert.Zero(t, store.calls.Load(), "the client store must not be consulted")
		})
	}
}

// TestBasicSplitsBeforeDecoding pins that the user-id ends at the first
// colon of the decoded Basic credentials: an encoded colon ("%3A") belongs
// to the client_id, a literal one separates it from the secret.
func TestBasicSplitsBeforeDecoding(t *testing.T) {
	t.Parallel()

	raw := "a%3Ab:c%3Ad"
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))

	id, secret, ok := decodeBasic(header)
	require.True(t, ok)
	assert.Equal(t, "a:b", id)
	assert.Equal(t, "c:d", secret)
}

// TestBasicEmptyCredentialGuardOnDecodedValues pins that the #94 guard
// judges the decoded values: an encoded client_id or secret is never empty
// once decoded unless it was empty on the wire.
func TestBasicEmptyCredentialGuardOnDecodedValues(t *testing.T) {
	t.Parallel()

	store := &countingStore{fakeStore: fakeStore{clients: map[string]oauth2.Client{"c1": confidentialClient()}}}

	for _, header := range []string{
		encodedBasicHeader("c1", ""),
		encodedBasicHeader("", "s3cr3t"),
	} {
		got, err := NewBasic().Authenticate(context.Background(), basicRequest(header), store)
		assert.Nil(t, got)
		assertInvalidClient(t, err)

		var oe *oauth2.Error
		require.ErrorAs(t, err, &oe)
		assert.Equal(t, "missing client_id or client_secret", oe.Description)
	}

	assert.Zero(t, store.calls.Load(), "the client store must not be consulted")

	// A secret made of one encoded space is not empty once decoded: it
	// reaches the secret comparison (and fails it).
	got, err := NewBasic().Authenticate(context.Background(), basicRequest(basicHeader("c1", "+")), store)
	assert.Nil(t, got)
	assertInvalidClient(t, err)
	assert.Equal(t, int32(1), store.calls.Load())
}
