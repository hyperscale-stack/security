// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic_test

import (
	"context"
	"encoding/base64"
	"runtime"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/basic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// basicHeader encodes user-pass the way RFC 7617 §2 does.
func basicHeader(userPass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userPass))
}

// Audit CORE-11 (probe TestZZAuditBasicControlChars): the extractor forwarded
// NUL, CR LF, ESC sequences and invalid UTF-8 to the UserLoader — log
// injection into the application — and decoded base64 with embedded CR LF.
// RFC 7617 §2: "The user-id and password MUST NOT contain any control
// characters"; §2.1 and RFC 8264 §4.2.3/§4.3.3/§9.12 (UTF-8, no Controls).
func TestExtractorRefusesMalformedCredentials(t *testing.T) {
	t.Parallel()

	enc := base64.StdEncoding.EncodeToString([]byte("alice:alice-secret"))

	cases := map[string]string{
		"NUL in the user-id":               basicHeader("al\x00ice:pw"),
		"CR LF in the user-id":             basicHeader("alice\r\nX-Injected: 1:pw"),
		"ESC sequence in the user-id":      basicHeader("\x1b[31mred\x1b[0m:pw"),
		"DEL in the password":              basicHeader("alice:p\x7fw"),
		"C1 control (NEL) in the password": basicHeader("alice:p\u0085w"),
		"invalid UTF-8 in the user-id":     basicHeader("\xff\xfe:pw"),
		"invalid UTF-8 in the password":    basicHeader("alice:\xc3("),
		"CR LF inside the base64":          "Basic " + enc[:4] + "\r\n" + enc[4:],
		"space inside the base64":          "Basic " + enc[:4] + " " + enc[4:],
		"unpadded base64":                  "Basic " + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("alice:pw")), "="),
		"non-canonical padding bits":       "Basic YTpiYx==", // lenient decoding: "a:bc"
		"base64url alphabet":               "Basic " + base64.URLEncoding.EncodeToString([]byte("alice:p?>?w")),
		"credentials over 4096 bytes":      "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+strings.Repeat("p", 3200))),
		"scheme without credentials":       "Basic",
		"empty credentials":                "Basic ",
		"missing colon":                    basicHeader("alicepassword"),
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := newCarrier()
			c.Set("Authorization", header)

			got, err := basic.NewExtractor().Extract(context.Background(), c)

			require.ErrorIs(t, err, basic.ErrBadFormat)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.Nil(t, got)
			assert.NotContains(t, err.Error(), "alice", "the error never echoes the credentials")
		})
	}
}

func TestExtractorAcceptsRFC7617Credentials(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, header, user, password string
	}{
		{"RFC 7617 §2 example", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "Aladdin", "open sesame"},
		{"UTF-8 user-id and password", basicHeader("józef:hasło żółć"), "józef", "hasło żółć"},
		{"colons, spaces and emoji in the password", basicHeader("alice:p a:s😀s"), "alice", "p a:s😀s"},
		{"empty password", basicHeader("alice:"), "alice", ""},
		{"empty user-id (API key as password)", basicHeader(":KEY-123"), "", "KEY-123"},
		{"several spaces after the scheme", "Basic    " + base64.StdEncoding.EncodeToString([]byte("bob:pw")), "bob", "pw"},
		{"scheme in another case", "bASIC " + base64.StdEncoding.EncodeToString([]byte("bob:pw")), "bob", "pw"},
		{"3072-byte user-pass", basicHeader("u:" + strings.Repeat("p", 3070)), "u", strings.Repeat("p", 3070)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			carrier := newCarrier()
			carrier.Set("Authorization", c.header)

			got, err := basic.NewExtractor().Extract(context.Background(), carrier)
			require.NoError(t, err)
			require.NotNil(t, got)

			ba, ok := got.(basic.Authentication)
			require.True(t, ok)
			assert.Equal(t, c.user, ba.Username())
			assert.Equal(t, c.password, ba.Password())
		})
	}
}

// A header of another scheme, even one starting with "Basic", is left to
// the other extractors.
func TestExtractorLeavesOtherSchemes(t *testing.T) {
	t.Parallel()

	for _, header := range []string{"Bearer abc", "BasicAuth abc", "Basicx", "Digest username=\"a\""} {
		c := newCarrier()
		c.Set("Authorization", header)

		got, err := basic.NewExtractor().Extract(context.Background(), c)
		require.NoError(t, err, header)
		assert.Nil(t, got, header)
	}
}

// Review finding 3: form logins (and the OAuth2 password grant) build the
// Authentication with basic.New from their own fields, bypassing the
// Extractor. The Authenticator applies the same rules before any lookup —
// and, the PasswordUser flow needing an account, refuses an empty user-id
// (RFC 8265 §3.1; the Extractor lets it through for custom authenticators
// such as API keys sent as `-u :KEY`). Malformed input is refused without a
// verification: an input property, not an account property.
func TestAuthenticatorRefusesMalformedCredentialsBeforeTheLoader(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]basic.Authentication{
		"NUL in the user-id":         basic.New("al\x00ice", "pw"),
		"CR LF in the user-id":       basic.New("a\r\nb", "pw"),
		"invalid UTF-8 user-id":      basic.New("\xff", "pw"),
		"control in the password":    basic.New("alice", "p\x1bw"),
		"invalid UTF-8 password":     basic.New("alice", "\xc3("),
		"empty user-id":              basic.New("", "pw"),
		"user-pass over 3072 bytes":  basic.New("alice", strings.Repeat("p", 3067)),
		"user-pass over 3072 (user)": basic.New(strings.Repeat("u", 3072), ""),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l := basic.NewMockUserLoader(t) // no expectation: the loader never sees malformed credentials
			h := &recordingHasher{always: true}
			a := basic.NewAuthenticator(l, h)

			out, err := a.Authenticate(context.Background(), in)

			require.ErrorIs(t, err, basic.ErrBadFormat)
			require.ErrorIs(t, err, security.ErrInvalidCredentials)
			assert.False(t, out.IsAuthenticated())
			assert.Empty(t, h.calls(), "nor does the hasher")
		})
	}
}

// The longest accepted user-pass is 3072 bytes, what 4096 base64 characters
// decode to.
func TestAuthenticatorAcceptsTheLongestUserPass(t *testing.T) {
	t.Parallel()

	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "alice").Return(mockUser(t, account{subject: "alice", hash: "h"}), nil).Once()
	a := basic.NewAuthenticator(l, &recordingHasher{always: true})

	out, err := a.Authenticate(context.Background(), basic.New("alice", strings.Repeat("p", 3066)))

	require.NoError(t, err)
	assert.True(t, out.IsAuthenticated())
}

// Audit CORE-11 (probe TestZZAuditBasicNameIsTypedUsername): Name() returned
// the typed user-id ("ALICE") instead of the authenticated subject
// ("alice"). Before authentication Name() is the scheme label: the typed
// user-id may be a password typed in the wrong field and Name MUST be safe
// to log.
func TestAuthenticationNameIsTheSubjectOnceAuthenticated(t *testing.T) {
	t.Parallel()

	// The loader finds users whatever the case of the typed user-id — the
	// usual e-mail lookup.
	l := basic.NewMockUserLoader(t)
	l.EXPECT().LoadByUsername(mock.Anything, "ALICE").Return(mockUser(t, account{subject: "alice", hash: "h"}), nil).Once()
	a := basic.NewAuthenticator(l, &recordingHasher{always: true})

	in := basic.New("ALICE", "pw")
	assert.Equal(t, "basic", in.Name())
	assert.Equal(t, "ALICE", in.Username(), "Username keeps the typed user-id")

	out, err := a.Authenticate(context.Background(), in)
	require.NoError(t, err)

	assert.Equal(t, "alice", out.Name())
	assert.Equal(t, "alice", out.Principal().Subject())
}

// FuzzExtractor: whatever the header, the extractor never returns both a
// value and an error, never an authenticated value, and only accepts Basic
// credentials whose user-id and password are UTF-8 without control
// characters.
func FuzzExtractor(f *testing.F) {
	f.Add("Basic YWxpY2U6c2VjcmV0")
	f.Add("basic Og==")
	f.Add("Basic ")
	f.Add("Basic YR==")
	f.Add("Bearer abc")
	f.Add(basicHeader("al\x00ice:pw"))

	e := basic.NewExtractor()

	f.Fuzz(func(t *testing.T, header string) {
		c := newCarrier()
		c.Set("Authorization", header)

		got, err := e.Extract(context.Background(), c)
		if got != nil && err != nil {
			t.Fatalf("both a value and an error for %q", header)
		}

		if got == nil {
			return
		}

		if got.IsAuthenticated() {
			t.Fatalf("authenticated value for %q", header)
		}

		if !strings.EqualFold(header[:min(5, len(header))], "basic") {
			t.Fatalf("accepted a non-Basic header %q", header)
		}

		ba, ok := got.(basic.Authentication)
		if !ok {
			t.Fatalf("unexpected type %T", got)
		}

		for _, s := range []string{ba.Username(), ba.Password()} {
			if !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
				t.Fatalf("accepted %q from %q", s, header)
			}
		}
	})
}

// The credentials are bounded before they are decoded: a hostile
// multi-megabyte header costs no allocation. (Not parallel: it reads the
// process-wide allocation counter.)
func TestExtractorBoundsTheCredentialsBeforeDecoding(t *testing.T) {
	c := newCarrier()
	c.Set("Authorization", "Basic "+strings.Repeat("QUFB", 1<<20)) // 4 MiB of valid base64

	var before, after runtime.MemStats

	runtime.ReadMemStats(&before)

	got, err := basic.NewExtractor().Extract(context.Background(), c)

	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, basic.ErrBadFormat)
	assert.Nil(t, got)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(64<<10), "the credentials must be refused before being decoded")
}
