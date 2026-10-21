// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package session_test

import (
	"context"
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit I-31 (BREACH-style hardening): the CSRF token was rendered as is,
// the same in every response of a session, so a compression side channel
// on a page that also reflects attacker input could recover it byte by
// byte. CSRFToken now renders a fresh mask with the secret XORed by it on
// every call; VerifyCSRF unmasks. The raw secret never verifies, so it is
// never worth rendering.
func TestCSRFTokensAreMaskedPerRendering(t *testing.T) {
	t.Parallel()

	mgr := newManager(t)

	s, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)

	first, second := session.CSRFToken(s), session.CSRFToken(s)

	assert.NotEqual(t, first, second, "a fresh mask per rendering")
	assert.NotContains(t, first, s.CSRFToken, "the secret is never rendered")
	assert.True(t, session.VerifyCSRF(s, first))
	assert.True(t, session.VerifyCSRF(s, second))

	raw, err := base64.RawURLEncoding.DecodeString(first)
	require.NoError(t, err)
	assert.Len(t, raw, 2*len(s.CSRFToken), "mask, then the masked secret")

	assert.False(t, session.VerifyCSRF(s, s.CSRFToken), "the unmasked secret does not verify")

	other, err := mgr.Login(context.Background(), newCarrier(), principal{sub: "alice"})
	require.NoError(t, err)
	assert.False(t, session.VerifyCSRF(s, session.CSRFToken(other)), "another session's token")
}

func TestVerifyCSRFRefusesTamperedTokens(t *testing.T) {
	t.Parallel()

	s := &session.Session{CSRFToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}
	masked := session.CSRFToken(s)
	raw, err := base64.RawURLEncoding.DecodeString(masked)
	require.NoError(t, err)

	flip := func(i int) string {
		b := append([]byte{}, raw...)
		b[i] ^= 0x01

		return base64.RawURLEncoding.EncodeToString(b)
	}
	n := len(s.CSRFToken)

	cases := map[string]string{
		"mask byte flipped":        flip(0),
		"last mask byte flipped":   flip(n - 1),
		"masked byte flipped":      flip(n),
		"last masked byte flipped": flip(2*n - 1),
		"one byte short":           base64.RawURLEncoding.EncodeToString(raw[:2*n-1]),
		"one byte long":            base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), 0)),
		"mask only":                base64.RawURLEncoding.EncodeToString(raw[:n]),
		"not base64url":            "!" + masked[1:],
		"standard base64 alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(masked) + "+/",
		"zero mask and raw secret": base64.RawURLEncoding.EncodeToString(append(make([]byte, n), s.CSRFToken...)),
		"empty":                    "",
	}

	for name, presented := range cases {
		if name == "zero mask and raw secret" {
			// A zero mask is a valid masking: the encoding is still the
			// session's own secret, as a page could have rendered it.
			assert.True(t, session.VerifyCSRF(s, presented), name)

			continue
		}

		assert.False(t, session.VerifyCSRF(s, presented), name)
	}
}

// Review nit 9: the length of a presented token is checked before it is
// decoded, so that a large value costs no allocation.
func TestVerifyCSRFDoesNotDecodeOversizedTokens(t *testing.T) {
	s := &session.Session{CSRFToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}
	huge := strings.Repeat("A", 1<<16)

	assert.False(t, session.VerifyCSRF(s, huge))
	assert.Zero(t, testing.AllocsPerRun(20, func() { session.VerifyCSRF(s, huge) }))
}

// Audit F-24 (CORE-10): replacing the constant-time comparison of
// VerifyCSRF with == kept every behavioural test green — only the timing
// changes. This test pins it in the source: VerifyCSRF compares with
// crypto/subtle.ConstantTimeCompare, calls no other comparison function,
// and its == and != compare only with a literal, nil or a length.
func TestVerifyCSRFComparesInConstantTime(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "csrf.go", nil, 0)
	require.NoError(t, err)

	var verify *ast.FuncDecl

	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "VerifyCSRF" {
			verify = fn
		}
	}

	require.NotNil(t, verify, "VerifyCSRF is declared in csrf.go")

	var constantTime bool

	ast.Inspect(verify.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			name := callName(n)
			if name == "subtle.ConstantTimeCompare" {
				constantTime = true
			}

			for _, banned := range []string{"bytes.Equal", "bytes.Compare", "strings.Compare", "strings.EqualFold",
				"reflect.DeepEqual", "slices.Equal", "hmac.Equal"} {
				assert.NotEqual(t, banned, name, "VerifyCSRF compares with %s", banned)
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				assert.True(t, harmless(n.X) || harmless(n.Y),
					"VerifyCSRF compares two values with %s", n.Op)
			}
		}

		return true
	})

	assert.True(t, constantTime, "VerifyCSRF calls subtle.ConstantTimeCompare")
}

// callName is "pkg.Func" for a selector call, "Func" otherwise.
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := fn.X.(*ast.Ident); ok {
			return pkg.Name + "." + fn.Sel.Name
		}
	case *ast.Ident:
		return fn.Name
	}

	return ""
}

// harmless reports whether e is a literal, nil or a length: comparing with
// it leaks nothing of the secret.
func harmless(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.CallExpr:
		return callName(e) == "len"
	case *ast.BinaryExpr:
		return harmless(e.X) && harmless(e.Y)
	}

	return false
}
