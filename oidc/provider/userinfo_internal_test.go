// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcprovider

import (
	"errors"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/oauth2"
	"github.com/stretchr/testify/assert"
)

// TestBearerChallengeQuotesItsParameters pins RFC 6750 §3 and RFC 9110
// §5.6.4: every parameter is a quoted-string, '"' and '\' escaped — a valid
// issuer never holds them, the challenge stays well-formed regardless.
func TestBearerChallengeQuotesItsParameters(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `Bearer realm="https://op.example/a\"b\\c"`, bearerChallenge(`https://op.example/a"b\c`, nil))
	assert.Equal(t,
		`Bearer realm="r", error="insufficient_scope", error_description="The access token does not grant the openid scope.", scope="openid"`,
		bearerChallenge("r", errBearerScope))
	assert.Equal(t, `Bearer realm="r", error="invalid_token", error_description="The access token is invalid, expired or revoked."`,
		bearerChallenge("r", errBearerToken))
}

// TestBearerErrorWrapsItsRefusal: a refusal reads and matches as its RFC
// 6750 error and its cause.
func TestBearerErrorWrapsItsRefusal(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")
	err := refuse(errBearerToken, cause)

	assert.Equal(t, "oauth2: invalid_token: The access token is invalid, expired or revoked.", err.Error())
	assert.ErrorIs(t, err, cause)
	assert.ErrorIs(t, err, security.ErrInvalidCredentials)
	assert.Equal(t, codeInvalidToken, oauth2.IsCode(err))
	assert.ErrorIs(t, refuse(errBearerScope, nil), security.ErrInsufficientScope)
}
