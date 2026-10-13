// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security"
	"github.com/stretchr/testify/mock"
)

// Builders of the mockery mocks (`make generate`) used as interface doubles
// by the contract, decision and span tests. Authentication and Attribute
// values (fakeAuthentication, stringAttr) and the header-backed mapCarrier
// stay plain values: the tests compare them, they script no behavior.

// Typed nils — the classic `var out *T; return out, nil`: a nil mock
// pointer satisfies the interface and panics on its first method call.
var (
	typedNilAuth security.Authentication = (*security.MockAuthentication)(nil)
	typedNilAttr security.Attribute      = (*security.MockAttribute)(nil)
)

// decidingVoter supports every attribute and votes d (possibly undefined).
func decidingVoter(t *testing.T, d security.Decision) *security.MockVoter {
	t.Helper()

	v := security.NewMockVoter(t)
	v.EXPECT().Supports(mock.Anything).Return(true).Maybe()
	v.EXPECT().Vote(mock.Anything, mock.Anything, mock.Anything).Return(d).Maybe()

	return v
}

// prefixVoter supports the attributes starting with prefix and votes d.
func prefixVoter(t *testing.T, prefix string, d security.Decision) *security.MockVoter {
	t.Helper()

	v := security.NewMockVoter(t)
	v.EXPECT().Supports(mock.Anything).RunAndReturn(hasPrefix(prefix)).Maybe()
	v.EXPECT().Vote(mock.Anything, mock.Anything, mock.Anything).Return(d).Maybe()

	return v
}

func hasPrefix(prefix string) func(security.Attribute) bool {
	return func(a security.Attribute) bool { return strings.HasPrefix(a.String(), prefix) }
}

// authReadingVoter supports every attribute and reads the Authentication it
// is given: it proves that Decide never hands a voter a nil one.
func authReadingVoter(t *testing.T) *security.MockVoter {
	t.Helper()

	v := security.NewMockVoter(t)
	v.EXPECT().Supports(mock.Anything).Return(true)
	v.EXPECT().Vote(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, auth security.Authentication, _ []security.Attribute) security.Decision {
			if auth.IsAuthenticated() {
				return security.DecisionGrant
			}

			return security.DecisionDeny
		})

	return v
}

// extractorReturning extracts (auth, err) and must be consulted.
func extractorReturning(t *testing.T, auth security.Authentication, err error) *security.MockExtractor {
	t.Helper()

	e := security.NewMockExtractor(t)
	e.EXPECT().Extract(mock.Anything, mock.Anything).Return(auth, err)

	return e
}

// authenticatorReturning supports every credential, answers (result, err)
// and must be consulted.
func authenticatorReturning(t *testing.T, result security.Authentication, err error) *security.MockAuthenticator {
	t.Helper()

	a := security.NewMockAuthenticator(t)
	a.EXPECT().Supports(mock.Anything).Return(true)
	a.EXPECT().Authenticate(mock.Anything, mock.Anything).Return(result, err)

	return a
}

// managerReturning is a custom Manager answering (result, err).
func managerReturning(t *testing.T, result security.Authentication, err error) *security.MockManager {
	t.Helper()

	m := security.NewMockManager(t)
	m.EXPECT().Authenticate(mock.Anything, mock.Anything).Return(result, err)

	return m
}
