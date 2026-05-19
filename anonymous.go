// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// Anonymous returns the singleton [Authentication] used when no credential
// could be extracted from a [Carrier]. It is safe to call from any goroutine;
// the returned value is shared and immutable.
//
// Voters that opt-in to anonymous access (see voter.Anonymous in Phase 5)
// match this value; the default policy of [AccessDecisionManager] is to deny
// when no voter grants, so anonymous calls fail closed by default.
func Anonymous() Authentication { return anonymousAuth }

// anonymousAuth is the package-wide singleton returned by Anonymous().
var anonymousAuth Authentication = anonymousAuthentication{}

type anonymousAuthentication struct{}

func (anonymousAuthentication) Principal() Principal { return AnonymousPrincipal }
func (anonymousAuthentication) Credentials() any     { return nil }
func (anonymousAuthentication) Authorities() []string {
	// Returning nil rather than a shared zero-length slice prevents
	// accidental mutation by misbehaving callers.
	return nil
}
func (anonymousAuthentication) IsAuthenticated() bool { return false }
func (anonymousAuthentication) Name() string          { return anonymousSubject }

// anonymousSubject is the stable subject string used by both
// [AnonymousPrincipal] and the anonymous [Authentication.Name].
const anonymousSubject = "anonymous"
