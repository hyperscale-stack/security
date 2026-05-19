// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

// Principal identifies the subject of an [Authentication]. Implementations
// represent end users, service clients, devices, or any other authenticatable
// entity.
//
// The interface is intentionally minimal: any authorisation-specific data
// (roles, scopes, claims, ...) is carried by [Authentication.Authorities]
// or by attaching a concrete implementation via [Authentication.Attribute].
// This keeps the core decoupled from any user store schema.
type Principal interface {
	// Subject returns the stable, unique identifier of the principal. It is
	// the value that authorisation checks key off (`sub` claim, user ID,
	// client ID, ...). Implementations MUST return the same value across
	// calls for the lifetime of a request.
	Subject() string
}

// AnonymousPrincipal is the singleton principal returned by the core when no
// credentials were extracted from a [Carrier]. Authorisation voters use it to
// distinguish "no authentication attempt" from "authentication failed".
var AnonymousPrincipal Principal = anonymousPrincipal{}

type anonymousPrincipal struct{}

func (anonymousPrincipal) Subject() string { return anonymousSubject }
