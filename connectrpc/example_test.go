// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/hyperscale-stack/security"
	connectrpcsec "github.com/hyperscale-stack/security/connectrpc"
	"github.com/hyperscale-stack/security/voter"
)

// Example wires the Bearer-token engine into a ConnectRPC service: the
// authentication interceptor validates the token, the authorization
// interceptor enforces a role, and the call only reaches the handler when
// both pass.
func Example() {
	engine := security.NewEngine(
		security.NewManager(tokenAuthenticator{authorities: []string{"ROLE_ADMIN"}}),
		tokenExtractor{},
	)
	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	// In a real server:
	//
	//	connect.WithInterceptors(
	//	    connectrpcsec.NewAuthenticationInterceptor(engine),
	//	    connectrpcsec.NewAuthorizationInterceptor(adm, []security.Attribute{security.Role("ADMIN")}),
	//	)
	//
	// Here we just demonstrate the error mapping the interceptors apply.
	_ = engine
	_ = adm

	mapper := connectrpcsec.DefaultErrorMapper()
	for _, err := range []error{
		security.ErrInvalidCredentials,
		security.ErrAccessDenied,
		security.ErrUnsupportedCredential,
	} {
		fmt.Println(connect.CodeOf(mapper.Map(context.Background(), err)))
	}

	// Output:
	// unauthenticated
	// permission_denied
	// invalid_argument
}
