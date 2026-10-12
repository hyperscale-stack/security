// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"fmt"
	"slices"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/hyperscale-stack/security/voter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// Example wires the Bearer-token engine into a gRPC server: the
// authentication interceptors validate the token, the authorization
// interceptors enforce a role, and a call — unary or streaming — only
// reaches its handler when both pass.
func Example() {
	engine := security.NewEngine(
		security.NewManager(tokenAuthenticator{authorities: []string{"ROLE_ADMIN"}}),
		tokenExtractor{},
	)
	adm := security.NewAffirmativeDecisionManager(voter.HasRole("ADMIN"))

	// ServerOptions and AuthorizeServerOptions chain the unary AND the
	// stream interceptors: chaining only unary ones would leave streaming
	// RPCs unauthenticated.
	srv := grpc.NewServer(slices.Concat(
		grpcsec.ServerOptions(engine),
		grpcsec.AuthorizeServerOptions(adm, []security.Attribute{security.Role("ADMIN")}),
	)...)
	defer srv.Stop()

	// The interceptors answer with the default error mapping.
	mapper := grpcsec.DefaultErrorMapper()
	for _, err := range []error{
		security.ErrInvalidCredentials,
		security.ErrAccessDenied,
		security.ErrUnavailable,
	} {
		fmt.Println(status.Code(mapper.Map(context.Background(), err)))
	}

	// Output:
	// Unauthenticated
	// PermissionDenied
	// Unavailable
}
