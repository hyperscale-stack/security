// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"fmt"

	"github.com/hyperscale-stack/security"
	grpcsec "github.com/hyperscale-stack/security/grpc"
	"github.com/hyperscale-stack/security/voter"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Example wires the Bearer-token engine into a gRPC server: the
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
	//	grpc.NewServer(
	//	    grpc.ChainUnaryInterceptor(
	//	        grpcsec.UnaryServerInterceptor(engine),
	//	        grpcsec.UnaryAuthorize(adm, []security.Attribute{security.Role("ADMIN")}),
	//	    ),
	//	)
	//
	// Here we just demonstrate the error mapping the interceptors apply.
	_ = engine
	_ = adm

	mapper := grpcsec.DefaultErrorMapper()
	for _, err := range []error{
		security.ErrInvalidCredentials,
		security.ErrAccessDenied,
		security.ErrUnsupportedCredential,
	} {
		fmt.Println(status.Code(mapper.Map(context.Background(), err)))
	}

	_ = healthpb.HealthCheckRequest{}
	_ = codes.OK

	// Output:
	// Unauthenticated
	// PermissionDenied
	// InvalidArgument
}
