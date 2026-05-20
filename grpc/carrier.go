// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"
	"strings"

	"github.com/hyperscale-stack/security"
	"google.golang.org/grpc/metadata"
)

// Carrier adapts gRPC request metadata to [security.Carrier].
//
// Reads consult the incoming metadata (metadata.FromIncomingContext).
// gRPC normalises metadata keys to lower-case; the Carrier lower-cases
// lookups so callers can use the conventional "Authorization" spelling.
//
// Writes accumulate in a private metadata.MD that the interceptor flushes
// as a response header (grpc.SetHeader) before returning. This lets an
// ErrorMapper attach, e.g., a diagnostic header alongside a status error.
//
// Carrier is NOT safe for concurrent use; one instance per RPC.
type Carrier struct {
	in  metadata.MD
	out metadata.MD
}

// NewCarrier builds a Carrier from an RPC context. When ctx carries no
// incoming metadata (a non-gRPC caller, a unit test), the read side is
// simply empty.
func NewCarrier(ctx context.Context) *Carrier {
	in, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		in = metadata.MD{}
	}

	return &Carrier{in: in, out: metadata.MD{}}
}

// Get implements [security.Carrier]. Returns the first value for key.
func (c *Carrier) Get(key string) string {
	vs := c.in.Get(strings.ToLower(key))
	if len(vs) == 0 {
		return ""
	}

	return vs[0]
}

// Values implements [security.Carrier].
func (c *Carrier) Values(key string) []string {
	return c.in.Get(strings.ToLower(key))
}

// Set implements [security.Carrier]. The value is staged in the response
// metadata; the interceptor flushes it via grpc.SetHeader.
func (c *Carrier) Set(key, value string) {
	c.out.Set(strings.ToLower(key), value)
}

// Add implements [security.Carrier].
func (c *Carrier) Add(key, value string) {
	c.out.Append(strings.ToLower(key), value)
}

// ResponseMetadata returns the staged response metadata. The interceptor
// calls it after the engine / handler run and, when non-empty, pushes it
// with grpc.SetHeader.
func (c *Carrier) ResponseMetadata() metadata.MD { return c.out }

// Compile-time check.
var _ security.Carrier = (*Carrier)(nil)
