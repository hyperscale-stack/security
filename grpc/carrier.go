// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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
// Writes accumulate in a private metadata.MD that the interceptors send as
// the response header (grpc.SetHeader), refused RPCs included: an extractor
// can attach, e.g., a challenge alongside a status error.
//
// A Carrier prints and logs its key counts only, never the metadata values.
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

// ResponseMetadata returns the staged response metadata. The interceptors
// call it after the engine ran and, when non-empty, send it as the response
// header (grpc.SetHeader / ServerStream.SetHeader) — before the handler
// runs, or before the status of a refused RPC.
func (c *Carrier) ResponseMetadata() metadata.MD { return c.out }

// String implements fmt.Stringer with the number of incoming and staged
// metadata keys: the values — the authorization metadata among them — are
// never printed.
func (c Carrier) String() string {
	return fmt.Sprintf("grpcsec.Carrier{Incoming: %d keys, Staged: %d keys}", len(c.in), len(c.out))
}

// Format implements fmt.Formatter like String, for every verb: without it,
// fmt prints the metadata maps. fmt handles %p of a non-pointer value before
// any method: no type can redact that one.
func (c Carrier) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue implements slog.LogValuer with the key counts only.
func (c Carrier) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("incoming_keys", len(c.in)), slog.Int("staged_keys", len(c.out)))
}

// Compile-time check.
var _ security.Carrier = (*Carrier)(nil)
