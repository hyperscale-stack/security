// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security_test

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// otelMu serialises every test that installs a TracerProvider so that
// concurrent t.Parallel runs do not stomp on each other's recorders.
// Any test that calls spanRecorder MUST NOT call t.Parallel().
var otelMu sync.Mutex

// spanRecorder installs an in-memory OTel exporter as the global tracer
// provider for the duration of a test, and returns the spans captured during
// the call to fn.
//
// The exporter is goroutine-safe; callers passing fn that spawns goroutines
// should Synchronize via the SpanRecorder's flush mechanics — out of scope
// for the current tests.
func spanRecorder(fn func()) []sdktrace.ReadOnlySpan {
	otelMu.Lock()
	defer otelMu.Unlock()

	previous := otel.GetTracerProvider()

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)

	defer otel.SetTracerProvider(previous)

	fn()

	_ = tp.Shutdown(context.Background())

	return rec.Ended()
}

// findAttr returns the value of attr in attrs as a string, or "" if missing.
func findAttr(attrs []attribute.KeyValue, key attribute.Key) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.Emit()
		}
	}

	return ""
}
