// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec_test

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
	"go.opentelemetry.io/otel/trace/noop"
)

// otelMu serialises the tests that install the recording provider as the
// global one. Such tests MUST NOT call t.Parallel(): top-level parallel
// tests are paused while a sequential test runs, so no other test emits
// spans into the recorder meanwhile.
var otelMu sync.Mutex

// recorder is a minimal trace.TracerProvider keeping what the package
// writes on its spans — built on the otel API alone, so the module needs
// no SDK dependency for its tests.
type recorder struct {
	embedded.TracerProvider

	mu    sync.Mutex
	spans []*recSpan
}

type recTracer struct {
	embedded.Tracer

	r *recorder
}

// recSpan records attributes, status, recorded errors and links.
type recSpan struct {
	noop.Span

	mu     sync.Mutex
	name   string
	attrs  []attribute.KeyValue
	errs   []string
	status codes.Code
	desc   string
	links  []trace.Link
	root   bool
}

// record installs a recorder as the global tracer provider while fn runs
// and returns the spans fn started.
func record(fn func()) []*recSpan {
	otelMu.Lock()
	defer otelMu.Unlock()

	previous := otel.GetTracerProvider()
	rec := &recorder{}

	otel.SetTracerProvider(rec)
	defer otel.SetTracerProvider(previous)

	fn()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	return append([]*recSpan(nil), rec.spans...)
}

func (r *recorder) Tracer(string, ...trace.TracerOption) trace.Tracer { return recTracer{r: r} }

func (t recTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	cfg := trace.NewSpanStartConfig(opts...)
	s := &recSpan{name: name, attrs: cfg.Attributes(), links: cfg.Links(), root: cfg.NewRoot()}

	t.r.mu.Lock()
	t.r.spans = append(t.r.spans, s)
	t.r.mu.Unlock()

	return trace.ContextWithSpan(ctx, s), s
}

func (s *recSpan) SetAttributes(kv ...attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attrs = append(s.attrs, kv...)
}

func (s *recSpan) RecordError(err error, _ ...trace.EventOption) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.errs = append(s.errs, err.Error())
}

func (s *recSpan) SetStatus(c codes.Code, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.status, s.desc = c, desc
}

func (s *recSpan) IsRecording() bool { return true }

// attr returns the last value of key, "" when absent.
func (s *recSpan) attr(key attribute.Key) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := ""

	for _, kv := range s.attrs {
		if kv.Key == key {
			out = kv.Value.Emit()
		}
	}

	return out
}

// named returns the recorded spans called name.
func named(spans []*recSpan, name string) []*recSpan {
	var out []*recSpan

	for _, s := range spans {
		if s.name == name {
			out = append(out, s)
		}
	}

	return out
}
