// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package httpsec_test

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// recordedSpan keeps the name and attributes of a span: enough to assert the
// telemetry of the middleware without pulling the OpenTelemetry SDK into
// this module.
type recordedSpan struct {
	noop.Span

	name  string
	mu    sync.Mutex
	attrs map[attribute.Key]attribute.Value
}

func (s *recordedSpan) SetAttributes(kv ...attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range kv {
		s.attrs[a.Key] = a.Value
	}
}

func (s *recordedSpan) attr(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, ok := s.attrs[attribute.Key(key)]

	return v.Emit(), ok
}

type spanSink struct {
	mu    sync.Mutex
	spans []*recordedSpan
}

type recordingTracer struct {
	noop.Tracer

	sink *spanSink
}

func (t recordingTracer) Start(ctx context.Context, name string, _ ...trace.SpanStartOption) (context.Context, trace.Span) {
	s := &recordedSpan{name: name, attrs: map[attribute.Key]attribute.Value{}}

	t.sink.mu.Lock()
	t.sink.spans = append(t.sink.spans, s)
	t.sink.mu.Unlock()

	return trace.ContextWithSpan(ctx, s), s
}

type recordingProvider struct {
	noop.TracerProvider

	sink *spanSink
}

func (p recordingProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return recordingTracer{sink: p.sink}
}

// otelMu serialises the tests that install a tracer provider. They MUST NOT
// call t.Parallel(): the provider is process-wide.
var otelMu sync.Mutex

// recordSpans installs a recording tracer provider while fn runs and returns
// the spans named name.
func recordSpans(name string, fn func()) []*recordedSpan {
	otelMu.Lock()
	defer otelMu.Unlock()

	previous := otel.GetTracerProvider()
	sink := &spanSink{}
	otel.SetTracerProvider(recordingProvider{sink: sink})

	defer otel.SetTracerProvider(previous)

	fn()

	var out []*recordedSpan

	for _, s := range sink.spans {
		if s.name == name {
			out = append(out, s)
		}
	}

	return out
}
