// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package grpcsec_test

import (
	"context"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// recordedSpan keeps what a trace backend would store about a span — its
// status, events and attributes — without pulling the OpenTelemetry SDK
// into this module. Hand-written: the span is an OpenTelemetry type, not an
// interface of this library mockery generates a mock for.
type recordedSpan struct {
	noop.Span

	name string

	mu     sync.Mutex
	status codes.Code
	desc   string
	events []string
	attrs  []string
}

func (s *recordedSpan) SetStatus(code codes.Code, desc string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.status, s.desc = code, desc
}

func (s *recordedSpan) AddEvent(name string, opts ...trace.EventOption) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, name)

	cfg := trace.NewEventConfig(opts...)

	for _, kv := range cfg.Attributes() {
		s.attrs = append(s.attrs, kv.Value.Emit())
	}
}

func (s *recordedSpan) RecordError(err error, _ ...trace.EventOption) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, "exception: "+err.Error())
}

func (s *recordedSpan) SetAttributes(kv ...attribute.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range kv {
		s.attrs = append(s.attrs, string(a.Key)+"="+a.Value.Emit())
	}
}

// evidence is every string the span would export.
func (s *recordedSpan) evidence() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.desc + "\n" + strings.Join(s.events, "\n") + "\n" + strings.Join(s.attrs, "\n")
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
	s := &recordedSpan{name: name}

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
// every span started.
func recordSpans(fn func()) []*recordedSpan {
	otelMu.Lock()
	defer otelMu.Unlock()

	previous := otel.GetTracerProvider()
	sink := &spanSink{}
	otel.SetTracerProvider(recordingProvider{sink: sink})

	defer otel.SetTracerProvider(previous)

	fn()

	return sink.spans
}
