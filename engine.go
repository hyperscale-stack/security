// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/codes"
)

// Engine is the high-level entry point: it drives a chain of [Extractor]s
// against a [Carrier], hands the produced [Authentication] to its [Manager],
// and returns a context enriched with the result so downstream handlers can
// call [FromContext].
//
// Engine is safe for concurrent use.
type Engine interface {
	// Process runs extractors in order and consults the manager on the first
	// non-empty result. The returned context always carries an Authentication
	// (the anonymous one when nothing was extracted).
	Process(ctx context.Context, c Carrier) (context.Context, Authentication, error)
}

// NewEngine returns an [Engine]. Passing zero extractors is allowed; the
// engine will produce the anonymous authentication and return
// [ErrNoExtractor] so callers can fail-closed if they wish.
func NewEngine(m Manager, extractors ...Extractor) Engine {
	cp := make([]Extractor, len(extractors))
	copy(cp, extractors)

	return &engine{manager: m, extractors: cp}
}

type engine struct {
	manager    Manager
	extractors []Extractor
}

// Process implements [Engine].
func (e *engine) Process(ctx context.Context, c Carrier) (context.Context, Authentication, error) {
	ctx, span := tracer().Start(ctx, "security.Engine.Process")
	defer span.End()

	span.SetAttributes(AttrExtractorsCount.Int(len(e.extractors)))

	if len(e.extractors) == 0 {
		span.SetStatus(codes.Error, ErrNoExtractor.Error())
		span.RecordError(ErrNoExtractor)

		ctx = WithAuthentication(ctx, Anonymous())

		return ctx, Anonymous(), ErrNoExtractor
	}

	var extracted Authentication

	for _, ex := range e.extractors {
		auth, err := ex.Extract(ctx, c)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)

			ctx = WithAuthentication(ctx, Anonymous())

			return ctx, Anonymous(), err
		}

		if auth != nil {
			extracted = auth

			break
		}
	}

	if extracted == nil {
		span.SetAttributes(AttrAuthenticated.Bool(false))

		ctx = WithAuthentication(ctx, Anonymous())

		return ctx, Anonymous(), nil
	}

	authed, err := e.manager.Authenticate(ctx, extracted)
	if err != nil {
		// Manager already attached its own span / status; propagate as-is
		// after recording the engine-level outcome. We attach the
		// (unauthenticated) extracted value to the context so that
		// error-mapping middleware can inspect Kind via FromContext for
		// richer challenges.
		span.SetStatus(codes.Error, err.Error())

		ctx = WithAuthentication(ctx, extracted)

		return ctx, extracted, fmt.Errorf("security.Engine: %w", err)
	}

	span.SetAttributes(AttrAuthenticated.Bool(authed.IsAuthenticated()))

	ctx = WithAuthentication(ctx, authed)

	return ctx, authed, nil
}
