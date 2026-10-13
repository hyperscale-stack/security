// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"context"
	"errors"
	"fmt"
)

// errContractViolation marks a component that broke its contract — an
// [Authenticator] or a [Manager] that reported success without an
// authenticated value. It wraps no security sentinel on purpose: the
// transport adapters answer it as an internal error, never as a verdict on
// the credentials.
var errContractViolation = errors.New("security: contract violation")

// Engine is the high-level entry point: it drives a chain of [Extractor]s
// against a [Carrier], hands the produced [Authentication] to its [Manager],
// and returns a context enriched with the result so downstream handlers can
// call [FromContext].
//
// Engine is safe for concurrent use.
type Engine interface {
	// Process runs extractors in order and consults the manager on the first
	// non-empty result — a typed nil (an interface holding a nil pointer)
	// counts as empty. The returned context always carries an
	// Authentication: the authenticated one on success, the anonymous one
	// when nothing was extracted and on every failure — the extracted
	// credentials never leave the Engine. On failure the error says why.
	Process(ctx context.Context, c Carrier) (context.Context, Authentication, error)
}

// NewEngine returns an [Engine]. Passing zero extractors is allowed; the
// engine will produce the anonymous authentication and return
// [ErrNoExtractor] so callers can fail-closed if they wish.
//
// Extractors run in order and the first one that finds a credential wins.
// Put the header-based extractors (bearer, basic) before cookie-based ones
// (session): a browser attaches cookies to cross-site requests by itself, so
// an engine that accepts a cookie session authenticates requests an
// attacker's page can trigger — protect state-changing endpoints reached
// with a cookie session against CSRF, and prefer one engine per audience
// (browser pages, APIs). Per-username throttling or lockout belongs in an
// [Authenticator] wrapper: the Engine never returns the attempted
// credentials.
//
// NewEngine panics if m or one of the extractors is nil: these are
// programming errors that would otherwise surface as a nil dereference on
// the first request.
func NewEngine(m Manager, extractors ...Extractor) Engine {
	if m == nil {
		panic("security: NewEngine: nil Manager")
	}

	for i, ex := range extractors {
		if ex == nil {
			panic(fmt.Sprintf("security: NewEngine: nil Extractor at index %d", i))
		}
	}

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
		recordFailure(span, ErrNoExtractor)

		ctx = WithAuthentication(ctx, Anonymous())

		return ctx, Anonymous(), ErrNoExtractor
	}

	var extracted Authentication

	for _, ex := range e.extractors {
		auth, err := ex.Extract(ctx, c)
		if err != nil {
			recordFailure(span, err)

			ctx = WithAuthentication(ctx, Anonymous())

			return ctx, Anonymous(), err
		}

		if !isNil(auth) {
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
	if err == nil {
		err = requireAuthenticated(authed, "Manager")
	}

	if err != nil {
		// The extracted value carries the presented credentials (a
		// cleartext password, a bearer token): it is dropped here and the
		// context gets the anonymous authentication.
		recordFailure(span, err)

		ctx = WithAuthentication(ctx, Anonymous())

		return ctx, Anonymous(), fmt.Errorf("security.Engine: %w", err)
	}

	span.SetAttributes(AttrAuthenticated.Bool(true))

	ctx = WithAuthentication(ctx, authed)

	return ctx, authed, nil
}

// requireAuthenticated reports a contract violation when a component that
// returned no error produced no authenticated value: nil, a typed nil or an
// unauthenticated value.
func requireAuthenticated(auth Authentication, component string) error {
	if isNil(auth) || !auth.IsAuthenticated() {
		return fmt.Errorf("%w: %s returned no authenticated value", errContractViolation, component)
	}

	return nil
}
