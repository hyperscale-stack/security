// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package security

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// trAttrName is a tiny helper that wraps a name into an event option to keep
// span.AddEvent calls succinct.
func trAttrName(name string) trace.EventOption {
	return trace.WithAttributes(AttrAuthenticatorName.String(name))
}

// tracerName is the OTel instrumentation scope name for the core package.
// Sub-modules MUST use their own scope (e.g. github.com/hyperscale-stack/security/http)
// to keep span attribution unambiguous.
const tracerName = "github.com/hyperscale-stack/security"

// tracer returns the package-level tracer. Callers should not cache it across
// goroutines; the OTel SDK already memoizes the returned tracer.
func tracer() trace.Tracer { return otel.Tracer(tracerName) }

// Span attribute keys used across the core. They are kept here as typed
// constants so that documentation in docs/observability.md can be diffed
// against the source of truth.
const (
	// AttrAuthenticated reports whether the resulting Authentication is
	// authenticated. Value: bool.
	AttrAuthenticated = attribute.Key("security.authenticated")

	// AttrPrincipalSubject is the principal subject. Emission is gated by the
	// subject-redaction policy (see SetSubjectAttributeMode) to avoid leaking
	// personal data into trace backends; the default is a hashed prefix.
	AttrPrincipalSubject = attribute.Key("security.principal.subject")

	// AttrExtractorsCount counts the extractors tried by an Engine call.
	// Value: int.
	AttrExtractorsCount = attribute.Key("security.extractors.count")

	// AttrAuthenticatorsCount counts the authenticators tried by a Manager.
	// Value: int.
	AttrAuthenticatorsCount = attribute.Key("security.authenticators.count")

	// AttrAuthenticatorName names the authenticator that produced the final
	// authenticated value, when known. Value: string.
	AttrAuthenticatorName = attribute.Key("security.authenticator.name")

	// AttrStrategy names the AccessDecisionManager strategy that took the
	// final decision. Value: "affirmative" | "consensus" | "unanimous".
	AttrStrategy = attribute.Key("security.strategy")

	// AttrDecision is the final authorization decision.
	// Value: "permit" | "deny" | "abstain".
	AttrDecision = attribute.Key("security.decision")

	// AttrAttributes is the joined String() form of the Attributes considered
	// for an authorization decision. Value: string.
	AttrAttributes = attribute.Key("security.attributes")
)
