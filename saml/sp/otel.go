// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the OTel instrumentation scope of this module.
const tracerName = "github.com/hyperscale-stack/security/saml/sp"

// Span attribute keys (documented in docs/observability.md). No span ever
// carries a NameID, an attribute value, a RelayState, a cookie, a request
// ID or message content.
const (
	// AttrConnectionID is the application's connection ID.
	AttrConnectionID = attribute.Key("samlsp.connection_id")
	// AttrIdPEntityID is the IdP entity ID of the connection.
	AttrIdPEntityID = attribute.Key("samlsp.idp_entity_id")
	// AttrOutcome is "success", "rejected" (the error matches ErrRejected)
	// or "error" (infrastructure or configuration failure).
	AttrOutcome = attribute.Key("samlsp.outcome")
	// AttrReason is the name of the sentinel error, e.g. "audience_mismatch".
	AttrReason = attribute.Key("samlsp.reason")
	// AttrInsecureSHA1 is set when the connection accepts SHA-1.
	AttrInsecureSHA1 = attribute.Key("samlsp.insecure_sha1")
)

// startSpan starts a span of this module.
func startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return otel.Tracer(tracerName).Start(ctx, name)
}

// annotateConnection records the connection attributes on the span.
func annotateConnection(span trace.Span, conn *Connection) {
	span.SetAttributes(
		AttrConnectionID.String(conn.ID),
		AttrIdPEntityID.String(conn.IdentityProvider.EntityID),
	)

	if conn.InsecureAllowSHA1 {
		span.SetAttributes(AttrInsecureSHA1.Bool(true))
	}
}

// endSpan records the outcome of an operation and ends the span. Error
// messages of this package are static, so recording them leaks nothing.
func endSpan(span trace.Span, err error) {
	defer span.End()

	switch {
	case err == nil:
		span.SetAttributes(AttrOutcome.String("success"))
		span.SetStatus(codes.Ok, "")
	case errors.Is(err, ErrRejected):
		span.SetAttributes(AttrOutcome.String("rejected"), AttrReason.String(reasonName(err)))
		span.SetStatus(codes.Error, "rejected")
	default:
		span.SetAttributes(AttrOutcome.String("error"), AttrReason.String(reasonName(err)))
		span.SetStatus(codes.Error, "error")
	}
}

// reasons maps sentinels to span reason names, most specific first.
var reasons = []struct {
	err  error
	name string
}{
	{ErrMalformedRequest, "malformed_request"},
	{ErrResponseTooLarge, "response_too_large"},
	{ErrUnsolicitedResponse, "unsolicited_response"},
	{ErrMissingBrowserBinding, "missing_browser_binding"},
	{ErrBrowserBindingMismatch, "browser_binding_mismatch"},
	{ErrTransactionNotFound, "transaction_not_found"},
	{ErrTransactionConsumed, "transaction_consumed"},
	{ErrTransactionExpired, "transaction_expired"},
	{ErrTransactionMismatch, "transaction_mismatch"},
	{ErrMalformedResponse, "malformed_response"},
	{ErrEncryptedAssertionUnsupported, "encrypted_assertion"},
	{ErrUnsupportedAlgorithm, "unsupported_algorithm"},
	{ErrInvalidSignature, "invalid_signature"},
	{ErrResponseStatus, "response_status"},
	{ErrIssuerMismatch, "issuer_mismatch"},
	{ErrDestinationMismatch, "destination_mismatch"},
	{ErrRecipientMismatch, "recipient_mismatch"},
	{ErrAudienceMismatch, "audience_mismatch"},
	{ErrInResponseToMismatch, "in_response_to_mismatch"},
	{ErrAssertionExpired, "assertion_expired"},
	{ErrAssertionNotYetValid, "assertion_not_yet_valid"},
	{ErrInvalidAssertion, "invalid_assertion"},
	{ErrNameIDFormatMismatch, "nameid_format_mismatch"},
	{ErrAuthnContextMismatch, "authn_context_mismatch"},
	{ErrStaleAuthentication, "stale_authentication"},
	{ErrAssertionReplayed, "assertion_replayed"},
	{ErrUnknownConnection, "unknown_connection"},
	{ErrInvalidConnection, "invalid_connection"},
	{ErrMetadataExpired, "metadata_expired"},
	{ErrMetadataUnavailable, "metadata_unavailable"},
	{ErrInvalidMetadata, "invalid_metadata"},
	{ErrInvalidLoginOptions, "invalid_login_options"},
	{ErrInvalidConfig, "invalid_config"},
	{ErrTransactionExists, "transaction_exists"},
	{ErrInvalidStoreRecord, "invalid_store_record"},
}

// reasonName names the first sentinel err matches; "error" otherwise.
func reasonName(err error) string {
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.name
		}
	}

	return "error"
}
