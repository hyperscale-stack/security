// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyperscale-stack/security"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors_Taxonomy(t *testing.T) {
	t.Parallel()

	rejections := []error{
		samlsp.ErrTransactionNotFound, samlsp.ErrTransactionConsumed, samlsp.ErrBrowserBindingMismatch,
		samlsp.ErrAssertionReplayed, samlsp.ErrMalformedRequest, samlsp.ErrResponseTooLarge,
		samlsp.ErrUnsolicitedResponse, samlsp.ErrMissingBrowserBinding, samlsp.ErrTransactionExpired,
		samlsp.ErrTransactionMismatch, samlsp.ErrMalformedResponse, samlsp.ErrEncryptedAssertionUnsupported,
		samlsp.ErrUnsupportedAlgorithm, samlsp.ErrInvalidSignature, samlsp.ErrResponseStatus,
		samlsp.ErrIssuerMismatch, samlsp.ErrDestinationMismatch, samlsp.ErrRecipientMismatch,
		samlsp.ErrAudienceMismatch, samlsp.ErrInResponseToMismatch, samlsp.ErrAssertionExpired,
		samlsp.ErrAssertionNotYetValid, samlsp.ErrInvalidAssertion, samlsp.ErrNameIDFormatMismatch,
		samlsp.ErrAuthnContextMismatch, samlsp.ErrStaleAuthentication,
	}

	for _, err := range rejections {
		require.ErrorIs(t, err, samlsp.ErrRejected, err.Error())
		require.ErrorIs(t, err, security.ErrInvalidCredentials, err.Error())
	}

	plain := []error{
		samlsp.ErrInvalidConfig, samlsp.ErrInvalidConnection, samlsp.ErrInvalidLoginOptions,
		samlsp.ErrUnknownConnection, samlsp.ErrInvalidMetadata, samlsp.ErrMetadataExpired,
		samlsp.ErrTransactionExists, samlsp.ErrInvalidStoreRecord,
	}

	for _, err := range plain {
		require.NotErrorIs(t, err, samlsp.ErrRejected, err.Error())
	}
}

func TestStatusError(t *testing.T) {
	t.Parallel()

	const ns = "urn:oasis:names:tc:SAML:2.0:status:"

	err := error(&samlsp.StatusError{Code: ns + "Responder"})
	require.ErrorIs(t, err, samlsp.ErrResponseStatus)
	require.ErrorIs(t, err, samlsp.ErrRejected)
	assert.Equal(t, samlsp.ErrResponseStatus.Error()+" (Responder)", err.Error())

	err = &samlsp.StatusError{Code: ns + "Requester", SubCode: ns + "NoPassive", Message: "secret detail"}
	assert.Equal(t, samlsp.ErrResponseStatus.Error()+" (Requester, NoPassive)", err.Error())
	assert.NotContains(t, err.Error(), "secret detail", "the message is never part of Error()")

	// Codes outside the SAML 2.0 status codes come from the IdP or from an
	// attacker: Error() names none of them (code review F5).
	for _, code := range []string{"level=error msg=admin", ns + "Unknown", ns + strings.Repeat("A", 300), "c"} {
		err = &samlsp.StatusError{Code: code, SubCode: code}
		assert.Equal(t, samlsp.ErrResponseStatus.Error()+" (non-standard status, non-standard status)", err.Error())
	}

	var se *samlsp.StatusError
	require.True(t, errors.As(err, &se))
}
