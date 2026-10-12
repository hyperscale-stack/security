// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"strings"
	"testing"
	"time"

	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/require"
)

func TestTransactionRecord_Validate(t *testing.T) {
	t.Parallel()

	key := strings.Repeat("ab", 32)
	valid := samlsp.TransactionRecord{ID: key, BindingHash: key, Payload: "{}", ExpiresAt: t0}
	require.NoError(t, valid.Validate())

	cases := map[string]func(*samlsp.TransactionRecord){
		"ID":           func(r *samlsp.TransactionRecord) { r.ID = "" },
		"binding":      func(r *samlsp.TransactionRecord) { r.BindingHash = strings.Repeat("g", 64) },
		"payload":      func(r *samlsp.TransactionRecord) { r.Payload = "" },
		"payload size": func(r *samlsp.TransactionRecord) { r.Payload = strings.Repeat("x", samlsp.MaxTransactionPayloadSize+1) },
		"payload NUL":  func(r *samlsp.TransactionRecord) { r.Payload = "\x00" },
		"payload UTF8": func(r *samlsp.TransactionRecord) { r.Payload = "\xc3" },
		"zero expiry":  func(r *samlsp.TransactionRecord) { r.ExpiresAt = time.Time{} },
		"epoch":        func(r *samlsp.TransactionRecord) { r.ExpiresAt = time.Unix(0, 0) },
		"sub-second":   func(r *samlsp.TransactionRecord) { r.ExpiresAt = t0.Add(time.Nanosecond) },
	}

	for name, mutate := range cases {
		rec := valid
		mutate(&rec)
		require.ErrorIs(t, rec.Validate(), samlsp.ErrInvalidStoreRecord, name)
	}

	var nilRec *samlsp.TransactionRecord
	require.ErrorIs(t, nilRec.Validate(), samlsp.ErrInvalidStoreRecord)

	rec := valid
	rec.Payload = strings.Repeat("x", samlsp.MaxTransactionPayloadSize)
	require.NoError(t, rec.Validate(), "payload at the cap")
}

func TestValidateStoreKey(t *testing.T) {
	t.Parallel()

	require.NoError(t, samlsp.ValidateStoreKey(strings.Repeat("0123456789abcdef", 4)))

	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("-", 64)} {
		require.ErrorIs(t, samlsp.ValidateStoreKey(bad), samlsp.ErrInvalidStoreRecord, bad)
	}
}
