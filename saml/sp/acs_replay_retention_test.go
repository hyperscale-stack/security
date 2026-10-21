// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package samlsp_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	samlsp "github.com/hyperscale-stack/security/saml/sp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCompleteLogin_ReplayRetentionLeavesNoGap: Profiles §4.1.4.5 asks to
// keep a bearer assertion's ID for as long as it would be considered
// valid. Its retention stops at the transaction expiry (plus a margin) even
// when the bearer confirmation lasts longer (audit I-22): no response of a
// transaction is accepted after its expiry, which the transaction MAC
// covers and the SP's clock judges. With a store that forgets the
// consumption (the consumed flag is outside the MAC) and replay marks that
// expire on time, a replay is refused by the mark up to the transaction
// expiry and by the expiry from then on: there is no window in between.
func TestCompleteLogin_ReplayRetentionLeavesNoGap(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		saved = map[string]samlsp.TransactionRecord{}
		marks = map[string]time.Time{}
		now   func() time.Time
	)

	mem := newMemoryStore(atT0)
	store := storageDouble(t, mem, func(m *samlsp.MockStorage) {
		m.EXPECT().SaveTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(ctx context.Context, rec *samlsp.TransactionRecord) error {
				mu.Lock()
				saved[rec.ID] = *rec
				mu.Unlock()

				return mem.SaveTransaction(ctx, rec)
			}).Maybe()
		// The store forgets every consumption.
		m.EXPECT().LookupTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, id string) (*samlsp.TransactionRecord, error) {
				mu.Lock()
				defer mu.Unlock()

				rec, ok := saved[id]
				if !ok {
					return nil, samlsp.ErrTransactionNotFound
				}

				return &rec, nil
			}).Maybe()
		m.EXPECT().ConsumeTransaction(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		// Replay marks expire exactly when asked, on the SP's clock.
		m.EXPECT().MarkAssertionUsed(mock.Anything, mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, key string, expiresAt time.Time) error {
				mu.Lock()
				defer mu.Unlock()

				if prev, ok := marks[key]; ok && now().Before(prev) {
					return samlsp.ErrAssertionReplayed
				}

				marks[key] = expiresAt

				return nil
			}).Maybe()
	})

	e := newEnv(t, withStorage(store))
	now = e.clock.Now

	// A bearer confirmation (and conditions) valid well past the
	// transaction expiry.
	long := respOpts{beforeAssertion: func(a *etree.Element) {
		exp := t0.Add(3 * samlsp.DefaultTransactionTTL).Format("2006-01-02T15:04:05Z")
		path(a, "Subject", "SubjectConfirmation", "SubjectConfirmationData").CreateAttr("NotOnOrAfter", exp)
		path(a, "Conditions").CreateAttr("NotOnOrAfter", exp)
	}}

	lr := begin(t, e, samlsp.LoginOptions{})
	samlResponse := respond(t, lr.requestID, long)

	_, err := complete(e, lr, samlResponse)
	require.NoError(t, err)

	steps := []struct {
		at   time.Duration
		want error
	}{
		{samlsp.DefaultTransactionTTL - time.Second, samlsp.ErrAssertionReplayed},    // the mark refuses
		{samlsp.DefaultTransactionTTL, samlsp.ErrTransactionExpired},                 // the expiry takes over
		{samlsp.DefaultTransactionTTL + 2*time.Minute, samlsp.ErrTransactionExpired}, // the mark is gone
		{3*samlsp.DefaultTransactionTTL - time.Second, samlsp.ErrTransactionExpired}, // the confirmation is still valid
	}

	for _, s := range steps {
		e.clock.set(t0.Add(s.at))

		_, err := complete(e, lr, samlResponse)
		require.ErrorIs(t, err, s.want, "replay at t0+%s", s.at)
	}
}
