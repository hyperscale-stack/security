// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hyperscale-stack/security/oauth2"
)

// Store is a database/sql-backed [oauth2.Storage].
//
// ConsumeAuthorizationCode runs in a transaction whose first statement, an
// UPDATE flagging the code consumed, decides the winner when two callers
// race (RowsAffected()==1). The consumed row stays, so a replay is
// recognized, until an operator deletes it (see the package
// documentation).
//
// The token operations implement the token-family contract of
// [oauth2.Storage] on one record per family (oauth2_token_families), the
// point every write into the family serializes on:
//
//   - SaveTokenPair and RotateRefreshToken each run in one transaction that
//     starts with a write — recording the family unless it exists — then
//     locks the family row (SELECT … FOR UPDATE; SQLite's single writer
//     serializes the transactions instead), refuses a revoked family, and
//     only then writes the tokens. A rotation records an unknown family as
//     revoked: only an issuance creates an active family.
//   - RevokeRefreshFamily records the family revoked in one transaction,
//     whether or not any of its tokens exists. On reuse, RotateRefreshToken
//     does the same inside its own transaction, which already holds the
//     family lock, and commits it.
//   - Lookups are single statements joining the family record: a token of
//     a revoked family — or of a family the table no longer holds — is
//     reported revoked, a refresh token as consumed.
//
// Revocation therefore never touches token rows: they stay until an
// operator deletes expired rows (see the package documentation).
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// New returns a [Store] bound to db using the given [Dialect]. The
// caller owns db's lifecycle. Call [Store.Migrate] once at boot (or run
// the DDL from [Schema] through a migration tool).
func New(db *sql.DB, dialect Dialect) (*Store, error) {
	if db == nil {
		return nil, errors.New("sqlstore: New: nil *sql.DB")
	}

	if dialect == nil {
		return nil, errors.New("sqlstore: New: nil Dialect")
	}

	return &Store{db: db, dialect: dialect}, nil
}

// exec runs a non-query statement, rebinding placeholders for the dialect.
func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.dialect.rebind(q), args...) //nolint:wrapcheck // wrapped by callers
}

// --- authorization codes -------------------------------------------------

// SaveAuthorizationCode implements [oauth2.AuthorizationCodeStore].
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *oauth2.AuthorizationCode) error {
	if code.CodeHash == "" {
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: empty code hash")
	}

	const q = `INSERT INTO oauth2_auth_codes
		(code_hash, client_id, subject, redirect_uri, scope,
		 code_challenge, code_challenge_method, nonce, issued_at, expires_at,
		 issuer, extension_data, redirect_uri_omitted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.exec(ctx, q,
		code.CodeHash, code.ClientID, code.Subject, code.RedirectURI, code.Scope,
		code.CodeChallenge, code.CodeChallengeMethod, code.Nonce,
		code.IssuedAt.Unix(), code.ExpiresAt.Unix(),
		code.Issuer, code.ExtensionData, flag(code.RedirectURIOmitted))
	if err != nil {
		return fmt.Errorf("sqlstore: save authorization code: %w", err)
	}

	return nil
}

// ConsumeAuthorizationCode implements [oauth2.AuthorizationCodeStore] in
// one transaction that starts with its write: an UPDATE flags the code
// consumed unless it already is, and its RowsAffected() picks the one
// winner when callers race — a concurrent UPDATE waits on the row lock,
// then finds the flag set (SQLite's single writer serializes them
// instead). The record is then read in the same transaction: the winner
// commits and gets it, a loser rolls back and gets an
// [*oauth2.CodeReplayError] carrying it, and a hash without a row is an
// unknown code.
func (s *Store) ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*oauth2.AuthorizationCode, error) {
	var code *oauth2.AuthorizationCode

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.dialect.rebind(
			`UPDATE oauth2_auth_codes SET consumed = 1 WHERE code_hash = ? AND consumed = 0`), codeHash)
		if err != nil {
			return fmt.Errorf("sqlstore: consume authorization code: %w", err)
		}

		won, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("sqlstore: rows affected: %w", err)
		}

		if code, err = s.selectCode(ctx, tx, codeHash); err != nil {
			return err
		}

		if won != 1 {
			// Consumed before: by an earlier call, or by a concurrent one
			// that committed first.
			return &oauth2.CodeReplayError{Record: code}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Expiry is NOT checked here: the grant compares ExpiresAt with its
	// own clock.
	return code, nil
}

// selectCode reads the record of the code codeHash within tx. A hash
// without a row is an unknown code: [oauth2.ErrCodeAlreadyUsed].
func (s *Store) selectCode(ctx context.Context, tx *sql.Tx, codeHash string) (*oauth2.AuthorizationCode, error) {
	const sel = `SELECT client_id, subject, redirect_uri, scope,
		code_challenge, code_challenge_method, nonce, issued_at, expires_at,
		COALESCE(issuer, ''), COALESCE(extension_data, ''), redirect_uri_omitted
		FROM oauth2_auth_codes WHERE code_hash = ?`

	var (
		code              = &oauth2.AuthorizationCode{CodeHash: codeHash}
		issuedAt, expires int64
		redirectOmitted   int64
	)

	err := tx.QueryRowContext(ctx, s.dialect.rebind(sel), codeHash).Scan(
		&code.ClientID, &code.Subject, &code.RedirectURI, &code.Scope,
		&code.CodeChallenge, &code.CodeChallengeMethod, &code.Nonce,
		&issuedAt, &expires, &code.Issuer, &code.ExtensionData, &redirectOmitted,
	)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, oauth2.ErrCodeAlreadyUsed
	case err != nil:
		return nil, fmt.Errorf("sqlstore: select authorization code: %w", err)
	}

	code.IssuedAt = time.Unix(issuedAt, 0)
	code.ExpiresAt = time.Unix(expires, 0)
	code.RedirectURIOmitted = redirectOmitted != 0

	return code, nil
}

// --- access and refresh tokens -------------------------------------------

// SaveTokenPair implements [oauth2.Storage]: one transaction joins the
// pair's family — recording it active when unknown, refusing it once
// revoked — and inserts both tokens. A pair outside any family is inserted
// without a family record.
func (s *Store) SaveTokenPair(ctx context.Context, pair *oauth2.TokenPair) error {
	if err := pair.Validate(); err != nil {
		return fmt.Errorf("sqlstore: save token pair: %w", err)
	}

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if familyID := pair.Access.FamilyID; familyID != "" {
			if err := s.joinFamily(ctx, tx, familyID, pairExpiry(pair)); err != nil {
				return err
			}
		}

		return s.insertPair(ctx, tx, pair)
	})
}

// LookupAccessToken implements [oauth2.AccessTokenStore]. One statement
// reads the token and its family record: a token of a revoked or unknown
// family is reported as [oauth2.ErrTokenFamilyRevoked].
func (s *Store) LookupAccessToken(ctx context.Context, tokenHash string) (*oauth2.AccessToken, error) {
	const q = `SELECT t.client_id, t.subject, t.scope, t.family_id, t.audience, t.issued_at, t.expires_at,
			COALESCE(t.issuer, ''), COALESCE(t.extension_data, ''), f.revoked_at
		FROM oauth2_access_tokens t
		LEFT JOIN oauth2_token_families f ON f.family_id = t.family_id
		WHERE t.token_hash = ?`

	var (
		t                 = &oauth2.AccessToken{TokenHash: tokenHash}
		issuedAt, expires int64
		revokedAt         sql.NullInt64
	)

	row := s.db.QueryRowContext(ctx, s.dialect.rebind(q), tokenHash)
	if err := row.Scan(&t.ClientID, &t.Subject, &t.Scope, &t.FamilyID, &t.Audience,
		&issuedAt, &expires, &t.Issuer, &t.ExtensionData, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("access token not found")
		}

		return nil, fmt.Errorf("sqlstore: lookup access token: %w", err)
	}

	if !familyActive(t.FamilyID, revokedAt) {
		return nil, oauth2.ErrTokenFamilyRevoked
	}

	t.IssuedAt = time.Unix(issuedAt, 0)
	t.ExpiresAt = time.Unix(expires, 0)

	return t, nil
}

// RevokeAccessToken implements [oauth2.AccessTokenStore].
func (s *Store) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	if _, err := s.exec(ctx, `DELETE FROM oauth2_access_tokens WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("sqlstore: revoke access token: %w", err)
	}

	return nil
}

// LookupRefreshToken implements [oauth2.RefreshTokenStore]. One statement
// reads the token and its family record: a token of a revoked or unknown
// family comes back consumed — and so does a token stored without a
// family, which no valid pair carries.
func (s *Store) LookupRefreshToken(ctx context.Context, tokenHash string) (*oauth2.RefreshToken, error) {
	const q = `SELECT t.client_id, t.subject, t.scope, t.family_id, t.consumed, t.issued_at, t.expires_at,
			COALESCE(t.issuer, ''), COALESCE(t.extension_data, ''), t.family_issued_at, f.revoked_at
		FROM oauth2_refresh_tokens t
		LEFT JOIN oauth2_token_families f ON f.family_id = t.family_id
		WHERE t.token_hash = ?`

	var (
		t                 = &oauth2.RefreshToken{TokenHash: tokenHash}
		consumed          int64
		issuedAt, expires int64
		familyIssuedAt    int64
		revokedAt         sql.NullInt64
	)

	row := s.db.QueryRowContext(ctx, s.dialect.rebind(q), tokenHash)
	if err := row.Scan(&t.ClientID, &t.Subject, &t.Scope, &t.FamilyID,
		&consumed, &issuedAt, &expires, &t.Issuer, &t.ExtensionData, &familyIssuedAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
		}

		return nil, fmt.Errorf("sqlstore: lookup refresh token: %w", err)
	}

	t.Consumed = consumed != 0 || t.FamilyID == "" || !familyActive(t.FamilyID, revokedAt)
	t.IssuedAt = time.Unix(issuedAt, 0)
	t.ExpiresAt = time.Unix(expires, 0)
	t.FamilyIssuedAt = timeOrZero(familyIssuedAt)

	return t, nil
}

// RotateRefreshToken implements [oauth2.RefreshTokenStore] in one
// transaction:
//
//  1. Lock next's family — recording it revoked if unknown, since a
//     rotation never creates an active family — then read the old token
//     under lock.
//  2. Decide in the contract's order: unknown old token (invalid_grant),
//     next in another family or carrying another grant context — issuer,
//     extension data — (invalid_request), revoked family
//     ([oauth2.ErrTokenFamilyRevoked]), consumed old token (reuse).
//  3. On reuse, record the family revoked and commit. A failure there is
//     reported as [oauth2.ErrRefreshTokenReused] joined with
//     [oauth2.ErrTokenFamilyRevocationFailed] and its cause.
//  4. Otherwise consume the old token, extend the family's retention,
//     insert next and commit.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, next *oauth2.TokenPair) error {
	if err := validateRotation(next); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, s.dialect.txOptions())
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}

	defer func() { _ = tx.Rollback() }() // a no-op once committed

	reused, err := s.rotateTx(ctx, tx, oldHash, next)
	if err != nil {
		return err
	}

	if reused {
		return s.revokeReused(ctx, tx, next.Access.FamilyID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}

	return nil
}

// RevokeRefreshFamily implements [oauth2.RefreshTokenStore]: one
// transaction records the family revoked — inserting the record if the
// family is unknown, keeping the time of a first revocation otherwise —
// and extends its retention to [oauth2.FamilyRevocationRetention] from
// now. A failure wraps [oauth2.ErrTokenFamilyRevocationFailed].
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	if err := checkFamilyID(familyID); err != nil {
		return err
	}

	err := s.inTx(ctx, func(tx *sql.Tx) error {
		now := time.Now()

		if err := s.recordFamily(ctx, tx, familyID, now.Unix(), retentionFloor(now)); err != nil {
			return err
		}

		return s.markRevoked(ctx, tx, familyID, now)
	})
	if err != nil {
		return revocationFailed(familyID, err)
	}

	return nil
}

// --- transaction steps -----------------------------------------------------

// inTx runs fn in a transaction with the dialect's options, committing when
// fn succeeds and rolling back otherwise. fn uses tx only: with a
// single-connection pool, touching s.db while the transaction is open
// would deadlock.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, s.dialect.txOptions())
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()

		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}

	return nil
}

// recordFamily inserts the record (familyID, revokedAt, expiresAt) unless
// the family already has one. It is the first statement of every write
// transaction on a family: a write first takes SQLite's write lock before
// anything is read.
func (s *Store) recordFamily(ctx context.Context, tx *sql.Tx, familyID string, revokedAt, expiresAt int64) error {
	if _, err := tx.ExecContext(ctx, s.dialect.rebind(s.dialect.insertFamily()),
		familyID, revokedAt, expiresAt); err != nil {
		return fmt.Errorf("sqlstore: record token family: %w", err)
	}

	return nil
}

// lockFamily records familyID with revokedAt and expiresAt unless it
// exists, then reads whether it is revoked under a row lock. A record
// missing even then reads as revoked.
func (s *Store) lockFamily(ctx context.Context, tx *sql.Tx, familyID string, revokedAt, expiresAt int64) (bool, error) {
	if err := s.recordFamily(ctx, tx, familyID, revokedAt, expiresAt); err != nil {
		return false, err
	}

	var current int64

	err := tx.QueryRowContext(ctx, s.dialect.rebind(s.dialect.lockFamily()), familyID).Scan(&current)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("sqlstore: lock token family: %w", err)
	default:
		return current != 0, nil
	}
}

// joinFamily locks familyID for an issuance, recording it active until
// expiresAt when unknown: a revoked family refuses the issuance, an active
// one has its retention extended to expiresAt.
func (s *Store) joinFamily(ctx context.Context, tx *sql.Tx, familyID string, expiresAt int64) error {
	revoked, err := s.lockFamily(ctx, tx, familyID, 0, expiresAt)
	if err != nil {
		return err
	}

	if revoked {
		return oauth2.ErrTokenFamilyRevoked
	}

	return s.extendFamily(ctx, tx, familyID, expiresAt)
}

// rotateTx runs the reads of a rotation and, unless the old token was
// already consumed, its writes; it reports a reuse to the caller, which
// owns the transaction.
func (s *Store) rotateTx(ctx context.Context, tx *sql.Tx, oldHash string, next *oauth2.TokenPair) (bool, error) {
	familyID := next.Access.FamilyID
	now := time.Now()

	revoked, err := s.lockFamily(ctx, tx, familyID, now.Unix(), retentionFloor(now))
	if err != nil {
		return false, err
	}

	var (
		old      grantRow
		consumed int64
	)

	err = tx.QueryRowContext(ctx, s.dialect.rebind(s.dialect.lockRefresh()), oldHash).
		Scan(&old.familyID, &consumed, &old.issuer, &old.extensionData)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, oauth2.ErrInvalidGrant.WithDescription("refresh token not found")
	case err != nil:
		return false, fmt.Errorf("sqlstore: lock refresh token: %w", err)
	case old.familyID != familyID:
		return false, oauth2.ErrInvalidRequest.WithDescription("sqlstore: rotation into another token family")
	case old.issuer != next.Access.Issuer || old.extensionData != next.Access.ExtensionData:
		return false, oauth2.ErrInvalidRequest.WithDescription("sqlstore: rotation into another grant context")
	case revoked:
		return false, oauth2.ErrTokenFamilyRevoked
	case consumed != 0:
		return true, nil
	}

	return false, s.consumeAndInsert(ctx, tx, oldHash, next)
}

// consumeAndInsert applies a rotation rotateTx cleared: it consumes the
// old token, extends the family's retention to next's tokens and inserts
// them.
func (s *Store) consumeAndInsert(ctx context.Context, tx *sql.Tx, oldHash string, next *oauth2.TokenPair) error {
	res, err := tx.ExecContext(ctx, s.dialect.rebind(
		`UPDATE oauth2_refresh_tokens SET consumed = 1 WHERE token_hash = ? AND consumed = 0`), oldHash)
	if err != nil {
		return fmt.Errorf("sqlstore: consume refresh token: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlstore: rows affected: %w", err)
	}

	// The token was read unconsumed under lock: any other count means the
	// lock did not hold, and the rotation must not go on.
	if affected != 1 {
		return fmt.Errorf("sqlstore: consume refresh token: %d rows affected", affected)
	}

	if err := s.extendFamily(ctx, tx, next.Access.FamilyID, pairExpiry(next)); err != nil {
		return err
	}

	return s.insertPair(ctx, tx, next)
}

// revokeReused answers a reuse rotateTx detected: within the rotation's
// transaction, which holds the family lock, it records the family revoked
// and commits, then reports the reuse.
func (s *Store) revokeReused(ctx context.Context, tx *sql.Tx, familyID string) error {
	err := s.markRevoked(ctx, tx, familyID, time.Now())
	if err == nil {
		err = tx.Commit()
	}

	if err != nil {
		return fmt.Errorf("%w: %w", oauth2.ErrRefreshTokenReused, revocationFailed(familyID, err))
	}

	return oauth2.ErrRefreshTokenReused
}

// markRevoked records familyID revoked — keeping the time of a first
// revocation — and extends its retention to the floor a revocation
// guarantees.
func (s *Store) markRevoked(ctx context.Context, tx *sql.Tx, familyID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, s.dialect.rebind(
		`UPDATE oauth2_token_families SET revoked_at = ? WHERE family_id = ? AND revoked_at = 0`),
		now.Unix(), familyID); err != nil {
		return fmt.Errorf("sqlstore: mark token family revoked: %w", err)
	}

	return s.extendFamily(ctx, tx, familyID, retentionFloor(now))
}

// extendFamily raises familyID's retention to until; it never lowers it.
func (s *Store) extendFamily(ctx context.Context, tx *sql.Tx, familyID string, until int64) error {
	if _, err := tx.ExecContext(ctx, s.dialect.rebind(
		`UPDATE oauth2_token_families SET expires_at = ? WHERE family_id = ? AND expires_at < ?`),
		until, familyID, until); err != nil {
		return fmt.Errorf("sqlstore: extend token family: %w", err)
	}

	return nil
}

// insertPair inserts the tokens of pair.
func (s *Store) insertPair(ctx context.Context, tx *sql.Tx, pair *oauth2.TokenPair) error {
	at := &pair.Access

	if _, err := tx.ExecContext(ctx, s.dialect.rebind(`INSERT INTO oauth2_access_tokens
		(token_hash, client_id, subject, scope, family_id, audience, issued_at, expires_at,
		 issuer, extension_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		at.TokenHash, at.ClientID, at.Subject, at.Scope, at.FamilyID, at.Audience,
		at.IssuedAt.Unix(), at.ExpiresAt.Unix(), at.Issuer, at.ExtensionData); err != nil {
		return fmt.Errorf("sqlstore: insert access token: %w", err)
	}

	rt := pair.Refresh
	if rt == nil {
		return nil
	}

	if _, err := tx.ExecContext(ctx, s.dialect.rebind(`INSERT INTO oauth2_refresh_tokens
		(token_hash, client_id, subject, scope, family_id, consumed, issued_at, expires_at,
		 issuer, extension_data, family_issued_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`),
		rt.TokenHash, rt.ClientID, rt.Subject, rt.Scope, rt.FamilyID,
		rt.IssuedAt.Unix(), rt.ExpiresAt.Unix(), rt.Issuer, rt.ExtensionData,
		unixOrZero(rt.FamilyIssuedAt)); err != nil {
		return fmt.Errorf("sqlstore: insert refresh token: %w", err)
	}

	return nil
}

// --- helpers ---------------------------------------------------------------

// grantRow is what a rotation reads of the presented refresh token under
// lock: its family and its grant context, which the replacement must keep.
type grantRow struct {
	familyID      string
	issuer        string
	extensionData string
}

// unixOrZero is the Unix second a BIGINT time column stores, 0 for the
// zero time — never the negative second of year 1.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}

// timeOrZero reads a BIGINT time column: 0 is the zero time, not the epoch.
func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}

	return time.Unix(sec, 0)
}

// flag is the SMALLINT a boolean column stores: 1 for true, 0 for false.
func flag(b bool) int {
	if b {
		return 1
	}

	return 0
}

// familyActive reports whether a token of familyID may be used: it is
// outside any family, or its family's record says active. A NULL revokedAt
// — no record joined — reads as revoked: a lookup never takes a lost family
// for an active one.
func familyActive(familyID string, revokedAt sql.NullInt64) bool {
	if familyID == "" {
		return true
	}

	return revokedAt.Valid && revokedAt.Int64 == 0
}

// pairExpiry is the Unix second the family of pair must be retained
// until: the later of the pair's token expiries.
func pairExpiry(pair *oauth2.TokenPair) int64 {
	until := pair.Access.ExpiresAt.Unix()

	if pair.Refresh != nil && pair.Refresh.ExpiresAt.Unix() > until {
		until = pair.Refresh.ExpiresAt.Unix()
	}

	return until
}

// retentionFloor is the Unix second a family revoked at now is retained
// until, at least.
func retentionFloor(now time.Time) int64 {
	return now.Add(oauth2.FamilyRevocationRetention).Unix()
}

// validateRotation refuses a malformed rotation target before anything
// runs: nil, failing [oauth2.TokenPair.Validate], or without the refresh
// token a rotation issues.
func validateRotation(next *oauth2.TokenPair) error {
	if err := next.Validate(); err != nil {
		return fmt.Errorf("sqlstore: rotate refresh token: %w", err)
	}

	if next.Refresh == nil {
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: rotation without a refresh token")
	}

	return nil
}

// checkFamilyID refuses a family ID no family can have: empty, which would
// reach every token outside a family, or longer than
// [oauth2.MaxFamilyIDLength].
func checkFamilyID(familyID string) error {
	switch {
	case familyID == "":
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: empty token family id")
	case len(familyID) > oauth2.MaxFamilyIDLength:
		return oauth2.ErrInvalidRequest.WithDescription("sqlstore: token family id too long")
	default:
		return nil
	}
}

// revocationFailed reports a family revocation that could not be recorded:
// the family ID, then [oauth2.ErrTokenFamilyRevocationFailed], then the
// cause.
func revocationFailed(familyID string, err error) error {
	return fmt.Errorf("sqlstore: revoke family %q: %w: %w", familyID, oauth2.ErrTokenFamilyRevocationFailed, err)
}

// Compile-time interface check.
var _ oauth2.Storage = (*Store)(nil)
