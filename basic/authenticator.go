// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package basic

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/hyperscale-stack/security"
	"github.com/hyperscale-stack/security/password"
)

// UnlimitedVerifications removes the cap on concurrent password
// verifications: WithMaxConcurrentVerifications(UnlimitedVerifications).
// Use it only with a hasher whose Verify is neither CPU- nor memory-bound
// (one calling a remote HSM, say): bcrypt and Argon2id gain nothing from
// running more verifications than there are cores — only latency and
// memory.
const UnlimitedVerifications = -1

// AuthorityResolver maps a [PasswordUser] to the authorities (roles, scopes,
// claims) attached to the resulting [security.Authentication]. The default
// resolver returns nil; applications that ship role-based authorization
// provide one that reads the authorities from the user record. Name roles
// [security.RolePrefix] + role ("ROLE_ADMIN") and scopes one
// [security.ScopePrefix] + scope authority each ("scope:read"): that is
// what voter.HasRole and voter.HasScope match.
type AuthorityResolver func(PasswordUser) []string

// Authenticator implements [security.Authenticator] for the HTTP Basic
// scheme. It loads the user via a [UserLoader], verifies the password with a
// [password.Hasher], checks the account's lifecycle flags, then returns the
// authenticated [Authentication].
//
// Credentials that are malformed — control, format (Cf) or separator (Zl,
// Zp) characters, invalid UTF-8, more than 3072 bytes, an empty user-id —
// are refused with [ErrBadFormat] before any lookup: a form login building
// the [Authentication] with [New] gets the same checks as the [Extractor].
//
// Every attempt with well-formed credentials runs exactly one password
// verification, whatever the account: an unknown user, a loader failure or
// an account without a password hash is verified against a dummy hash the
// hasher made at construction, and the lifecycle flags (disabled, locked,
// expired) are read only after the verification. The response time therefore does not
// tell which accounts exist or are locked (CWE-208), and every refusal
// wraps [security.ErrInvalidCredentials] — the detailed cause stays in the
// error chain for server-side telemetry only: do NOT mirror it in the
// client response. A [UserLoader] error wrapping [security.ErrUnavailable]
// keeps it, and [security.ErrorClass] ranks the outage first: a user store
// that is down is answered 503 / Unavailable for every username, not
// refused.
//
// The equalization holds for stored hashes made with the hasher's current
// algorithm and parameters: configure the hasher with the parameters of
// your stored hashes, and let a [PasswordRehasher] loader upgrade the ones
// that differ — a hash at other parameters costs another time to verify
// than the dummy.
//
// Since every attempt costs a hash, at most runtime.GOMAXPROCS(0)
// verifications run at once by default ([WithMaxConcurrentVerifications]):
// further attempts wait for a slot, so a flood of attempts cannot exhaust
// memory (an Argon2id verification with the default parameters allocates
// 19 MiB). Limit the failed attempts per account and per client with
// [WithAttemptLimiter] (NIST SP 800-63B-4 §3.2.2).
type Authenticator struct {
	loader     UserLoader
	hasher     password.Hasher
	authResolv AuthorityResolver
	dummyHash  string
	maxVerify  int
	slots      chan struct{} // nil: unlimited
	limiter    security.AttemptLimiter
	subject    func(username string) string
}

// attemptRealm is the realm of the AttemptKey of a Basic attempt.
const attemptRealm = "basic"

// NewAuthenticator returns an Authenticator using the supplied loader and
// hasher. Authorities default to nil (use [WithAuthorityResolver] to
// populate them from the user record).
//
// It hashes a random password once with hasher — the dummy hash that
// unknown accounts are verified against — so construction costs one hash:
// build the Authenticator once, not per request. It panics on a nil loader
// or hasher — a typed nil included —, and when hasher cannot hash: an
// Authenticator without its dummy hash would answer unknown accounts faster
// than known ones.
func NewAuthenticator(loader UserLoader, hasher password.Hasher, opts ...Option) *Authenticator {
	if isNil(loader) {
		panic("basic: NewAuthenticator: nil UserLoader")
	}

	if isNil(hasher) {
		panic("basic: NewAuthenticator: nil password.Hasher")
	}

	a := &Authenticator{loader: loader, hasher: hasher, maxVerify: runtime.GOMAXPROCS(0), subject: strings.ToLower}

	for _, o := range opts {
		o(a)
	}

	if a.maxVerify != UnlimitedVerifications {
		a.slots = make(chan struct{}, a.maxVerify)
	}

	dummy, err := hasher.Hash(context.Background(), rand.Text())
	if err != nil {
		panic("basic: NewAuthenticator: the hasher cannot make the dummy hash: " + err.Error())
	}

	a.dummyHash = dummy

	return a
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithAuthorityResolver overrides the resolver mapping a [PasswordUser] to
// the authorities materialized on the [Authentication].
func WithAuthorityResolver(r AuthorityResolver) Option {
	return func(a *Authenticator) { a.authResolv = r }
}

// WithMaxConcurrentVerifications runs at most n password verifications at
// once — the dummy ones included. Default: runtime.GOMAXPROCS(0).
// [UnlimitedVerifications] removes the cap. An attempt waits for a slot
// until its context ends, then fails with an error wrapping
// [security.ErrUnavailable] (HTTP 503 / Unavailable): an overloaded
// verifier is not a verdict on the credentials. net/http request contexts
// carry no deadline — a queued attempt waits as long as its client stays
// connected — so bound the request time (http.TimeoutHandler, a deadline
// middleware). It panics unless n ≥ 1 or n is UnlimitedVerifications.
func WithMaxConcurrentVerifications(n int) Option {
	if n < 1 && n != UnlimitedVerifications {
		panic(fmt.Sprintf("basic: WithMaxConcurrentVerifications: %d is neither ≥ 1 nor UnlimitedVerifications", n))
	}

	return func(a *Authenticator) { a.maxVerify = n }
}

// WithAttemptLimiter limits the failed attempts with l — the online-guessing
// control NIST SP 800-63B-4 §3.2.2 requires. Each well-formed attempt is
// admitted by l before the user is looked up, keyed by the realm "basic",
// the user-id normalized by [WithAttemptSubject] and the client address of
// the request context ([security.ClientAddrFromContext], which the
// transport adapters fill in). A refused attempt fails with l's error —
// [security.ErrTooManyAttempts]: HTTP 429, gRPC ResourceExhausted — before
// any lookup or verification; an error of l that is not a throttle answers
// [security.ErrUnavailable] (fail closed). Each admitted attempt is then
// settled: a success with security.AttemptSucceeded, an outage of the user
// store or of the verification with security.AttemptInconclusive, every
// other refusal — wrong password, unknown, disabled or locked account
// alike, so that the limiter reveals no account — with
// security.AttemptFailed, on a context a canceled request does not cancel.
//
// Outside the transport adapters — a form login calling Authenticate —
// store the client address in the context ([security.WithClientAddr]):
// without it the source is unknown and only the limiter's per-subject
// allowance applies. An attempt holds its reservation while it waits for a
// verification slot: size the allowance above a client's concurrency, or
// exchange the credentials once for a session or a token. Another verifier
// of the same passwords (an OAuth 2.0 password grant) keys its attempts in
// its own realm: give it the same limiter knowingly, each realm has its own
// allowance. Default: no limiter. It panics on a nil limiter, a typed nil
// included.
func WithAttemptLimiter(l security.AttemptLimiter) Option {
	if isNil(l) {
		panic("basic: WithAttemptLimiter: nil AttemptLimiter")
	}

	return func(a *Authenticator) { a.limiter = l }
}

// WithAttemptSubject sets how a user-id becomes the subject of an
// [security.AttemptKey]. normalize MUST map every user-id your [UserLoader]
// resolves to one account to one value: variants counted apart multiply the
// allowance (a store comparing case- and accent-insensitively, a loader
// applying NFC). Default: strings.ToLower. It panics on a nil function.
func WithAttemptSubject(normalize func(username string) string) Option {
	if normalize == nil {
		panic("basic: WithAttemptSubject: nil function")
	}

	return func(a *Authenticator) { a.subject = normalize }
}

// AuthenticatorName implements [security.NamedAuthenticator] so the core
// Manager can attribute spans to "basic".
func (a *Authenticator) AuthenticatorName() string { return schemeLabel }

// Supports reports whether auth is a [basic.Authentication]. Returns false
// for everything else, which lets the [security.Manager] delegate to the
// next authenticator in line.
func (a *Authenticator) Supports(auth security.Authentication) bool {
	_, ok := auth.(Authentication)

	return ok
}

// Authenticate implements [security.Authenticator]. On failure it returns
// [security.Anonymous]: the presented credentials never flow back.
func (a *Authenticator) Authenticate(ctx context.Context, auth security.Authentication) (security.Authentication, error) {
	in, ok := auth.(Authentication)
	if !ok {
		return security.Anonymous(), security.ErrUnsupportedCredential
	}

	// The Extractor's rules again — a form login builds the Authentication
	// from its own fields — plus a non-empty user-id (RFC 8265 §3.1): a
	// property of the input, refused before any lookup or verification.
	if err := checkUserPass(in.Username(), in.Password()); err != nil {
		return security.Anonymous(), err
	}

	if in.Username() == "" {
		return security.Anonymous(), malformed("empty user-id")
	}

	key := a.attemptKey(ctx, in.Username())

	if err := a.allow(ctx, key); err != nil {
		return security.Anonymous(), err
	}

	user, stored, err := a.check(ctx, in.Username(), in.Password())
	a.record(ctx, key, err)

	if err != nil {
		return security.Anonymous(), err
	}

	a.rehash(ctx, user, stored, in.Password())

	var authorities []string
	if a.authResolv != nil {
		authorities = a.authResolv(user)
	}

	return in.WithAuthenticated(user, authorities), nil
}

// check looks the user up and verifies the password — exactly one
// verification, whatever the account — and returns the user and its stored
// hash, or the reason to refuse the attempt.
func (a *Authenticator) check(ctx context.Context, username, pw string) (PasswordUser, string, error) {
	user, loadErr := a.loader.LoadByUsername(ctx, username)

	// A typed nil — `return m[name], nil` over a map of pointers — is an
	// unknown user, never dereferenced.
	stored, hasPassword := "", false
	if loadErr == nil && !isNil(user) {
		stored = user.GetPasswordHash()
		hasPassword = stored != ""
	}

	hash := a.dummyHash
	if hasPassword {
		hash = stored
	}

	match, verifyErr := a.verify(ctx, hash, pw)

	return user, stored, refusal(loadErr, user, hasPassword, match, verifyErr)
}

// attemptKey is the AttemptKey of an attempt by username.
func (a *Authenticator) attemptKey(ctx context.Context, username string) security.AttemptKey {
	if a.limiter == nil {
		return security.AttemptKey{}
	}

	source, _ := security.ClientAddrFromContext(ctx)

	return security.AttemptKey{Realm: attemptRealm, Subject: a.subject(username), Source: source}
}

// allow asks the limiter, if any, to admit the attempt. An error that is
// neither a throttle nor an outage is answered as an outage: fail closed.
func (a *Authenticator) allow(ctx context.Context, key security.AttemptKey) error {
	if a.limiter == nil {
		return nil
	}

	err := a.limiter.Allow(ctx, key)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, security.ErrTooManyAttempts), errors.Is(err, security.ErrUnavailable):
		return fmt.Errorf("basic: %w", err)
	default:
		return fmt.Errorf("basic: attempt limiter: %w (%w)", err, security.ErrUnavailable)
	}
}

// record settles an admitted attempt with the outcome err tells, on a
// context that outlives a canceled request.
func (a *Authenticator) record(ctx context.Context, key security.AttemptKey, err error) {
	if a.limiter == nil {
		return
	}

	outcome := security.AttemptFailed

	switch {
	case err == nil:
		outcome = security.AttemptSucceeded
	case security.ErrorClass(err) == security.ErrorClassUnavailable:
		outcome = security.AttemptInconclusive
	}

	a.limiter.Record(context.WithoutCancel(ctx), key, outcome)
}

// refusal returns the reason to refuse the attempt, or nil. It runs after
// the verification, so every refusal costs the same work. An unavailable
// verifier comes first: it is not a verdict on the account, and answering
// it differently for unknown accounts would reveal them under load.
func refusal(loadErr error, user PasswordUser, hasPassword, match bool, verifyErr error) error {
	switch {
	case verifyErr != nil && unavailable(verifyErr):
		return fmt.Errorf("basic: verify password: %w (%w)", verifyErr, security.ErrUnavailable)
	case loadErr != nil:
		// Loader-level errors (db down, unknown user, ...) collapse to a
		// single ErrInvalidCredentials at the client boundary (an
		// ErrUnavailable the loader wrapped still answers 503). The original
		// error stays in the chain for observability; the typed username
		// does not (it can be a password typed in the wrong field).
		return fmt.Errorf("basic: load user: %w (%w)", loadErr, security.ErrInvalidCredentials)
	case isNil(user):
		return fmt.Errorf("basic: user not found: %w", security.ErrInvalidCredentials)
	case !hasPassword:
		return fmt.Errorf("basic: account without a password hash: %w", security.ErrInvalidCredentials)
	case verifyErr != nil:
		return fmt.Errorf("basic: verify password: %w (%w)", verifyErr, security.ErrInvalidCredentials)
	case !match:
		return fmt.Errorf("basic: password mismatch: %w", security.ErrInvalidCredentials)
	case !user.IsEnabled() || user.IsLocked() || user.IsExpired() || user.IsCredentialsExpired():
		return fmt.Errorf("basic: account ineligible: %w", security.ErrInvalidCredentials)
	}

	return nil
}

// unavailable reports whether a verification error means the credentials
// were not checked: no slot before the context ended, or the context ended
// before the hashing.
func unavailable(err error) bool {
	return errors.Is(err, security.ErrUnavailable) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// verify runs one password verification inside a slot.
func (a *Authenticator) verify(ctx context.Context, hash, pw string) (bool, error) {
	release, err := a.acquire(ctx)
	if err != nil {
		return false, err
	}

	defer release()

	match, err := a.hasher.Verify(ctx, hash, pw)
	if err != nil {
		return false, fmt.Errorf("basic: %w", err)
	}

	return match, nil
}

// acquire waits for a verification slot until ctx ends. A context that has
// already ended never gets a slot (select would pick a free slot or the
// done context at random).
func (a *Authenticator) acquire(ctx context.Context) (func(), error) {
	if a.slots == nil {
		return func() {}, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("basic: no verification slot: %w (%w)", err, security.ErrUnavailable)
	}

	select {
	case a.slots <- struct{}{}:
		return func() { <-a.slots }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("basic: waiting for a verification slot: %w (%w)", ctx.Err(), security.ErrUnavailable)
	}
}

// rehash re-hashes the password of a successfully authenticated user whose
// stored hash NeedsRehash, when the loader can store it. A failure leaves
// the stored hash as it is — the next login tries again — and never fails
// the authentication. It runs only after a success, so it reveals nothing
// about other accounts.
func (a *Authenticator) rehash(ctx context.Context, user PasswordUser, stored, pw string) {
	rehasher, ok := a.loader.(PasswordRehasher)
	if !ok || !a.hasher.NeedsRehash(stored) {
		return
	}

	release, err := a.acquire(ctx)
	if err != nil {
		return
	}

	defer release()

	hash, err := a.hasher.Hash(ctx, pw)
	if err != nil {
		return
	}

	_ = rehasher.UpdatePasswordHash(ctx, user, hash)
}

// Compile-time interface check.
var _ security.Authenticator = (*Authenticator)(nil)
