// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package throttle ships MemoryLimiter, a bounded, in-memory
// [security.AttemptLimiter]: the control against online guessing that
// NIST SP 800-63B-4 §3.2.2 requires of verifiers, and the brute-force
// protection RFC 6749 §2.3.1 and §4.3.2 require of OAuth 2.0 endpoints
// that check a secret.
//
// Every attempt is charged to up to three budgets, checked and charged
// together under one lock, before the credentials are verified:
//
//   - PerSubjectSource — one subject (a username, a client_id) from one
//     source: what one client may try against one account;
//   - PerSubject — one subject from every source: the per-account limit
//     NIST asks for, which also lets a distributed attacker lock the
//     account out for as long as the attack lasts;
//   - PerSource — one source against every subject: password spraying,
//     and the number of entries one source can create.
//
// Each budget allows a burst of Limit.Failures attempts, then one more
// every Window/Failures (a generic cell rate algorithm: one timestamp per
// entry). A refused attempt charges nothing. Sources count per IPv4
// address and per IPv6 /56 by default (RFC 6177: end sites are assigned
// far more than one /64, commonly a /56).
//
// Use one MemoryLimiter per credential type, configured for it: HTTP Basic
// passwords keep the three budgets; OAuth 2.0 client authentication, whose
// client identifiers are public and whose secrets are high-entropy, turns
// the per-subject budget off — Limit{Failures: Unlimited} — so that nobody
// can lock a client out from other sources. An attempt from an unknown
// source meets only the per-subject budget; with that budget off, no budget
// applies and Allow refuses it as unavailable (503): supply the client
// address. Call Allow once per attempt — every budget, the per-source one
// included, is charged by that one call.
//
// MemoryLimiter is a throttle, not the lock-out of NIST SP 800-63B-4
// §3.2.2 ("no more than 100 [consecutive failed attempts] by disabling
// that authenticator"): its state lives in one process and is lost at
// restart, so the absolute cap needs persistent state — an AttemptLimiter
// over your account store, or an account flag the user loader reports
// locked. Each instance of a deployment keeps its own budgets.
//
// The package depends on the standard library and the core only.
package throttle
