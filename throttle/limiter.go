// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package throttle

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/hyperscale-stack/security"
)

// Unlimited turns a budget off: Limit{Failures: Unlimited}.
const Unlimited = -1

// Defaults of the zero fields of a [Config].
const (
	// DefaultMaxKeys bounds the entries a MemoryLimiter tracks — about
	// 12 MiB when full.
	DefaultMaxKeys = 100_000
	// DefaultIPv6PrefixLen is the IPv6 prefix a source counts as: a /56,
	// the common end-site assignment (RFC 6177).
	DefaultIPv6PrefixLen = 56
)

// Bounds of Config.IPv6PrefixLen and Config.MaxKeys.
const (
	minIPv6PrefixLen = 48
	maxIPv6PrefixLen = 64
	// minMaxKeys: one attempt charges up to three entries.
	minMaxKeys = 3
)

// Limit is the allowance of one budget: a burst of Failures failed
// attempts, then one more every Window/Failures — the allowance refills
// linearly over Window. The zero Limit takes the budget's default;
// Limit{Failures: Unlimited} turns the budget off.
type Limit struct {
	Failures int
	Window   time.Duration
}

// Config configures [NewMemoryLimiter]. Its zero value is the default
// configuration.
//
// Sources count per IPv4 address and per IPv6 /56: clients behind one
// IPv4 address (a NAT, a proxy) or in one /56 (providers numbering
// customers inside one /56, a NAT64 or SIIT translator mapping every IPv4
// client into one prefix) share the per-source budgets. Behind such a
// translator, store the embedded IPv4 address with
// [security.WithClientAddr].
type Config struct {
	// PerSubjectSource bounds the attempts of one subject from one source.
	// Default: 10 per 15 minutes.
	PerSubjectSource Limit
	// PerSubject bounds the attempts of one subject from every source —
	// the per-account limit of NIST SP 800-63B-4 §3.2.2 — and is the only
	// budget an attempt from an unknown source meets. A distributed
	// attacker exhausting it locks the account out while the attack
	// lasts: turn it off (Unlimited) for credentials that cannot be
	// guessed, such as OAuth 2.0 client secrets; an attempt from an
	// unknown source is then refused as unavailable. Default: 100 per
	// hour.
	PerSubject Limit
	// PerSource bounds the attempts of one source against every subject
	// (password spraying, and the entries one source can create). Clients
	// behind one address — a NAT, a proxy — share it. Default: 100 per
	// 15 minutes.
	PerSource Limit
	// IPv6PrefixLen is the prefix an IPv6 source counts as, 48 to 64.
	// Default: 56 (RFC 6177). IPv4 sources count per address.
	IPv6PrefixLen int
	// MaxKeys bounds the entries tracked, at least 3. When the table is
	// full the least throttled entry is forgotten. Default: 100 000.
	MaxKeys int
	// Clock reads the time. Default: security.SystemClock{}.
	Clock security.Clock
}

// MemoryLimiter is a bounded, in-memory [security.AttemptLimiter] for one
// process. It never stores a subject: each entry is keyed by a 128-bit
// truncated SHA-256 of its budget, realm, subject and source, and holds one
// timestamp. Entries whose charges have all expired are purged; when the
// table holds MaxKeys entries, the one closest to recovery — the least
// throttled — is forgotten to make room, never an entry of the attempt
// being charged, so a flood of fresh keys forgets a throttled key only
// after MaxKeys more throttled keys. Allow returns an error wrapping
// [security.ErrUnavailable] only when no configured budget applies to the
// key (see Allow).
//
// Create it with NewMemoryLimiter: the zero value is not usable.
// MemoryLimiter is safe for concurrent use.
type MemoryLimiter struct {
	budgets [budgetCount]budget
	prefix6 int
	maxKeys int
	clock   security.Clock

	mu      sync.Mutex
	entries map[digest]*entry
	heap    entryHeap
}

// Compile-time interface check.
var _ security.AttemptLimiter = (*MemoryLimiter)(nil)

// NewMemoryLimiter returns a MemoryLimiter configured by cfg. It panics on
// a configuration that would limit nothing while looking like a limit — a
// Limit with only one of its fields set, a negative value, a Window too
// short to give each attempt a positive interval, Unlimited with a
// Window — and on a MaxKeys below 3 or an IPv6PrefixLen outside 48–64:
// limits are static configuration, refused at start-up.
func NewMemoryLimiter(cfg Config) *MemoryLimiter {
	l := &MemoryLimiter{
		budgets: [budgetCount]budget{
			perSubjectSource: newBudget("PerSubjectSource", cfg.PerSubjectSource, Limit{10, 15 * time.Minute}),
			perSubject:       newBudget("PerSubject", cfg.PerSubject, Limit{100, time.Hour}),
			perSource:        newBudget("PerSource", cfg.PerSource, Limit{100, 15 * time.Minute}),
		},
		prefix6: orDefault(cfg.IPv6PrefixLen, DefaultIPv6PrefixLen),
		maxKeys: orDefault(cfg.MaxKeys, DefaultMaxKeys),
		clock:   cfg.Clock,
		entries: make(map[digest]*entry),
	}

	switch {
	case l.prefix6 < minIPv6PrefixLen || l.prefix6 > maxIPv6PrefixLen:
		panic(fmt.Sprintf("throttle: IPv6PrefixLen %d is outside %d–%d", cfg.IPv6PrefixLen, minIPv6PrefixLen, maxIPv6PrefixLen))
	case l.maxKeys < minMaxKeys:
		panic(fmt.Sprintf("throttle: MaxKeys %d is below %d", cfg.MaxKeys, minMaxKeys))
	case isNil(l.clock) && l.clock != nil:
		panic("throttle: typed-nil Clock")
	case l.clock == nil:
		l.clock = security.SystemClock{}
	}

	return l
}

// errNoBudget refuses an attempt no configured budget applies to.
var errNoBudget = fmt.Errorf("throttle: no budget applies to an attempt from an unknown source: %w", security.ErrUnavailable)

// limits reports whether at least one budget is configured.
func (l *MemoryLimiter) limits() bool {
	for _, b := range l.budgets {
		if b.enabled {
			return true
		}
	}

	return false
}

// orDefault returns v, or def when v is zero.
func orDefault(v, def int) int {
	if v == 0 {
		return def
	}

	return v
}

// Allow implements [security.AttemptLimiter]. It admits the attempt and
// charges it to every applicable budget when they all have room, and
// otherwise refuses it with a [*security.TooManyAttemptsError] whose
// RetryAfter is the longest wait among the refusing budgets — charging
// nothing. A zero Source skips the two source budgets; when budgets are
// configured but none applies to the key — an unknown source with the
// per-subject budget off, as for OAuth 2.0 client authentication — the
// attempt cannot be limited and is refused with an error wrapping
// [security.ErrUnavailable] (503): fail closed until the client address is
// supplied ([security.WithClientAddr]).
func (l *MemoryLimiter) Allow(_ context.Context, key security.AttemptKey) error {
	slots := l.slots(key)
	if len(slots) == 0 && l.limits() {
		return errNoBudget
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()
	l.purge(now)

	var wait time.Duration

	for _, s := range slots {
		if e := l.entries[s.digest]; e != nil {
			wait = max(wait, e.tat.Sub(now)-l.budgets[s.budget].tolerance)
		}
	}

	if wait > 0 {
		return &security.TooManyAttemptsError{RetryAfter: wait}
	}

	l.makeRoom(slots)

	for _, s := range slots {
		l.charge(s, now)
	}

	return nil
}

// Record implements [security.AttemptLimiter]. It settles one outstanding
// reservation of the key: AttemptFailed keeps its charges;
// AttemptSucceeded forgets the failures of its (subject, source) entry and
// refunds its charge to the subject and source budgets — it does not reset
// them, so that an account in use does not clear what other sources spent;
// and AttemptInconclusive refunds every charge. Any other outcome counts as
// failed. Reservations are counted per key, not told apart: a Record
// without an outstanding reservation — a second one, or one whose entries
// expired or were forgotten — changes nothing, but a late Record arriving
// after its own entry expired may settle a newer reservation of the same
// key. A burst can then exceed Failures by the number of such late
// settlements; the long-run rate is never exceeded.
func (l *MemoryLimiter) Record(_ context.Context, key security.AttemptKey, outcome security.AttemptOutcome) {
	slots := l.slots(key)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock.Now()
	l.purge(now)

	for _, s := range slots {
		e := l.entries[s.digest]
		if e == nil || e.pending == 0 {
			continue
		}

		e.pending--

		switch {
		case outcome == security.AttemptSucceeded && s.budget == perSubjectSource:
			l.remove(e)
		case outcome == security.AttemptSucceeded, outcome == security.AttemptInconclusive:
			l.refund(e, l.budgets[s.budget].interval, now)
		}
	}
}

// charge reserves one attempt on the entry of s, creating it.
func (l *MemoryLimiter) charge(s slot, now time.Time) {
	interval := l.budgets[s.budget].interval

	e := l.entries[s.digest]
	if e == nil {
		e = &entry{key: s.digest, tat: now.Add(interval), pending: 1}
		l.entries[s.digest] = e
		heap.Push(&l.heap, e)

		return
	}

	// purge left no entry at or before now: the charge extends its TAT.
	e.tat = e.tat.Add(interval)
	e.pending++
	heap.Fix(&l.heap, e.index)
}

// refund gives one charge back to e, never below now: an entry left with
// no charge is removed.
func (l *MemoryLimiter) refund(e *entry, interval time.Duration, now time.Time) {
	e.tat = e.tat.Add(-interval)
	if !e.tat.After(now) {
		l.remove(e)

		return
	}

	heap.Fix(&l.heap, e.index)
}

// purge removes the entries whose every charge has expired: they carry
// nothing an absent entry does not.
func (l *MemoryLimiter) purge(now time.Time) {
	for len(l.heap) > 0 && !l.heap[0].tat.After(now) {
		l.remove(l.heap[0])
	}
}

// makeRoom forgets the least throttled entries until the entries the
// attempt creates fit within maxKeys. The entries of the attempt itself
// are never forgotten.
func (l *MemoryLimiter) makeRoom(slots []slot) {
	missing := 0

	for _, s := range slots {
		if l.entries[s.digest] == nil {
			missing++
		}
	}

	var spared []*entry

	for len(l.entries)+missing > l.maxKeys && len(l.heap) > 0 {
		e, _ := heap.Pop(&l.heap).(*entry)

		if slices.ContainsFunc(slots, func(s slot) bool { return s.digest == e.key }) {
			spared = append(spared, e)

			continue
		}

		delete(l.entries, e.key)
	}

	for _, e := range spared {
		heap.Push(&l.heap, e)
	}
}

// remove deletes e from the table.
func (l *MemoryLimiter) remove(e *entry) {
	heap.Remove(&l.heap, e.index)
	delete(l.entries, e.key)
}

// budgetID names the budgets.
type budgetID uint8

const (
	perSubjectSource budgetID = iota
	perSubject
	perSource
	budgetCount
)

// budget is a Limit turned into the generic cell rate algorithm's
// parameters: an attempt adds interval to the entry's theoretical arrival
// time (TAT), and is refused when the TAT is more than tolerance ahead of
// now — Failures attempts in a burst.
type budget struct {
	enabled   bool
	interval  time.Duration
	tolerance time.Duration
}

// newBudget validates lim, the zero Limit taking def.
func newBudget(name string, lim, def Limit) budget {
	switch {
	case lim == Limit{}:
		lim = def
	case lim.Failures == Unlimited && lim.Window == 0:
		return budget{}
	case lim.Failures < 1 || lim.Window <= 0:
		panic(fmt.Sprintf("throttle: %s: %d failures over %s: both must be positive, or Failures Unlimited alone",
			name, lim.Failures, lim.Window))
	}

	interval := lim.Window / time.Duration(lim.Failures)
	if interval <= 0 {
		panic(fmt.Sprintf("throttle: %s: a window of %s is too short for %d failures", name, lim.Window, lim.Failures))
	}

	return budget{enabled: true, interval: interval, tolerance: interval * time.Duration(lim.Failures-1)}
}

// digest is the key of an entry: SHA-256 truncated to 128 bits.
type digest [16]byte

// slot is one budget an attempt is charged to, and the entry it uses.
type slot struct {
	budget budgetID
	digest digest
}

// slots returns the entries key is charged to, computed outside the lock:
// one per enabled budget, the source budgets only for a known source.
func (l *MemoryLimiter) slots(key security.AttemptKey) []slot {
	src, known := l.source(key)

	out := make([]slot, 0, budgetCount)

	for id := range budgetCount {
		if !l.budgets[id].enabled || (id != perSubject && !known) {
			continue
		}

		out = append(out, slot{budget: id, digest: hashKey(id, key, src)})
	}

	return out
}

// source returns the 18 bytes identifying the source's aggregate — the
// family, the prefix length and the masked address —, or false when the
// source is unknown.
func (l *MemoryLimiter) source(key security.AttemptKey) ([18]byte, bool) {
	var out [18]byte

	addr := key.Source.Unmap().WithZone("")
	if !addr.IsValid() {
		return out, false
	}

	bits := 32
	if addr.Is6() {
		bits = l.prefix6
	}

	prefix, _ := addr.Prefix(bits) // fails only for a length beyond the address

	out[0], out[1] = byte(addr.BitLen()), byte(bits) //nolint:gosec // G115: 32, 128 and 48–64 fit a byte

	masked := prefix.Addr().As16()
	copy(out[2:], masked[:])

	return out, true
}

// hashKey derives the digest of a budget's entry from the length-prefixed
// realm and subject and the source aggregate — only the parts that budget
// keys on.
func hashKey(id budgetID, key security.AttemptKey, src [18]byte) digest {
	h := sha256.New()

	_, _ = h.Write([]byte{byte(id)})

	writeField(h, key.Realm)

	if id != perSource {
		writeField(h, key.Subject)
	}

	if id != perSubject {
		_, _ = h.Write(src[:])
	}

	var d digest

	copy(d[:], h.Sum(nil))

	return d
}

// writeField writes s with a 64-bit length prefix, so that no two (realm,
// subject) pairs give the same input.
func writeField(h interface{ Write(p []byte) (int, error) }, s string) {
	_, _ = h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(s))))
	_, _ = h.Write([]byte(s))
}

// entry is the state of one budget for one key: its theoretical arrival
// time and its reservations not yet settled.
type entry struct {
	key     digest
	tat     time.Time
	pending int
	index   int
}

// entryHeap orders the entries by TAT, the least throttled first.
type entryHeap []*entry

func (h entryHeap) Len() int           { return len(h) }
func (h entryHeap) Less(i, j int) bool { return h[i].tat.Before(h[j].tat) }

func (h entryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}

func (h *entryHeap) Push(x any) {
	e, _ := x.(*entry)
	e.index = len(*h)
	*h = append(*h, e)
}

func (h *entryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	e.index = -1

	return e
}

// nilableKinds are the kinds whose zero value is a nil a method call can
// dereference.
var nilableKinds = []reflect.Kind{
	reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer,
}

// isNil reports whether v is nil or a typed nil — an interface holding a
// nil pointer, map, slice, function or channel. The core, its adapters and
// this package hold the same unexported helper: it stays out of the core's
// API.
func isNil(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)

	return slices.Contains(nilableKinds, rv.Kind()) && rv.IsNil()
}
