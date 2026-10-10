// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package redisstore is a Redis implementation of oauth2.Storage. Atomicity
// of ConsumeAuthorizationCode and of the token-family operations is
// guaranteed by Lua scripts loaded via EVALSHA (with EVAL fallback).
//
// # Key layout
//
// Every key starts with the store prefix (WithKeyPrefix, "oauth2:" by
// default):
//
//   - code:{hash}: an authorization code (JSON), until it expires —
//     exchanged or not: an exchanged code stays, flagged consumed, so that
//     a replay of it is recognized.
//   - at:{hash}, rt:{hash}: an access or refresh token (JSON), until it
//     expires.
//   - fam:{id}: the state of a token family, "active" or "revoked", kept at
//     least as long as every token of the family and, once revoked, for
//     oauth2.FamilyRevocationRetention.
//
// # Deployment requirements
//
// The token-family guarantees of oauth2.Storage hold under these
// conditions:
//
//   - Redis 6.0 or later: the rotation and code-consumption scripts use
//     SET … KEEPTTL, which an older server refuses at the script's first
//     write — failing closed.
//   - A standalone server, or the primary of a Sentinel deployment. Redis
//     Cluster is not supported: the scripts touch keys of different hash
//     slots (CROSSSLOT).
//   - Every command reaches the primary: no replica reads, and no
//     client-side caching on the store's client. Either could answer from
//     before a revocation.
//   - Durability is the server's: a revocation acknowledged by a primary
//     that fails before persisting (AOF) or replicating it can be lost in a
//     failover, reviving its tokens. Choose the persistence and failover
//     settings accordingly.
//   - maxmemory-policy noeviction. Every family key carries a TTL, so the
//     volatile-* policies may evict it as well as the allkeys-* ones. A
//     lost "active" key only logs users out — the store treats the tokens
//     of an unknown family as revoked — but a lost "revoked" key, within
//     its retention, is recorded active again by the next issuance into
//     the family, reviving its tokens. An evicted code key reads as an
//     unknown code: a replay of it is still refused, but no longer
//     recognized as one.
//
// go-redis resends a command whose reply was lost; every script is safe to
// run twice: a resent rotation is not mistaken for a reuse, nor a resent
// code consumption for a replay.
//
// Allowed dependencies:
//   - github.com/hyperscale-stack/security/oauth2
//   - github.com/redis/go-redis/v9
//   - stdlib only
package redisstore
