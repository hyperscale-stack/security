// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package redisstore is a Redis implementation of oauth2.Storage. Atomicity
// of ConsumeAuthorizationCode and RotateRefreshToken is guaranteed by Lua
// scripts loaded via EVALSHA (with EVAL fallback).
//
// Allowed dependencies (per architecture plan):
//   - github.com/hyperscale-stack/security/oauth2
//   - github.com/redis/go-redis/v9
//   - stdlib only
//
// Real implementation lands in Phase 8.
package redisstore
