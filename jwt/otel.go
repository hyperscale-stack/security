// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package jwtsec

// tracerName is the OTel instrumentation scope used by this module's
// span emissions. Per the project's OTel-direct policy, every signer /
// verifier call opens a span here.
const tracerName = "github.com/hyperscale-stack/security/jwt"
