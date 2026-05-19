// Copyright 2020 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package authorization

import "github.com/hyperscale-stack/security/authentication/credential"

// Option is the legacy authorization-decision function. Deprecated: use
// [security.Voter] and [security.AccessDecisionManager] (from the parent
// module) for the v2 voter-based authorization. Scheduled for removal at the
// end of Phase 7.
//
//nolint:staticcheck // legacy package, scheduled removal Phase 7
type Option func(creds credential.Credential) bool
