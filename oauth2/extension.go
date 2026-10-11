// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

// MaxExtensionDataLength is the longest ExtensionData, in bytes, an
// authorization records: the whole per-grant budget of an [Extension],
// copied onto the code and onto every token issued from it.
const MaxExtensionDataLength = 4096
