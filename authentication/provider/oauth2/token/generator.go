// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package token

type Generator interface {
	GenerateAccessToken(generateRefresh bool) (accessToken string, refreshToken string, err error)
}
