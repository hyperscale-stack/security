// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package random

// Configuration struct
type Configuration struct {
	AccessTokenSize  int `mapstructure:"access_token_size"`
	RefreshTokenSize int `mapstructure:"refresh_token_size"`
}
