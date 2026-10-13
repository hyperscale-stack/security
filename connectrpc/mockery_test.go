// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package connectrpcsec_test

// `make generate` writes this module's mockery mocks as in-package
// mock_*_test.go files, which are never committed. They import testify/mock:
// importing it here too keeps go.mod and go.sum identical whether or not the
// mocks have been generated (go mod tidy, Dependabot).
import _ "github.com/stretchr/testify/mock"
