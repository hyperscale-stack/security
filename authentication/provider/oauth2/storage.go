// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

import (
	"errors"

	"github.com/hyperscale-stack/security/user"
)

var (
	ErrClientNotFound    = errors.New("oauth2 client not found")
	ErrAccessNotFound    = errors.New("oauth2 access token not found")
	ErrRefreshNotFound   = errors.New("oauth2 refresh token not found")
	ErrAuthorizeNotFound = errors.New("oauth2 authorize code not found")
	ErrUserNotFound      = errors.New("oauth2 user not found")
)

//go:generate mockery --name=ClientProvider --inpackage --case underscore
type ClientProvider interface {
	SaveClient(Client) error
	LoadClient(id string) (Client, error)
	RemoveClient(id string) error
}

//go:generate mockery --name=AccessProvider --inpackage --case underscore
type AccessProvider interface {
	SaveAccess(*AccessInfo) error
	LoadAccess(token string) (*AccessInfo, error)
	RemoveAccess(token string) error
}

//go:generate mockery --name=RefreshProvider --inpackage --case underscore
type RefreshProvider interface {
	SaveRefresh(*AccessInfo) error
	LoadRefresh(token string) (*AccessInfo, error)
	RemoveRefresh(token string) error
}

//go:generate mockery --name=AuthorizeProvider --inpackage --case underscore
type AuthorizeProvider interface {
	SaveAuthorize(*AuthorizeInfo) error
	LoadAuthorize(code string) (*AuthorizeInfo, error)
	RemoveAuthorize(code string) error
}

//go:generate mockery --name=UserProvider --inpackage --case underscore
type UserProvider interface {
	LoadUser(id string) (user.User, error)
	LoadByUsername(username string) (user.User, error)
	Authenticate(username string, password string) (user.User, error)
}

//go:generate mockery --name=StorageProvider --inpackage --case underscore
type StorageProvider interface {
	ClientProvider
	AccessProvider
	RefreshProvider
	AuthorizeProvider
}
