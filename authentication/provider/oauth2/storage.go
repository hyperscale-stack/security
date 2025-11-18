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

type ClientProvider interface {
	SaveClient(Client) error
	LoadClient(id string) (Client, error)
	RemoveClient(id string) error
}

type AccessProvider interface {
	SaveAccess(*AccessInfo) error
	LoadAccess(token string) (*AccessInfo, error)
	RemoveAccess(token string) error
}

type RefreshProvider interface {
	SaveRefresh(*AccessInfo) error
	LoadRefresh(token string) (*AccessInfo, error)
	RemoveRefresh(token string) error
}

type AuthorizeProvider interface {
	SaveAuthorize(*AuthorizeInfo) error
	LoadAuthorize(code string) (*AuthorizeInfo, error)
	RemoveAuthorize(code string) error
}

type UserProvider interface {
	LoadUser(id string) (user.User, error)
}

type StorageProvider interface {
	ClientProvider
	AccessProvider
	RefreshProvider
	AuthorizeProvider
}
