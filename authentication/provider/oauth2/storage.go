// Copyright 2021 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oauth2

type ClientStorage interface {
	SaveClient(Client) error
	LoadClient(id string) (Client, error)
	RemoveClient(id string) error
}

type AccessStorage interface {
	SaveAccess(*AccessInfo) error
	LoadAccess(token string) (*AccessInfo, error)
	RemoveAccess(token string) error
}

type RefreshStorage interface {
	SaveRefresh(*AccessInfo) error
	LoadRefresh(token string) (*AccessInfo, error)
	RemoveRefresh(token string) error
}

type AuthorizeStorage interface {
	SaveAuthorize(*AuthorizeInfo) error
	LoadAuthorize(code string) (*AuthorizeInfo, error)
	RemoveAuthorize(code string) error
}

type Storage interface {
	ClientStorage
	AccessStorage
	RefreshStorage
	AuthorizeStorage
}