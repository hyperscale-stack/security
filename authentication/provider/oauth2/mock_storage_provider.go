// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package oauth2

import mock "github.com/stretchr/testify/mock"

// MockStorageProvider is an autogenerated mock type for the StorageProvider type
type MockStorageProvider struct {
	mock.Mock
}

// LoadAccess provides a mock function with given fields: token
func (_m *MockStorageProvider) LoadAccess(token string) (*AccessData, error) {
	ret := _m.Called(token)

	var r0 *AccessData
	if rf, ok := ret.Get(0).(func(string) *AccessData); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*AccessData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadAuthorize provides a mock function with given fields: code
func (_m *MockStorageProvider) LoadAuthorize(code string) (*AuthorizeData, error) {
	ret := _m.Called(code)

	var r0 *AuthorizeData
	if rf, ok := ret.Get(0).(func(string) *AuthorizeData); ok {
		r0 = rf(code)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*AuthorizeData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(code)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadClient provides a mock function with given fields: id
func (_m *MockStorageProvider) LoadClient(id string) (Client, error) {
	ret := _m.Called(id)

	var r0 Client
	if rf, ok := ret.Get(0).(func(string) Client); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(Client)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadRefresh provides a mock function with given fields: token
func (_m *MockStorageProvider) LoadRefresh(token string) (*AccessData, error) {
	ret := _m.Called(token)

	var r0 *AccessData
	if rf, ok := ret.Get(0).(func(string) *AccessData); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*AccessData)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveAccess provides a mock function with given fields: token
func (_m *MockStorageProvider) RemoveAccess(token string) error {
	ret := _m.Called(token)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveAuthorize provides a mock function with given fields: code
func (_m *MockStorageProvider) RemoveAuthorize(code string) error {
	ret := _m.Called(code)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(code)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveClient provides a mock function with given fields: id
func (_m *MockStorageProvider) RemoveClient(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveRefresh provides a mock function with given fields: token
func (_m *MockStorageProvider) RemoveRefresh(token string) error {
	ret := _m.Called(token)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveAccess provides a mock function with given fields: _a0
func (_m *MockStorageProvider) SaveAccess(_a0 *AccessData) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*AccessData) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveAuthorize provides a mock function with given fields: _a0
func (_m *MockStorageProvider) SaveAuthorize(_a0 *AuthorizeData) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*AuthorizeData) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveClient provides a mock function with given fields: _a0
func (_m *MockStorageProvider) SaveClient(_a0 Client) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(Client) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveRefresh provides a mock function with given fields: _a0
func (_m *MockStorageProvider) SaveRefresh(_a0 *AccessData) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*AccessData) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
