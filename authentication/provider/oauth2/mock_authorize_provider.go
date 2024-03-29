// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package oauth2

import mock "github.com/stretchr/testify/mock"

// MockAuthorizeProvider is an autogenerated mock type for the AuthorizeProvider type
type MockAuthorizeProvider struct {
	mock.Mock
}

// LoadAuthorize provides a mock function with given fields: code
func (_m *MockAuthorizeProvider) LoadAuthorize(code string) (*AuthorizeInfo, error) {
	ret := _m.Called(code)

	var r0 *AuthorizeInfo
	if rf, ok := ret.Get(0).(func(string) *AuthorizeInfo); ok {
		r0 = rf(code)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*AuthorizeInfo)
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

// RemoveAuthorize provides a mock function with given fields: code
func (_m *MockAuthorizeProvider) RemoveAuthorize(code string) error {
	ret := _m.Called(code)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(code)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveAuthorize provides a mock function with given fields: _a0
func (_m *MockAuthorizeProvider) SaveAuthorize(_a0 *AuthorizeInfo) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*AuthorizeInfo) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
