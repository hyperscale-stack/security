// Copyright 2026 Hyperscale. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package oidcclient

import (
	"bytes"
	"crypto/ed25519"
)

// smallOrderY are the y-coordinates, little-endian, of the Ed25519 points
// of order dividing 8 (0, 1, p−1 and the two of order 8): with the sign bit
// cleared, every encoding of a small-order point is one of them, or a
// non-canonical encoding of 0 or 1 (p, p+1).
var smallOrderY = [][]byte{
	make([]byte, ed25519.PublicKeySize),
	append([]byte{0x01}, make([]byte, ed25519.PublicKeySize-1)...),
	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
}

// validEd25519PublicKey reports whether key can verify Ed25519 signatures:
// 32 bytes, a canonical encoding — y, the key with its sign bit (bit 255)
// cleared, below p = 2^255 − 19 (RFC 8032 §5.1.3 step 1: decoding fails
// otherwise, and the signature is invalid, §5.1.7 step 1), which
// crypto/ed25519 does not check — and not a point of small order, under
// which forged signatures verify (RFC 8725 §3.4). A key that is not on the
// curve verifies nothing: crypto/ed25519 fails its decoding.
func validEd25519PublicKey(key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}

	y := bytes.Clone(key)
	y[ed25519.PublicKeySize-1] &= 0x7f

	if !canonicalY(y) {
		return false
	}

	for _, small := range smallOrderY {
		if bytes.Equal(y, small) {
			return false
		}
	}

	return true
}

// canonicalY reports whether y (32 bytes, little-endian, bit 255 cleared)
// is below p = 2^255 − 19, whose encoding is ed ff … ff 7f.
func canonicalY(y []byte) bool {
	if y[ed25519.PublicKeySize-1] != 0x7f {
		return true
	}

	for _, b := range y[1 : ed25519.PublicKeySize-1] {
		if b != 0xff {
			return true
		}
	}

	return y[0] < 0xed
}
