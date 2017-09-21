// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import "github.com/keybase/kbfs/kbfscrypto"

// EncryptedTLFCryptKeyClientHalf is an encrypted
// TLFCryptKeyClientHalf object.
type EncryptedTLFCryptKeyClientHalf struct {
	kbfscrypto.EncryptedData
}

// EncryptedPrivateMetadata is an encrypted PrivateMetadata object.
type EncryptedPrivateMetadata struct {
	kbfscrypto.EncryptedData
}

// EncryptedTLFCryptKeys is an encrypted TLFCryptKey array.
type EncryptedTLFCryptKeys struct {
	kbfscrypto.EncryptedData
}
