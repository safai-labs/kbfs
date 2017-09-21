// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfscrypto

import (
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/keybase/kbfs/cache"
)

// EncryptionVer denotes a version for the encryption method.
type EncryptionVer int

const (
	// EncryptionSecretbox is the encryption version that uses
	// nacl/secretbox or nacl/box.
	EncryptionSecretbox EncryptionVer = 1
)

func (v EncryptionVer) String() string {
	switch v {
	case EncryptionSecretbox:
		return "EncryptionSecretbox"
	default:
		return fmt.Sprintf("EncryptionVer(%d)", v)
	}
}

// EncryptedData is encrypted data with a nonce and a version.
type EncryptedData struct {
	// Exported only for serialization purposes. Should only be
	// used by implementations of Crypto.
	Version EncryptionVer `codec:"v"`
	Data    []byte        `codec:"e"`
	Nonce   []byte        `codec:"n"`
}

// Size implements the cache.Measurable interface.
func (ed EncryptedData) Size() int {
	return cache.IntSize /* ed.Version */ +
		cache.PtrSize + len(ed.Data) + cache.PtrSize + len(ed.Nonce)
}

func (ed EncryptedData) String() string {
	if reflect.DeepEqual(ed, EncryptedData{}) {
		return "EncryptedData{}"
	}
	return fmt.Sprintf("%s{data=%s, nonce=%s}",
		ed.Version, hex.EncodeToString(ed.Data),
		hex.EncodeToString(ed.Nonce))
}
