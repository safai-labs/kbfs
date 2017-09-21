// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-codec/codec"
	"github.com/keybase/kbfs/kbfscrypto"
	"github.com/keybase/kbfs/kbfshash"
)

// TLFCryptKeyServerHalfID is the identifier type for a server-side key half.
type TLFCryptKeyServerHalfID struct {
	ID kbfshash.HMAC // Exported for serialization.
}

// String implements the Stringer interface for TLFCryptKeyServerHalfID.
func (id TLFCryptKeyServerHalfID) String() string {
	return id.ID.String()
}

// TLFCryptKeyInfo is a per-device key half entry in the
// TLF{Writer,Reader}KeyBundleV{2,3}.
type TLFCryptKeyInfo struct {
	ClientHalf   EncryptedTLFCryptKeyClientHalf
	ServerHalfID TLFCryptKeyServerHalfID
	EPubKeyIndex int `codec:"i,omitempty"`

	codec.UnknownFieldSetHandler
}

// DevicePublicKeys is a set of a user's devices (identified by the
// corresponding device CryptPublicKey).
type DevicePublicKeys map[kbfscrypto.CryptPublicKey]bool

// Equals returns whether both sets of keys are equal.
func (dpk DevicePublicKeys) Equals(other DevicePublicKeys) bool {
	if len(dpk) != len(other) {
		return false
	}

	for k := range dpk {
		if !other[k] {
			return false
		}
	}

	return true
}

// DeviceKeyServerHalves is a map from a user devices (identified by the
// corresponding device CryptPublicKey) to corresponding key server
// halves.
type DeviceKeyServerHalves map[kbfscrypto.CryptPublicKey]kbfscrypto.TLFCryptKeyServerHalf

// cryptoPure contains all methods of Crypto that don't depend on
// implicit state, i.e. they're pure functions of the input.
type cryptoPure interface {
	// MakeRandomTLFCryptKeyServerHalf generates the server-side of a
	// top-level folder crypt key.
	MakeRandomTLFCryptKeyServerHalf() (
		kbfscrypto.TLFCryptKeyServerHalf, error)

	// EncryptTLFCryptKeyClientHalf encrypts a TLFCryptKeyClientHalf
	// using both a TLF's ephemeral private key and a device pubkey.
	EncryptTLFCryptKeyClientHalf(
		privateKey kbfscrypto.TLFEphemeralPrivateKey,
		publicKey kbfscrypto.CryptPublicKey,
		clientHalf kbfscrypto.TLFCryptKeyClientHalf) (
		EncryptedTLFCryptKeyClientHalf, error)

	// GetTLFCryptKeyServerHalfID creates a unique ID for this particular
	// kbfscrypto.TLFCryptKeyServerHalf.
	GetTLFCryptKeyServerHalfID(
		user keybase1.UID, devicePubKey kbfscrypto.CryptPublicKey,
		serverHalf kbfscrypto.TLFCryptKeyServerHalf) (
		TLFCryptKeyServerHalfID, error)
}

// SplitTLFCryptKey splits the given TLFCryptKey into two parts -- the
// client-side part (which is encrypted with the given keys), and the
// server-side part, which will be uploaded to the server.
func SplitTLFCryptKey(crypto cryptoPure, uid keybase1.UID,
	tlfCryptKey kbfscrypto.TLFCryptKey,
	ePrivKey kbfscrypto.TLFEphemeralPrivateKey, ePubIndex int,
	pubKey kbfscrypto.CryptPublicKey) (
	TLFCryptKeyInfo, kbfscrypto.TLFCryptKeyServerHalf, error) {
	//    * create a new random server half
	//    * mask it with the key to get the client half
	//    * encrypt the client half
	var serverHalf kbfscrypto.TLFCryptKeyServerHalf
	serverHalf, err := crypto.MakeRandomTLFCryptKeyServerHalf()
	if err != nil {
		return TLFCryptKeyInfo{}, kbfscrypto.TLFCryptKeyServerHalf{}, err
	}

	clientHalf := kbfscrypto.MaskTLFCryptKey(serverHalf, tlfCryptKey)

	var encryptedClientHalf EncryptedTLFCryptKeyClientHalf
	encryptedClientHalf, err =
		crypto.EncryptTLFCryptKeyClientHalf(ePrivKey, pubKey, clientHalf)
	if err != nil {
		return TLFCryptKeyInfo{}, kbfscrypto.TLFCryptKeyServerHalf{}, err
	}

	var serverHalfID TLFCryptKeyServerHalfID
	serverHalfID, err =
		crypto.GetTLFCryptKeyServerHalfID(uid, pubKey, serverHalf)
	if err != nil {
		return TLFCryptKeyInfo{}, kbfscrypto.TLFCryptKeyServerHalf{}, err
	}

	clientInfo := TLFCryptKeyInfo{
		ClientHalf:   encryptedClientHalf,
		ServerHalfID: serverHalfID,
		EPubKeyIndex: ePubIndex,
	}
	return clientInfo, serverHalf, nil
}
