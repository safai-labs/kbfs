// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"reflect"

	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/kbfs/cache"
	"github.com/keybase/kbfs/kbfscrypto"
)

// A lot of this code is duplicated from key_bundle_v2.go, except with
// DeviceKeyInfoMapV2 (keyed by keybase1.KID) replaced with
// DeviceKeyInfoMapV3 (keyed by kbfscrypto.CryptPublicKey).

// DeviceKeyInfoMapV3 is a map from a user devices (identified by the
// corresponding device CryptPublicKey) to the TLF's symmetric secret
// key information.
type DeviceKeyInfoMapV3 map[kbfscrypto.CryptPublicKey]TLFCryptKeyInfo

// static sizes in DeviceKeyInfoMapV3
var (
	ssCryptPublicKey  = int(reflect.TypeOf(kbfscrypto.CryptPublicKey{}).Size())
	ssTLFCryptKeyInfo = int(reflect.TypeOf(TLFCryptKeyInfo{}).Size())
)

// Size implements the cache.Measurable interface.
func (dkimV3 DeviceKeyInfoMapV3) Size() int {
	// statically-sized part
	mapSize := cache.StaticSizeOfMapWithSize(
		ssCryptPublicKey, ssTLFCryptKeyInfo, len(dkimV3))

	// go through pointer type content
	var contentSize int
	for k, v := range dkimV3 {
		contentSize += len(k.KID())
		contentSize += len(v.ServerHalfID.ID.String())

		// We are not using v.ClientHalf.encryptedData here since that would
		// include the size of struct itself which is already counted in
		// cache.StaticSizeOfMapWithSize.
		contentSize += len(v.ClientHalf.Data) +
			len(v.ClientHalf.EncryptedData.Nonce)
	}

	return mapSize + contentSize
}

// FillInDeviceInfos is temporarily public.
func (dkimV3 DeviceKeyInfoMapV3) FillInDeviceInfos(crypto cryptoPure,
	uid keybase1.UID, tlfCryptKey kbfscrypto.TLFCryptKey,
	ePrivKey kbfscrypto.TLFEphemeralPrivateKey, ePubIndex int,
	updatedDeviceKeys DevicePublicKeys) (
	serverHalves DeviceKeyServerHalves, err error) {
	serverHalves = make(DeviceKeyServerHalves, len(updatedDeviceKeys))
	// TODO: parallelize
	for k := range updatedDeviceKeys {
		// Skip existing entries, and only fill in new ones
		if _, ok := dkimV3[k]; ok {
			continue
		}

		clientInfo, serverHalf, err := SplitTLFCryptKey(
			crypto, uid, tlfCryptKey, ePrivKey, ePubIndex, k)
		if err != nil {
			return nil, err
		}

		dkimV3[k] = clientInfo
		serverHalves[k] = serverHalf
	}

	return serverHalves, nil
}

// ToPublicKeys is temporarily public.
func (dkimV3 DeviceKeyInfoMapV3) ToPublicKeys() DevicePublicKeys {
	publicKeys := make(DevicePublicKeys, len(dkimV3))
	for key := range dkimV3 {
		publicKeys[key] = true
	}
	return publicKeys
}
