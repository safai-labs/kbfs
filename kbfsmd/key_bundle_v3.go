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

// UserDeviceKeyInfoMapV3 maps a user's keybase UID to their
// DeviceKeyInfoMapV3.
type UserDeviceKeyInfoMapV3 map[keybase1.UID]DeviceKeyInfoMapV3

// Size implements the cache.Measurable interface.
func (udkimV3 UserDeviceKeyInfoMapV3) Size() int {
	// statically-sized part
	mapSize := cache.StaticSizeOfMapWithSize(
		cache.PtrSize, cache.PtrSize, len(udkimV3))

	// go through pointer type content
	var contentSize int
	for k, v := range udkimV3 {
		contentSize += len(k) + v.Size()
	}

	return mapSize + contentSize
}

func (udkimV3 UserDeviceKeyInfoMapV3) ToPublicKeys() UserDevicePublicKeys {
	publicKeys := make(UserDevicePublicKeys, len(udkimV3))
	for u, dkimV3 := range udkimV3 {
		publicKeys[u] = dkimV3.ToPublicKeys()
	}
	return publicKeys
}

// RemoveDevicesNotIn removes any info for any device that is not
// contained in the given map of users and devices.
func (udkimV3 UserDeviceKeyInfoMapV3) RemoveDevicesNotIn(
	updatedUserKeys UserDevicePublicKeys) ServerHalfRemovalInfo {
	removalInfo := make(ServerHalfRemovalInfo)
	for uid, dkim := range udkimV3 {
		userRemoved := false
		deviceServerHalfIDs := make(DeviceServerHalfRemovalInfo)
		if deviceKeys, ok := updatedUserKeys[uid]; ok {
			for key, info := range dkim {
				if !deviceKeys[key] {
					delete(dkim, key)
					deviceServerHalfIDs[key] = append(
						deviceServerHalfIDs[key],
						info.ServerHalfID)
				}
			}

			if len(deviceServerHalfIDs) == 0 {
				continue
			}
		} else {
			// The user was completely removed, which
			// shouldn't happen but might as well make it
			// work just in case.
			userRemoved = true
			for key, info := range dkim {
				deviceServerHalfIDs[key] = append(
					deviceServerHalfIDs[key],
					info.ServerHalfID)
			}

			delete(udkimV3, uid)
		}

		removalInfo[uid] = UserServerHalfRemovalInfo{
			UserRemoved:         userRemoved,
			DeviceServerHalfIDs: deviceServerHalfIDs,
		}
	}

	return removalInfo
}

func (udkimV3 UserDeviceKeyInfoMapV3) FillInUserInfos(
	crypto cryptoPure, newIndex int, updatedUserKeys UserDevicePublicKeys,
	ePrivKey kbfscrypto.TLFEphemeralPrivateKey,
	tlfCryptKey kbfscrypto.TLFCryptKey) (
	serverHalves UserDeviceKeyServerHalves, err error) {
	serverHalves = make(UserDeviceKeyServerHalves, len(updatedUserKeys))
	for u, updatedDeviceKeys := range updatedUserKeys {
		if _, ok := udkimV3[u]; !ok {
			udkimV3[u] = DeviceKeyInfoMapV3{}
		}

		deviceServerHalves, err := udkimV3[u].FillInDeviceInfos(
			crypto, u, tlfCryptKey, ePrivKey, newIndex,
			updatedDeviceKeys)
		if err != nil {
			return nil, err
		}
		if len(deviceServerHalves) > 0 {
			serverHalves[u] = deviceServerHalves
		}
	}
	return serverHalves, nil
}
