// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"testing"

	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/kbfs/kbfscodec"
	"github.com/keybase/kbfs/kbfscrypto"
	"github.com/stretchr/testify/require"
)

// Make sure creating an WKB ID for a WKB with no keys fails.
func TestWKBID(t *testing.T) {
	codec := kbfscodec.NewMsgpack()

	var wkb TLFWriterKeyBundleV3

	_, err := MakeTLFWriterKeyBundleID(codec, wkb)
	require.Error(t, err)

	wkb.Keys = UserDeviceKeyInfoMapV3{
		keybase1.UID(0): nil,
	}

	_, err = MakeTLFWriterKeyBundleID(codec, wkb)
	require.NoError(t, err)
}

// Make sure that RKBs can be created with nil vs. empty keys get the
// same ID.
func TestRKBID(t *testing.T) {
	codec := kbfscodec.NewMsgpack()

	var wkb1, wkb2 TLFReaderKeyBundleV3
	wkb2.Keys = make(UserDeviceKeyInfoMapV3)

	id1, err := MakeTLFReaderKeyBundleID(codec, wkb1)
	require.NoError(t, err)

	id2, err := MakeTLFReaderKeyBundleID(codec, wkb2)
	require.NoError(t, err)

	require.Equal(t, id1, id2)
}

// TestRemoveDevicesNotInV3 checks basic functionality of
// removeDevicesNotIn().
func TestRemoveDevicesNotInV3(t *testing.T) {
	uid1 := keybase1.MakeTestUID(0x1)
	uid2 := keybase1.MakeTestUID(0x2)
	uid3 := keybase1.MakeTestUID(0x3)

	key1a := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key1")
	key1b := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key2")
	key2a := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key3")
	key2b := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key4")
	key2c := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key5")
	key3a := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key6")

	half1a := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x1})
	half1b := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x2})
	half2a := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x3})
	half2b := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x4})
	half2c := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x5})
	half3a := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x6})

	id1a, err := GetTLFCryptKeyServerHalfID(uid1, key1a, half1a)
	require.NoError(t, err)
	id1b, err := GetTLFCryptKeyServerHalfID(uid1, key1b, half1b)
	require.NoError(t, err)
	id2a, err := GetTLFCryptKeyServerHalfID(uid2, key2a, half2a)
	require.NoError(t, err)
	id2b, err := GetTLFCryptKeyServerHalfID(uid2, key2b, half2b)
	require.NoError(t, err)
	id2c, err := GetTLFCryptKeyServerHalfID(uid2, key2c, half2c)
	require.NoError(t, err)
	id3a, err := GetTLFCryptKeyServerHalfID(uid2, key3a, half3a)
	require.NoError(t, err)

	udkimV3 := UserDeviceKeyInfoMapV3{
		uid1: DeviceKeyInfoMapV3{
			key1a: TLFCryptKeyInfo{
				ServerHalfID: id1a,
				EPubKeyIndex: 1,
			},
			key1b: TLFCryptKeyInfo{
				ServerHalfID: id1b,
				EPubKeyIndex: 2,
			},
		},
		uid2: DeviceKeyInfoMapV3{
			key2a: TLFCryptKeyInfo{
				ServerHalfID: id2a,
				EPubKeyIndex: 2,
			},
			key2b: TLFCryptKeyInfo{
				ServerHalfID: id2b,
				EPubKeyIndex: 0,
			},
			key2c: TLFCryptKeyInfo{
				ServerHalfID: id2c,
				EPubKeyIndex: 0,
			},
		},
		uid3: DeviceKeyInfoMapV3{
			key3a: TLFCryptKeyInfo{
				ServerHalfID: id3a,
				EPubKeyIndex: 2,
			},
		},
	}

	removalInfo := udkimV3.RemoveDevicesNotIn(UserDevicePublicKeys{
		uid2: {key2a: true, key2c: true},
		uid3: {key3a: true},
	})

	require.Equal(t, UserDeviceKeyInfoMapV3{
		uid2: DeviceKeyInfoMapV3{
			key2a: TLFCryptKeyInfo{
				ServerHalfID: id2a,
				EPubKeyIndex: 2,
			},
			key2c: TLFCryptKeyInfo{
				ServerHalfID: id2c,
				EPubKeyIndex: 0,
			},
		},
		uid3: DeviceKeyInfoMapV3{
			key3a: TLFCryptKeyInfo{
				ServerHalfID: id3a,
				EPubKeyIndex: 2,
			},
		},
	}, udkimV3)

	require.Equal(t, ServerHalfRemovalInfo{
		uid1: UserServerHalfRemovalInfo{
			UserRemoved: true,
			DeviceServerHalfIDs: DeviceServerHalfRemovalInfo{
				key1a: []TLFCryptKeyServerHalfID{id1a},
				key1b: []TLFCryptKeyServerHalfID{id1b},
			},
		},
		uid2: UserServerHalfRemovalInfo{
			UserRemoved: false,
			DeviceServerHalfIDs: DeviceServerHalfRemovalInfo{
				key2b: []TLFCryptKeyServerHalfID{id2b},
			},
		},
	}, removalInfo)
}

// TestRemoveLastDeviceV3 checks behavior of removeDevicesNotIn() with
// respect to removing the last device of a user vs. removing the user
// completely.
//
// This is a regression test for KBFS-1898.
func TestRemoveLastDeviceV3(t *testing.T) {
	uid1 := keybase1.MakeTestUID(0x1)
	uid2 := keybase1.MakeTestUID(0x2)
	uid3 := keybase1.MakeTestUID(0x3)
	uid4 := keybase1.MakeTestUID(0x4)

	key1 := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key1")
	key2 := kbfscrypto.MakeFakeCryptPublicKeyOrBust("key2")

	half1 := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x1})
	half2 := kbfscrypto.MakeTLFCryptKeyServerHalf([32]byte{0x2})

	id1, err := GetTLFCryptKeyServerHalfID(uid1, key1, half1)
	require.NoError(t, err)
	id2, err := GetTLFCryptKeyServerHalfID(uid2, key2, half2)
	require.NoError(t, err)

	udkimV3 := UserDeviceKeyInfoMapV3{
		uid1: DeviceKeyInfoMapV3{
			key1: TLFCryptKeyInfo{
				ServerHalfID: id1,
				EPubKeyIndex: 1,
			},
		},
		uid2: DeviceKeyInfoMapV3{
			key2: TLFCryptKeyInfo{
				ServerHalfID: id2,
				EPubKeyIndex: 2,
			},
		},
		uid3: DeviceKeyInfoMapV3{},
		uid4: DeviceKeyInfoMapV3{},
	}

	removalInfo := udkimV3.RemoveDevicesNotIn(UserDevicePublicKeys{
		uid1: {},
		uid3: {},
	})

	require.Equal(t, UserDeviceKeyInfoMapV3{
		uid1: DeviceKeyInfoMapV3{},
		uid3: DeviceKeyInfoMapV3{},
	}, udkimV3)

	require.Equal(t, ServerHalfRemovalInfo{
		uid1: UserServerHalfRemovalInfo{
			UserRemoved: false,
			DeviceServerHalfIDs: DeviceServerHalfRemovalInfo{
				key1: []TLFCryptKeyServerHalfID{id1},
			},
		},
		uid2: UserServerHalfRemovalInfo{
			UserRemoved: true,
			DeviceServerHalfIDs: DeviceServerHalfRemovalInfo{
				key2: []TLFCryptKeyServerHalfID{id2},
			},
		},
		uid4: UserServerHalfRemovalInfo{
			UserRemoved:         true,
			DeviceServerHalfIDs: DeviceServerHalfRemovalInfo{},
		},
	}, removalInfo)
}
