// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"fmt"

	"github.com/keybase/kbfs/kbfscodec"
	"github.com/keybase/kbfs/kbfscrypto"
	"github.com/keybase/kbfs/kbfsmd"
)

// DeviceKeyInfoMapV3 is a temporary alias.
type DeviceKeyInfoMapV3 = kbfsmd.DeviceKeyInfoMapV3

// UserDeviceKeyInfoMapV3 is a temporary alias.
type UserDeviceKeyInfoMapV3 = kbfsmd.UserDeviceKeyInfoMapV3

func writerUDKIMV2ToV3(codec kbfscodec.Codec, udkimV2 UserDeviceKeyInfoMapV2,
	ePubKeyCount int) (
	UserDeviceKeyInfoMapV3, error) {
	udkimV3 := make(UserDeviceKeyInfoMapV3, len(udkimV2))
	for uid, dkimV2 := range udkimV2 {
		dkimV3 := make(DeviceKeyInfoMapV3, len(dkimV2))
		for kid, info := range dkimV2 {
			index := info.EPubKeyIndex
			if index < 0 {
				// TODO: Fix this; see KBFS-1719.
				return nil, fmt.Errorf(
					"Writer key with index %d for user=%s, kid=%s not handled yet",
					index, uid, kid)
			}
			if index >= ePubKeyCount {
				return nil, fmt.Errorf(
					"Invalid writer key index %d for user=%s, kid=%s",
					index, uid, kid)
			}

			var infoCopy TLFCryptKeyInfo
			err := kbfscodec.Update(codec, &infoCopy, info)
			if err != nil {
				return nil, err
			}
			dkimV3[kbfscrypto.MakeCryptPublicKey(kid)] = infoCopy
		}
		udkimV3[uid] = dkimV3
	}
	return udkimV3, nil
}

type TLFWriterKeyBundleV3 = kbfsmd.TLFWriterKeyBundleV3

type TLFReaderKeyBundleV3 = kbfsmd.TLFReaderKeyBundleV3

type TLFWriterKeyBundleID = kbfsmd.TLFWriterKeyBundleID

type TLFReaderKeyBundleID = kbfsmd.TLFReaderKeyBundleID
