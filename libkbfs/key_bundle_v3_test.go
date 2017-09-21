// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"testing"

	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/go-codec/codec"
	"github.com/keybase/kbfs/kbfscodec"
	"github.com/keybase/kbfs/kbfscrypto"
)

type deviceKeyInfoMapV3Future map[kbfscrypto.CryptPublicKey]tlfCryptKeyInfoFuture

func (dkimf deviceKeyInfoMapV3Future) toCurrent() DeviceKeyInfoMapV3 {
	dkim := make(DeviceKeyInfoMapV3, len(dkimf))
	for k, kif := range dkimf {
		ki := kif.toCurrent()
		dkim[k] = TLFCryptKeyInfo(ki)
	}
	return dkim
}

type userDeviceKeyInfoMapV3Future map[keybase1.UID]deviceKeyInfoMapV3Future

func (udkimf userDeviceKeyInfoMapV3Future) toCurrent() UserDeviceKeyInfoMapV3 {
	udkim := make(UserDeviceKeyInfoMapV3)
	for u, dkimf := range udkimf {
		dkim := dkimf.toCurrent()
		udkim[u] = dkim
	}
	return udkim
}

type tlfWriterKeyBundleV3Future struct {
	TLFWriterKeyBundleV3
	// Override TLFWriterKeyBundleV3.Keys.
	Keys userDeviceKeyInfoMapV3Future `codec:"wKeys"`
	kbfscodec.Extra
}

func (wkbf tlfWriterKeyBundleV3Future) toCurrent() TLFWriterKeyBundleV3 {
	wkb := wkbf.TLFWriterKeyBundleV3
	wkb.Keys = wkbf.Keys.toCurrent()
	return wkb
}

func (wkbf tlfWriterKeyBundleV3Future) ToCurrentStruct() kbfscodec.CurrentStruct {
	return wkbf.toCurrent()
}

func makeFakeDeviceKeyInfoMapV3Future(t *testing.T) userDeviceKeyInfoMapV3Future {
	return userDeviceKeyInfoMapV3Future{
		"fake uid": deviceKeyInfoMapV3Future{
			kbfscrypto.MakeFakeCryptPublicKeyOrBust("fake key"): makeFakeTLFCryptKeyInfoFuture(t),
		},
	}
}

func makeFakeTLFWriterKeyBundleV3Future(t *testing.T) tlfWriterKeyBundleV3Future {
	wkb := TLFWriterKeyBundleV3{
		nil,
		kbfscrypto.MakeTLFPublicKey([32]byte{0xa}),
		kbfscrypto.TLFEphemeralPublicKeys{
			kbfscrypto.MakeTLFEphemeralPublicKey([32]byte{0xb}),
		},
		EncryptedTLFCryptKeys{},
		codec.UnknownFieldSetHandler{},
	}
	return tlfWriterKeyBundleV3Future{
		wkb,
		makeFakeDeviceKeyInfoMapV3Future(t),
		kbfscodec.MakeExtraOrBust("TLFWriterKeyBundleV3", t),
	}
}

func TestTLFWriterKeyBundleV3UnknownFields(t *testing.T) {
	testStructUnknownFields(t, makeFakeTLFWriterKeyBundleV3Future(t))
}

type tlfReaderKeyBundleV3Future struct {
	TLFReaderKeyBundleV3
	// Override TLFReaderKeyBundleV3.Keys.
	Keys userDeviceKeyInfoMapV3Future `codec:"rKeys"`
	kbfscodec.Extra
}

func (rkbf tlfReaderKeyBundleV3Future) toCurrent() TLFReaderKeyBundleV3 {
	rkb := rkbf.TLFReaderKeyBundleV3
	rkb.Keys = rkbf.Keys.toCurrent()
	return rkb
}

func (rkbf tlfReaderKeyBundleV3Future) ToCurrentStruct() kbfscodec.CurrentStruct {
	return rkbf.toCurrent()
}

func makeFakeTLFReaderKeyBundleV3Future(
	t *testing.T) tlfReaderKeyBundleV3Future {
	rkb := TLFReaderKeyBundleV3{
		nil,
		kbfscrypto.TLFEphemeralPublicKeys{
			kbfscrypto.MakeTLFEphemeralPublicKey([32]byte{0xc}),
		},
		codec.UnknownFieldSetHandler{},
	}
	return tlfReaderKeyBundleV3Future{
		rkb,
		makeFakeDeviceKeyInfoMapV3Future(t),
		kbfscodec.MakeExtraOrBust("TLFReaderKeyBundleV3", t),
	}
}

func TestTLFReaderKeyBundleV3UnknownFields(t *testing.T) {
	testStructUnknownFields(t, makeFakeTLFReaderKeyBundleV3Future(t))
}
