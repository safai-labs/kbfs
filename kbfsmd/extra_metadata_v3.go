// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"github.com/keybase/kbfs/kbfscodec"
)

// ExtraMetadataV3 contains references to key bundles stored outside of metadata
// blocks.  This only ever exists in memory and is never serialized itself.
type ExtraMetadataV3 struct {
	Wkb TLFWriterKeyBundleV3
	Rkb TLFReaderKeyBundleV3
	// Set if wkb is new and should be sent to the server on an MD
	// put.
	WkbNew bool
	// Set if rkb is new and should be sent to the server on an MD
	// put.
	RkbNew bool
}

// NewExtraMetadataV3 creates a new ExtraMetadataV3 given a pair of key bundles
func NewExtraMetadataV3(
	wkb TLFWriterKeyBundleV3, rkb TLFReaderKeyBundleV3,
	wkbNew, rkbNew bool) *ExtraMetadataV3 {
	return &ExtraMetadataV3{wkb, rkb, wkbNew, rkbNew}
}

// MetadataVersion implements the ExtraMetadata interface for ExtraMetadataV3.
func (extra ExtraMetadataV3) MetadataVersion() MetadataVer {
	return SegregatedKeyBundlesVer
}

func (extra *ExtraMetadataV3) UpdateNew(wkbNew, rkbNew bool) {
	extra.WkbNew = extra.WkbNew || wkbNew
	extra.RkbNew = extra.RkbNew || rkbNew
}

// DeepCopy implements the ExtraMetadata interface for ExtraMetadataV3.
func (extra ExtraMetadataV3) DeepCopy(codec kbfscodec.Codec) (
	ExtraMetadata, error) {
	wkb, err := extra.Wkb.DeepCopy(codec)
	if err != nil {
		return nil, err
	}
	rkb, err := extra.Rkb.DeepCopy(codec)
	if err != nil {
		return nil, err
	}
	return NewExtraMetadataV3(wkb, rkb, extra.WkbNew, extra.RkbNew), nil
}

// MakeSuccessorCopy implements the ExtraMetadata interface for ExtraMetadataV3.
func (extra ExtraMetadataV3) MakeSuccessorCopy(codec kbfscodec.Codec) (
	ExtraMetadata, error) {
	wkb, err := extra.Wkb.DeepCopy(codec)
	if err != nil {
		return nil, err
	}
	rkb, err := extra.Rkb.DeepCopy(codec)
	if err != nil {
		return nil, err
	}
	return NewExtraMetadataV3(wkb, rkb, false, false), nil
}

// GetWriterKeyBundle returns the contained writer key bundle.
func (extra ExtraMetadataV3) GetWriterKeyBundle() TLFWriterKeyBundleV3 {
	return extra.Wkb
}

// GetReaderKeyBundle returns the contained reader key bundle.
func (extra ExtraMetadataV3) GetReaderKeyBundle() TLFReaderKeyBundleV3 {
	return extra.Rkb
}
