// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"github.com/keybase/kbfs/tlf"
)

// RootMetadata is a read-only interface to the serializeable MD that
// is signed by the reader or writer.
//
// TODO: Move the rest of libkbfs.BareRootMetadata here.
type RootMetadata interface {
	// TlfID returns the ID of the TLF this BareRootMetadata is for.
	TlfID() tlf.ID
	// KeyGenerationsToUpdate returns a range that has to be
	// updated when rekeying. start is included, but end is not
	// included. This range can be empty (i.e., start >= end), in
	// which case there's nothing to update, i.e. the TLF is
	// public, or there aren't any existing key generations.
	KeyGenerationsToUpdate() (start KeyGen, end KeyGen)
	// LatestKeyGeneration returns the most recent key generation in this
	// BareRootMetadata, or PublicKeyGen if this TLF is public.
	LatestKeyGeneration() KeyGen

	// GetSerializedPrivateMetadata returns the serialized private metadata as a byte slice.
	GetSerializedPrivateMetadata() []byte
}
