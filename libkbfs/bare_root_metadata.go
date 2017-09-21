// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/davecgh/go-spew/spew"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/kbfs/kbfscodec"
	"github.com/keybase/kbfs/kbfscrypto"
	"github.com/keybase/kbfs/kbfsmd"
	"github.com/keybase/kbfs/tlf"
)

// TODO: Wrap errors coming from BareRootMetadata.

// BareRootMetadata is a read-only interface to the bare serializeable MD that
// is signed by the reader or writer.
type BareRootMetadata interface {
	kbfsmd.RootMetadata

	// IsValidRekeyRequest returns true if the current block is a simple rekey wrt
	// the passed block.
	IsValidRekeyRequest(codec kbfscodec.Codec, prevMd BareRootMetadata,
		user keybase1.UID, prevExtra, extra ExtraMetadata) (bool, error)
	// MergedStatus returns the status of this update -- has it been
	// merged into the main folder or not?
	MergedStatus() MergeStatus
	// IsWriter returns whether or not the user+device is an authorized writer.
	IsWriter(ctx context.Context, user keybase1.UID,
		cryptKey kbfscrypto.CryptPublicKey,
		verifyingKey kbfscrypto.VerifyingKey,
		teamMemChecker TeamMembershipChecker, extra ExtraMetadata) (bool, error)
	// IsReader returns whether or not the user+device is an authorized reader.
	IsReader(ctx context.Context, user keybase1.UID,
		cryptKey kbfscrypto.CryptPublicKey,
		teamMemChecker TeamMembershipChecker, extra ExtraMetadata) (bool, error)
	// DeepCopy returns a deep copy of the underlying data structure.
	DeepCopy(codec kbfscodec.Codec) (MutableBareRootMetadata, error)
	// MakeSuccessorCopy returns a newly constructed successor
	// copy to this metadata revision.  It differs from DeepCopy
	// in that it can perform an up conversion to a new metadata
	// version. tlfCryptKeyGetter should be a function that
	// returns a list of TLFCryptKeys for all key generations in
	// ascending order.
	MakeSuccessorCopy(codec kbfscodec.Codec, crypto cryptoPure,
		extra ExtraMetadata, latestMDVer MetadataVer,
		tlfCryptKeyGetter func() ([]kbfscrypto.TLFCryptKey, error),
		isReadableAndWriter bool) (mdCopy MutableBareRootMetadata,
		extraCopy ExtraMetadata, err error)
	// CheckValidSuccessor makes sure the given BareRootMetadata is a valid
	// successor to the current one, and returns an error otherwise.
	CheckValidSuccessor(currID kbfsmd.ID, nextMd BareRootMetadata) error
	// CheckValidSuccessorForServer is like CheckValidSuccessor but with
	// server-specific error messages.
	CheckValidSuccessorForServer(currID kbfsmd.ID, nextMd BareRootMetadata) error
	// IsValidAndSigned verifies the BareRootMetadata, checks the
	// writer signature, and returns an error if a problem was
	// found. This should be the first thing checked on a BRMD
	// retrieved from an untrusted source, and then the signing
	// user and key should be validated, either by comparing to
	// the current device key (using IsLastModifiedBy), or by
	// checking with KBPKI.
	IsValidAndSigned(ctx context.Context, codec kbfscodec.Codec,
		crypto cryptoPure, teamMemChecker TeamMembershipChecker,
		extra ExtraMetadata, writerVerifyingKey kbfscrypto.VerifyingKey) error
	// BID returns the per-device branch ID associated with this metadata revision.
	BID() BranchID
	// GetHistoricTLFCryptKey attempts to symmetrically decrypt the key at the given
	// generation using the current generation's TLFCryptKey.
	GetHistoricTLFCryptKey(c cryptoPure, keyGen KeyGen,
		currentKey kbfscrypto.TLFCryptKey, extra ExtraMetadata) (
		kbfscrypto.TLFCryptKey, error)
}

// MutableBareRootMetadata is a mutable interface to the bare serializeable MD that is signed by the reader or writer.
type MutableBareRootMetadata interface {
	BareRootMetadata

	kbfsmd.MutableRootMetadata

	// SetBranchID sets the branch ID for this metadata revision.
	SetBranchID(bid BranchID)

	// AddKeyGeneration adds a new key generation to this revision
	// of metadata. If StoresHistoricTLFCryptKeys is false, then
	// currCryptKey must be zero. Otherwise, currCryptKey must be
	// zero if there are no existing key generations, and non-zero
	// for otherwise.
	//
	// AddKeyGeneration must only be called on metadata for
	// private TLFs.
	//
	// Note that the TLFPrivateKey corresponding to privKey must
	// also be stored in PrivateMetadata.
	AddKeyGeneration(codec kbfscodec.Codec, crypto cryptoPure,
		currExtra ExtraMetadata,
		updatedWriterKeys, updatedReaderKeys UserDevicePublicKeys,
		ePubKey kbfscrypto.TLFEphemeralPublicKey,
		ePrivKey kbfscrypto.TLFEphemeralPrivateKey,
		pubKey kbfscrypto.TLFPublicKey,
		currCryptKey, nextCryptKey kbfscrypto.TLFCryptKey) (
		nextExtra ExtraMetadata,
		serverHalves UserDeviceKeyServerHalves, err error)

	// UpdateKeyBundles ensures that every device for every writer
	// and reader in the provided lists has complete TLF crypt key
	// info, and uses the new ephemeral key pair to generate the
	// info if it doesn't yet exist. tlfCryptKeys must contain an
	// entry for each key generation in KeyGenerationsToUpdate(),
	// in ascending order.
	//
	// updatedWriterKeys and updatedReaderKeys usually contains
	// the full maps of writers to per-device crypt public keys,
	// but for reader rekey, updatedWriterKeys will be empty and
	// updatedReaderKeys will contain only a single entry.
	//
	// UpdateKeyBundles must only be called on metadata for
	// private TLFs.
	//
	// An array of server halves to push to the server are
	// returned, with each entry corresponding to each key
	// generation in KeyGenerationsToUpdate(), in ascending order.
	UpdateKeyBundles(crypto cryptoPure, extra ExtraMetadata,
		updatedWriterKeys, updatedReaderKeys UserDevicePublicKeys,
		ePubKey kbfscrypto.TLFEphemeralPublicKey,
		ePrivKey kbfscrypto.TLFEphemeralPrivateKey,
		tlfCryptKeys []kbfscrypto.TLFCryptKey) (
		[]UserDeviceKeyServerHalves, error)

	// FinalizeRekey must be called called after all rekeying work
	// has been performed on the underlying metadata.
	FinalizeRekey(c cryptoPure, extra ExtraMetadata) error
}

// MakeInitialBareRootMetadata creates a new MutableBareRootMetadata
// instance of the given MetadataVer with revision
// RevisionInitial, and the given TLF ID and handle. Note that
// if the given ID/handle are private, rekeying must be done
// separately.
func MakeInitialBareRootMetadata(
	ver MetadataVer, tlfID tlf.ID, h tlf.Handle) (
	MutableBareRootMetadata, error) {
	if ver < kbfsmd.FirstValidMetadataVer {
		return nil, kbfsmd.InvalidMetadataVersionError{tlfID, ver}
	}
	if ver > kbfsmd.SegregatedKeyBundlesVer {
		// Shouldn't be possible at the moment.
		panic("Invalid metadata version")
	}
	if ver < kbfsmd.SegregatedKeyBundlesVer {
		return MakeInitialBareRootMetadataV2(tlfID, h)
	}

	return MakeInitialBareRootMetadataV3(tlfID, h)
}

func dumpConfig() *spew.ConfigState {
	c := spew.NewDefaultConfig()
	c.Indent = "  "
	c.DisablePointerAddresses = true
	c.DisableCapacities = true
	c.SortKeys = true
	return c
}

// DumpBareRootMetadata returns a detailed dump of the given
// BareRootMetadata's contents.
func DumpBareRootMetadata(
	codec kbfscodec.Codec, brmd BareRootMetadata) (string, error) {
	serializedBRMD, err := codec.Encode(brmd)
	if err != nil {
		return "", err
	}

	// Make a copy so we can zero out SerializedPrivateMetadata.
	brmdCopy, err := brmd.DeepCopy(codec)
	if err != nil {
		return "", err
	}

	switch brmdCopy := brmdCopy.(type) {
	case *BareRootMetadataV2:
		brmdCopy.SerializedPrivateMetadata = nil
	case *BareRootMetadataV3:
		brmdCopy.WriterMetadata.SerializedPrivateMetadata = nil
	default:
		// Do nothing, and let SerializedPrivateMetadata get
		// spewed, I guess.
	}
	s := fmt.Sprintf("MD size: %d bytes\n"+
		"MD version: %s\n\n", len(serializedBRMD), brmd.Version())
	s += dumpConfig().Sdump(brmdCopy)
	return s, nil
}
