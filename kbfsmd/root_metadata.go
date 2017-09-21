// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/kbfs/kbfscodec"
	"github.com/keybase/kbfs/kbfscrypto"
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
	// IsRekeySet returns true if the rekey bit is set.
	IsRekeySet() bool
	// IsWriterMetadataCopiedSet returns true if the bit is set indicating
	// the writer metadata was copied.
	IsWriterMetadataCopiedSet() bool
	// IsFinal returns true if this is the last metadata block for a given
	// folder.  This is only expected to be set for folder resets.
	IsFinal() bool
	// MakeBareTlfHandle makes a tlf.Handle for this
	// BareRootMetadata. Should be used only by servers and MDOps.
	MakeBareTlfHandle(extra ExtraMetadata) (tlf.Handle, error)
	// TlfHandleExtensions returns a list of handle extensions associated with the TLf.
	TlfHandleExtensions() (extensions []tlf.HandleExtension)
	// GetDevicePublicKeys returns the kbfscrypto.CryptPublicKeys
	// for all known users and devices. Returns an error if the
	// TLF is public.
	GetUserDevicePublicKeys(extra ExtraMetadata) (
		writers, readers UserDevicePublicKeys, err error)
	// GetTLFCryptKeyParams returns all the necessary info to construct
	// the TLF crypt key for the given key generation, user, and device
	// (identified by its crypt public key), or false if not found. This
	// returns an error if the TLF is public.
	GetTLFCryptKeyParams(keyGen KeyGen, user keybase1.UID,
		key kbfscrypto.CryptPublicKey, extra ExtraMetadata) (
		kbfscrypto.TLFEphemeralPublicKey,
		EncryptedTLFCryptKeyClientHalf,
		TLFCryptKeyServerHalfID, bool, error)
	// IsLastModifiedBy verifies that the BareRootMetadata is
	// written by the given user and device (identified by the
	// device verifying key), and returns an error if not.
	IsLastModifiedBy(uid keybase1.UID, key kbfscrypto.VerifyingKey) error
	// LastModifyingWriter return the UID of the last user to modify the writer metadata.
	LastModifyingWriter() keybase1.UID
	// LastModifyingUser return the UID of the last user to modify the any of the metadata.
	GetLastModifyingUser() keybase1.UID
	// RefBytes returns the number of newly referenced bytes of data blocks introduced by this revision of metadata.
	RefBytes() uint64
	// UnrefBytes returns the number of newly unreferenced bytes introduced by this revision of metadata.
	UnrefBytes() uint64
	// MDRefBytes returns the number of newly referenced bytes of MD blocks introduced by this revision of metadata.
	MDRefBytes() uint64
	// DiskUsage returns the estimated disk usage for the folder as of this revision of metadata.
	DiskUsage() uint64
	// MDDiskUsage returns the estimated MD disk usage for the folder as of this revision of metadata.
	MDDiskUsage() uint64
	// RevisionNumber returns the revision number associated with this metadata structure.
	RevisionNumber() Revision
	// MerkleRoot returns the root of the global Keybase Merkle tree
	// at the time the MD was written.
	MerkleRoot() keybase1.MerkleRootV2

	// GetSerializedPrivateMetadata returns the serialized private metadata as a byte slice.
	GetSerializedPrivateMetadata() []byte
	// GetPrevRoot returns the hash of the previous metadata revision.
	GetPrevRoot() ID
	// IsUnmergedSet returns true if the unmerged bit is set.
	IsUnmergedSet() bool
	// GetSerializedWriterMetadata serializes the underlying writer metadata and returns the result.
	GetSerializedWriterMetadata(codec kbfscodec.Codec) ([]byte, error)
	// Version returns the metadata version.
	Version() MetadataVer
	// GetCurrentTLFPublicKey returns the TLF public key for the
	// current key generation.
	GetCurrentTLFPublicKey(ExtraMetadata) (kbfscrypto.TLFPublicKey, error)
	// GetUnresolvedParticipants returns any unresolved readers
	// and writers present in this revision of metadata. The
	// returned array should be safe to modify by the caller.
	GetUnresolvedParticipants() []keybase1.SocialAssertion
	// GetTLFWriterKeyBundleID returns the ID of the externally-stored writer key bundle, or the zero value if
	// this object stores it internally.
	GetTLFWriterKeyBundleID() TLFWriterKeyBundleID
	// GetTLFReaderKeyBundleID returns the ID of the externally-stored reader key bundle, or the zero value if
	// this object stores it internally.
	GetTLFReaderKeyBundleID() TLFReaderKeyBundleID
	// StoresHistoricTLFCryptKeys returns whether or not history keys are symmetrically encrypted; if not, they're
	// encrypted per-device.
	StoresHistoricTLFCryptKeys() bool
}
