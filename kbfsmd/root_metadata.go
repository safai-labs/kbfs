// Copyright 2017 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package kbfsmd

import (
	"golang.org/x/net/context"

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

type MutableRootMetadata interface {

	// SetRefBytes sets the number of newly referenced bytes of data blocks introduced by this revision of metadata.
	SetRefBytes(refBytes uint64)
	// SetUnrefBytes sets the number of newly unreferenced bytes introduced by this revision of metadata.
	SetUnrefBytes(unrefBytes uint64)
	// SetMDRefBytes sets the number of newly referenced bytes of MD blocks introduced by this revision of metadata.
	SetMDRefBytes(mdRefBytes uint64)
	// SetDiskUsage sets the estimated disk usage for the folder as of this revision of metadata.
	SetDiskUsage(diskUsage uint64)
	// SetMDDiskUsage sets the estimated MD disk usage for the folder as of this revision of metadata.
	SetMDDiskUsage(mdDiskUsage uint64)
	// AddRefBytes increments the number of newly referenced bytes of data blocks introduced by this revision of metadata.
	AddRefBytes(refBytes uint64)
	// AddUnrefBytes increments the number of newly unreferenced bytes introduced by this revision of metadata.
	AddUnrefBytes(unrefBytes uint64)
	// AddMDRefBytes increments the number of newly referenced bytes of MD blocks introduced by this revision of metadata.
	AddMDRefBytes(mdRefBytes uint64)
	// AddDiskUsage increments the estimated disk usage for the folder as of this revision of metadata.
	AddDiskUsage(diskUsage uint64)
	// AddMDDiskUsage increments the estimated MD disk usage for the folder as of this revision of metadata.
	AddMDDiskUsage(mdDiskUsage uint64)
	// ClearRekeyBit unsets any set rekey bit.
	ClearRekeyBit()
	// ClearWriterMetadataCopiedBit unsets any set writer metadata copied bit.
	ClearWriterMetadataCopiedBit()
	// ClearFinalBit unsets any final bit.
	ClearFinalBit()
	// SetUnmerged sets the unmerged bit.
	SetUnmerged()

	// SetPrevRoot sets the hash of the previous metadata revision.
	SetPrevRoot(mdID ID)
	// SetSerializedPrivateMetadata sets the serialized private metadata.
	SetSerializedPrivateMetadata(spmd []byte)
	// SignWriterMetadataInternally signs the writer metadata, for
	// versions that store this signature inside the metadata.
	SignWriterMetadataInternally(ctx context.Context,
		codec kbfscodec.Codec, signer kbfscrypto.Signer) error
	// SetLastModifyingWriter sets the UID of the last user to modify the writer metadata.
	SetLastModifyingWriter(user keybase1.UID)
	// SetLastModifyingUser sets the UID of the last user to modify any of the metadata.
	SetLastModifyingUser(user keybase1.UID)
	// SetRekeyBit sets the rekey bit.
	SetRekeyBit()
	// SetFinalBit sets the finalized bit.
	SetFinalBit()
	// SetWriterMetadataCopiedBit set the writer metadata copied bit.
	SetWriterMetadataCopiedBit()
	// SetRevision sets the revision number of the underlying metadata.
	SetRevision(revision Revision)
	// SetMerkleRoot sets the root of the global Keybase Merkle tree
	// at the time the MD was written.
	SetMerkleRoot(root keybase1.MerkleRootV2)
	// SetUnresolvedReaders sets the list of unresolved readers associated with this folder.
	SetUnresolvedReaders(readers []keybase1.SocialAssertion)
	// SetUnresolvedWriters sets the list of unresolved writers associated with this folder.
	SetUnresolvedWriters(writers []keybase1.SocialAssertion)
	// SetConflictInfo sets any conflict info associated with this metadata revision.
	SetConflictInfo(ci *tlf.HandleExtension)
	// SetFinalizedInfo sets any finalized info associated with this metadata revision.
	SetFinalizedInfo(fi *tlf.HandleExtension)
	// SetWriters sets the list of writers associated with this folder.
	SetWriters(writers []keybase1.UserOrTeamID)
	// SetTlfID sets the ID of the underlying folder in the metadata structure.
	SetTlfID(tlf tlf.ID)

	// SetLatestKeyGenerationForTeamTLF sets the latest key generation
	// number of a team TLF.  It is not valid to call this for
	// anything but a team TLF.
	SetLatestKeyGenerationForTeamTLF(keyGen KeyGen)

	// PromoteReaders converts the given set of users (which may
	// be empty) from readers to writers.
	PromoteReaders(readersToPromote map[keybase1.UID]bool,
		extra ExtraMetadata) error

	// RevokeRemovedDevices removes key info for any device not in
	// the given maps, and returns a corresponding map of server
	// halves to delete from the server.
	//
	// Note: the returned server halves may not be for all key
	// generations, e.g. for MDv3 it's only for the latest key
	// generation.
	RevokeRemovedDevices(
		updatedWriterKeys, updatedReaderKeys UserDevicePublicKeys,
		extra ExtraMetadata) (ServerHalfRemovalInfo, error)
}
