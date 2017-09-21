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
	// IsRekeySet returns true if the rekey bit is set.
	IsRekeySet() bool
	// IsWriterMetadataCopiedSet returns true if the bit is set indicating
	// the writer metadata was copied.
	IsWriterMetadataCopiedSet() bool
	// IsFinal returns true if this is the last metadata block for a given
	// folder.  This is only expected to be set for folder resets.
	IsFinal() bool
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
	RevisionNumber() kbfsmd.Revision
	// MerkleRoot returns the root of the global Keybase Merkle tree
	// at the time the MD was written.
	MerkleRoot() keybase1.MerkleRootV2
	// BID returns the per-device branch ID associated with this metadata revision.
	BID() BranchID
	// GetPrevRoot returns the hash of the previous metadata revision.
	GetPrevRoot() kbfsmd.ID
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
	// GetHistoricTLFCryptKey attempts to symmetrically decrypt the key at the given
	// generation using the current generation's TLFCryptKey.
	GetHistoricTLFCryptKey(c cryptoPure, keyGen KeyGen,
		currentKey kbfscrypto.TLFCryptKey, extra ExtraMetadata) (
		kbfscrypto.TLFCryptKey, error)
}

// MutableBareRootMetadata is a mutable interface to the bare serializeable MD that is signed by the reader or writer.
type MutableBareRootMetadata interface {
	BareRootMetadata

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
	// SetBranchID sets the branch ID for this metadata revision.
	SetBranchID(bid BranchID)
	// SetPrevRoot sets the hash of the previous metadata revision.
	SetPrevRoot(mdID kbfsmd.ID)
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
	SetRevision(revision kbfsmd.Revision)
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

	// SetLatestKeyGenerationForTeamTLF sets the latest key generation
	// number of a team TLF.  It is not valid to call this for
	// anything but a team TLF.
	SetLatestKeyGenerationForTeamTLF(keyGen KeyGen)

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
