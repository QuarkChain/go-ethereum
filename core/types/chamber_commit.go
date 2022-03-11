package types

import (
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Commit contains the evidence that a block was committed by a set of validators.
// NOTE: Commit is empty for height 1, but never nil.
type Commit struct {
	// NOTE: The signatures are in order of address to preserve the bonded
	// ValidatorSet order.
	// Any peer with a block can gossip signatures by index with a peer without
	// recalculating the active ValidatorSet.
	Height     uint64      `json:"height"` // must >= 0
	Round      uint32      `json:"round"`  // must >= 0
	BlockID    common.Hash `json:"block_id"`
	Signatures []CommitSig `json:"signatures"`

	// Memoized in first call to corresponding method.
	// NOTE: can't memoize in constructor because constructor isn't used for
	// unmarshaling.
	// hash common.Hash
	bitArray *BitArray
}

type commitRaw struct {
	Height     uint64      `json:"height"` // must >= 0
	Round      uint32      `json:"round"`  // must >= 0
	BlockID    common.Hash `json:"block_id"`
	Signatures []CommitSig `json:"signatures"`
}

// ValidateBasic performs basic validation that doesn't involve state data.
// Does not actually check the cryptographic signatures.
func (commit *Commit) ValidateBasic() error {
	if commit.Height >= 1 {
		if (commit.BlockID == common.Hash{}) {
			return errors.New("commit cannot be for nil block")
		}

		if len(commit.Signatures) == 0 {
			return errors.New("no signatures in commit")
		}

		for i, commitSig := range commit.Signatures {
			if err := commitSig.ValidateBasic(); err != nil {
				return fmt.Errorf("wrong CommitSig #%d: %v", i, err)
			}
		}
	}
	return nil
}

func (commit *Commit) Hash() common.Hash {
	data, err := rlp.EncodeToBytes(commit)
	if err != nil {
		panic("fail to rlp Commit")
	}
	return crypto.Keccak256Hash(data)
}

// GetVote converts the CommitSig for the given valIdx to a Vote.
// Returns nil if the precommit at valIdx is nil.
// Panics if valIdx >= commit.Size().
func (commit *Commit) GetVote(valIdx int32) *Vote {
	commitSig := commit.Signatures[valIdx]
	return &Vote{
		Type:             PrecommitType,
		Height:           commit.Height,
		Round:            SafeConvertInt32FromUint32(commit.Round),
		BlockID:          commitSig.BlockID(commit.BlockID),
		TimestampMs:      commitSig.TimestampMs,
		ValidatorAddress: commitSig.ValidatorAddress,
		ValidatorIndex:   valIdx,
		Signature:        commitSig.Signature,
	}
}

// VoteSignBytes returns the proto-encoding of the canonicalized Vote, for
// signing. Panics is the marshaling fails.
//
// The encoded Protobuf message is varint length-prefixed (using MarshalDelimited)
// for backwards-compatibility with the Amino encoding, due to e.g. hardware
// devices that rely on this encoding.
//
// See CanonicalizeVote
func (commit *Commit) VoteSignBytes(chainID string, idx int32) []byte {
	return commit.GetVote(idx).VoteSignBytes(chainID)
}

// GetByIndex returns the vote corresponding to a given validator index.
// Panics if `index >= commit.Size()`.
// Implements VoteSetReader.
func (commit *Commit) GetByIndex(valIdx int32) *Vote {
	return commit.GetVote(valIdx)
}

// GetHeight returns height of the commit.
// Implements VoteSetReader.
func (commit *Commit) GetHeight() uint64 {
	return commit.Height
}

// IsCommit returns true if there is at least one signature.
// Implements VoteSetReader.
func (commit *Commit) IsCommit() bool {
	return len(commit.Signatures) != 0
}

// Size returns the number of signatures in the commit.
// Implements VoteSetReader.
func (commit *Commit) Size() int {
	if commit == nil {
		return 0
	}
	return len(commit.Signatures)
}

// BitArray returns a BitArray of which validators voted for BlockID or nil in this commit.
// Implements VoteSetReader.
func (commit *Commit) BitArray() *BitArray {
	if commit.bitArray == nil {
		commit.bitArray = NewBitArray(len(commit.Signatures))
		for i, commitSig := range commit.Signatures {
			// TODO: need to check the BlockID otherwise we could be counting conflicts,
			// not just the one with +2/3 !
			commit.bitArray.SetIndex(i, !commitSig.Absent())
		}
	}
	return commit.bitArray
}

// GetRound returns height of the commit.
// Implements VoteSetReader.
func (commit *Commit) GetRound() int32 {
	return int32(commit.Round)
}

// Type returns the vote type of the commit, which is always VoteTypePrecommit
// Implements VoteSetReader.
func (commit *Commit) Type() byte {
	return byte(PrecommitType)
}

// Empty with zero signature.  Used as the commit for genesis.
var EmptyCommit = &Commit{Signatures: []CommitSig{}}

// NewCommit returns a new Commit.
func NewCommit(height uint64, round int32, blockID common.Hash, commitSigs []CommitSig) *Commit {
	return &Commit{
		Height:     height,
		Round:      SafeConvertUint32FromInt32(round),
		BlockID:    blockID,
		Signatures: commitSigs,
	}
}

func (v *Commit) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &commitRaw{
		Height:     uint64(v.Height),
		Round:      uint32(v.Round),
		BlockID:    v.BlockID,
		Signatures: v.Signatures,
	})
}

func (v *Commit) DecodeRLP(s *rlp.Stream) error {
	var vr commitRaw
	if err := s.Decode(&vr); err != nil {
		return err
	}

	v.Height = vr.Height
	v.Round = vr.Round
	v.BlockID = vr.BlockID
	v.Signatures = vr.Signatures

	return nil
}

// CommitToVoteSet constructs a VoteSet from the Commit and validator set.
// Panics if signatures from the commit can't be added to the voteset.
// Inverse of VoteSet.MakeCommit().
func CommitToVoteSet(chainID string, commit *Commit, vals *ValidatorSet) *VoteSet {
	voteSet := NewVoteSet(chainID, commit.Height, SafeConvertInt32FromUint32(commit.Round), PrecommitType, vals)
	for idx, commitSig := range commit.Signatures {
		if commitSig.Absent() {
			continue // OK, some precommits can be missing.
		}
		added, err := voteSet.AddVote(commit.GetVote(int32(idx)))
		if !added || err != nil {
			panic(fmt.Sprintf("Failed to reconstruct LastCommit: %v", err))
		}
	}
	return voteSet
}
