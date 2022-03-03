package types

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type ValidatorSet struct {
	// NOTE: persisted via reflect, must be exported.
	Validators        []*Validator `json:"validators"`
	Proposer          *Validator   `json:"proposer"`
	proposerReptition int64
}

func NewValidatorSet(addrs []common.Address, proposerReptition int64) *ValidatorSet {
	validators := make([]*Validator, len(addrs))
	for i, addr := range addrs {
		pubkey := NewEcdsaPubKey(addr)
		validators[i] = &Validator{Address: addr, PubKey: pubkey}
	}
	return &ValidatorSet{Validators: validators, proposerReptition: proposerReptition}
}

// HasAddress returns true if address given is in the validator set, false -
// otherwise.
func (vals *ValidatorSet) HasAddress(address common.Address) bool {
	for _, val := range vals.Validators {
		if val.Address == address {
			return true
		}
	}
	return false
}

// GetByAddress returns an index of the validator with address and validator
// itself (copy) if found. Otherwise, -1 and nil are returned.
func (vals *ValidatorSet) GetByAddress(address common.Address) (index int32, val *Validator) {
	for idx, val := range vals.Validators {
		if val.Address == address {
			return int32(idx), val.Copy()
		}
	}
	return -1, nil
}

// GetByIndex returns the validator's address and validator itself (copy) by
// index.
// It returns nil values if index is less than 0 or greater or equal to
// len(ValidatorSet.Validators).
func (vals *ValidatorSet) GetByIndex(index int32) (address common.Address, val *Validator) {
	if index < 0 || int(index) >= len(vals.Validators) {
		return common.Address{}, nil
	}
	val = vals.Validators[index]
	return val.Address, val.Copy()
}

// Size returns the length of the validator set.
func (vals *ValidatorSet) Size() int {
	return len(vals.Validators)
}

func (vals *ValidatorSet) TotalVotingPower() int64 {
	return int64(len(vals.Validators))
}

// Makes a copy of the validator list.
func validatorListCopy(valsList []*Validator) []*Validator {
	if valsList == nil {
		return nil
	}
	valsCopy := make([]*Validator, len(valsList))
	for i, val := range valsList {
		valsCopy[i] = val.Copy()
	}
	return valsCopy
}

// IsNilOrEmpty returns true if validator set is nil or empty.
func (vals *ValidatorSet) IsNilOrEmpty() bool {
	return vals == nil || len(vals.Validators) == 0
}

func (vals *ValidatorSet) incrementProposerPriority() *Validator {
	// simple RR with 8 repetitions
	for i, val := range vals.Validators {
		if val.ProposerPriority != 0 {
			val.ProposerPriority += 1
			if val.ProposerPriority > vals.proposerReptition {
				val.ProposerPriority = 0
				i = i + 1
				if i >= len(vals.Validators) {
					i = 0
				}
				vals.Validators[i].ProposerPriority = 1
				return vals.Validators[i]
			}
			return val
		}
	}

	// all zeros, start with the first one with priority 1
	vals.Validators[0].ProposerPriority = 1
	return vals.Validators[0]
}

func (vals *ValidatorSet) findProposer() *Validator {
	for _, val := range vals.Validators {
		if val.ProposerPriority != 0 {
			return val
		}
	}
	return vals.Validators[0]
}

func (vals *ValidatorSet) GetProposer() *Validator {
	if len(vals.Validators) == 0 {
		return nil
	}
	if vals.Proposer == nil {
		vals.Proposer = vals.findProposer()
	}
	return vals.Proposer.Copy()
}

// IncrementProposerPriority increments ProposerPriority of each validator and
// updates the proposer. Panics if validator set is empty.
// `times` must be positive.
func (vals *ValidatorSet) IncrementProposerPriority(times int32) {
	if vals.IsNilOrEmpty() {
		panic("empty validator set")
	}
	if times <= 0 {
		panic("Cannot call IncrementProposerPriority with non-positive times")
	}

	var proposer *Validator
	// Call IncrementProposerPriority(1) times times.
	for i := int32(0); i < times; i++ {
		proposer = vals.incrementProposerPriority()
	}

	vals.Proposer = proposer
}

// Copy each validator into a new ValidatorSet.
func (vals *ValidatorSet) Copy() *ValidatorSet {
	return &ValidatorSet{
		Validators:        validatorListCopy(vals.Validators),
		Proposer:          vals.Proposer,
		proposerReptition: vals.proposerReptition,
	}
}

// VerifyCommit verifies +2/3 of the set had signed the given commit and all
// other signatures are valid
func (vals *ValidatorSet) VerifyCommit(chainID string, blockID common.Hash,
	height uint64, commit *Commit) error {
	return VerifyCommit(chainID, vals, blockID, height, commit)
}

// VerifyCommit verifies +2/3 of the set had signed the given commit.
//
// It checks all the signatures! While it's safe to exit as soon as we have
// 2/3+ signatures, doing so would impact incentivization logic in the ABCI
// application that depends on the LastCommitInfo sent in BeginBlock, which
// includes which validators signed. For instance, Gaia incentivizes proposers
// with a bonus for including more than +2/3 of the signatures.
func VerifyCommit(chainID string, vals *ValidatorSet, blockID common.Hash,
	height uint64, commit *Commit) error {
	// run a basic validation of the arguments
	if err := verifyBasicValsAndCommit(vals, commit, height, blockID); err != nil {
		return err
	}

	// calculate voting power needed. Note that total voting power is capped to
	// 1/8th of max int64 so this operation should never overflow
	votingPowerNeeded := vals.TotalVotingPower() * 2 / 3

	// ignore all absent signatures
	ignore := func(c CommitSig) bool { return c.Absent() }

	// only count the signatures that are for the block
	count := func(c CommitSig) bool { return c.ForBlock() }

	// attempt to batch verify
	// if shouldBatchVerify(vals, commit) {
	// 	return verifyCommitBatch(chainID, vals, commit,
	// 		votingPowerNeeded, ignore, count, true, true)
	// }

	// if verification failed or is not supported then fallback to single verification
	return verifyCommitSingle(chainID, vals, commit, votingPowerNeeded,
		ignore, count, true, true)
}

// Batch verification

// Single Verification

// verifyCommitSingle single verifies commits.
// If a key does not support batch verification, or batch verification fails this will be used
// This method is used to check all the signatures included in a commit.
// It is used in consensus for validating a block LastCommit.
// CONTRACT: both commit and validator set should have passed validate basic
func verifyCommitSingle(
	chainID string,
	vals *ValidatorSet,
	commit *Commit,
	votingPowerNeeded int64,
	ignoreSig func(CommitSig) bool,
	countSig func(CommitSig) bool,
	countAllSignatures bool,
	lookUpByIndex bool,
) error {
	var (
		val                *Validator
		valIdx             int32
		talliedVotingPower int64
		voteSignBytes      []byte
		seenVals           = make(map[int32]int, len(commit.Signatures))
	)
	for idx, commitSig := range commit.Signatures {
		if ignoreSig(commitSig) {
			continue
		}

		// If the vals and commit have a 1-to-1 correspondance we can retrieve
		// them by index else we need to retrieve them by address
		if lookUpByIndex {
			val = vals.Validators[idx]
		} else {
			valIdx, val = vals.GetByAddress(commitSig.ValidatorAddress)

			// if the signature doesn't belong to anyone in the validator set
			// then we just skip over it
			if val == nil {
				continue
			}

			// because we are getting validators by address we need to make sure
			// that the same validator doesn't commit twice
			if firstIndex, ok := seenVals[valIdx]; ok {
				secondIndex := idx
				return fmt.Errorf("double vote from %v (%d and %d)", val, firstIndex, secondIndex)
			}
			seenVals[valIdx] = idx
		}

		voteSignBytes = commit.VoteSignBytes(chainID, int32(idx))

		if !val.PubKey.VerifySignature(voteSignBytes, commitSig.Signature) {
			return fmt.Errorf("wrong signature (#%d): %X", idx, commitSig.Signature)
		}

		// If this signature counts then add the voting power of the validator
		// to the tally
		if countSig(commitSig) {
			talliedVotingPower += val.VotingPower()
		}

		// check if we have enough signatures and can thus exit early
		if !countAllSignatures && talliedVotingPower > votingPowerNeeded {
			return nil
		}
	}

	if got, needed := talliedVotingPower, votingPowerNeeded; got <= needed {
		return ErrNotEnoughVotingPowerSigned{Got: got, Needed: needed}
	}

	return nil
}

func verifyBasicValsAndCommit(vals *ValidatorSet, commit *Commit, height uint64, blockID common.Hash) error {
	if vals == nil {
		return errors.New("nil validator set")
	}

	if commit == nil {
		return errors.New("nil commit")
	}

	if vals.Size() != len(commit.Signatures) {
		return NewErrInvalidCommitSignatures(vals.Size(), len(commit.Signatures))
	}

	// Validate Height and BlockID.
	if height != commit.Height {
		return NewErrInvalidCommitHeight(height, commit.Height)
	}
	if blockID != commit.BlockID {
		return fmt.Errorf("invalid commit -- wrong block ID: want %v, got %v",
			blockID, commit.BlockID)
	}

	return nil
}

type (
	// ErrInvalidCommitHeight is returned when we encounter a commit with an
	// unexpected height.
	ErrInvalidCommitHeight struct {
		Expected uint64
		Actual   uint64
	}

	// ErrInvalidCommitSignatures is returned when we encounter a commit where
	// the number of signatures doesn't match the number of validators.
	ErrInvalidCommitSignatures struct {
		Expected int
		Actual   int
	}
)

func NewErrInvalidCommitHeight(expected, actual uint64) ErrInvalidCommitHeight {
	return ErrInvalidCommitHeight{
		Expected: expected,
		Actual:   actual,
	}
}

func (e ErrInvalidCommitHeight) Error() string {
	return fmt.Sprintf("Invalid commit -- wrong height: %v vs %v", e.Expected, e.Actual)
}

func NewErrInvalidCommitSignatures(expected, actual int) ErrInvalidCommitSignatures {
	return ErrInvalidCommitSignatures{
		Expected: expected,
		Actual:   actual,
	}
}

func (e ErrInvalidCommitSignatures) Error() string {
	return fmt.Sprintf("Invalid commit -- wrong set size: %v vs %v", e.Expected, e.Actual)
}

// IsErrNotEnoughVotingPowerSigned returns true if err is
// ErrNotEnoughVotingPowerSigned.
func IsErrNotEnoughVotingPowerSigned(err error) bool {
	return errors.As(err, &ErrNotEnoughVotingPowerSigned{})
}

// ErrNotEnoughVotingPowerSigned is returned when not enough validators signed
// a commit.
type ErrNotEnoughVotingPowerSigned struct {
	Got    int64
	Needed int64
}

func (e ErrNotEnoughVotingPowerSigned) Error() string {
	return fmt.Sprintf("invalid commit -- insufficient voting power: got %d, needed more than %d", e.Got, e.Needed)
}
