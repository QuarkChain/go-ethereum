package types

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// MaxTotalVotingPower - the maximum allowed total voting power.
	// It needs to be sufficiently small to, in all cases:
	// 1. prevent clipping in incrementProposerPriority()
	// 2. let (diff+diffMax-1) not overflow in IncrementProposerPriority()
	// (Proof of 1 is tricky, left to the reader).
	// It could be higher, but this is sufficiently large for our purposes,
	// and leaves room for defensive purposes.
	MaxTotalVotingPower = int64(math.MaxInt64) / 8

	// PriorityWindowSizeFactor - is a constant that when multiplied with the
	// total voting power gives the maximum allowed distance between validator
	// priorities.
	PriorityWindowSizeFactor = 2
)

type ValidatorSet struct {
	// NOTE: persisted via reflect, must be exported.
	Validators        []*Validator `json:"validators"`
	Proposer          *Validator   `json:"proposer"`
	ProposerReptition int64

	// cached (unexported)
	totalVotingPower int64
}

func NewValidatorSet(addrs []common.Address, votingPowers []int64, proposerReptition int64) *ValidatorSet {
	if len(addrs) != len(votingPowers) {
		panic("len(addrs) != len(votingPowers")
	}

	validators := make([]*Validator, len(addrs))
	for i, addr := range addrs {
		pubkey := NewEcdsaPubKey(addr)
		if votingPowers[i] <= 0 || votingPowers[i] > MaxTotalVotingPower {
			panic("invalid voting power")
		}
		validators[i] = &Validator{Address: addr, VotingPower: votingPowers[i], PubKey: pubkey}
	}
	vals := &ValidatorSet{Validators: validators, ProposerReptition: proposerReptition}
	if len(addrs) > 0 {
		vals.IncrementProposerPriority(1)
	}
	return vals
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

// Forces recalculation of the set's total voting power.
// Panics if total voting power is bigger than MaxTotalVotingPower.
func (vals *ValidatorSet) updateTotalVotingPower() {
	sum := int64(0)
	for _, val := range vals.Validators {
		// mind overflow
		sum = safeAddClip(sum, val.VotingPower)
		if sum > MaxTotalVotingPower {
			panic(fmt.Sprintf(
				"Total voting power should be guarded to not exceed %v; got: %v",
				MaxTotalVotingPower,
				sum))
		}
	}

	vals.totalVotingPower = sum
}

func (vals *ValidatorSet) TotalVotingPower() int64 {
	if vals.totalVotingPower == 0 {
		vals.updateTotalVotingPower()
	}
	return vals.totalVotingPower
}

// GetProposer returns the current proposer. If the validator set is empty, nil
// is returned.
func (vals *ValidatorSet) GetProposer() (proposer *Validator) {
	if len(vals.Validators) == 0 {
		return nil
	}
	if vals.Proposer == nil {
		vals.Proposer = vals.findProposer()
	}
	return vals.Proposer.Copy()
}

func (vals *ValidatorSet) findProposer() *Validator {
	var proposer *Validator
	for _, val := range vals.Validators {
		if proposer == nil || !bytes.Equal(val.Address[:], proposer.Address[:]) {
			proposer = proposer.CompareProposerPriority(val)
		}
	}
	return proposer
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

func (vals *ValidatorSet) incrementProposerRepetitionTimes() *Validator {
	// simple RR with repetitions
	for _, val := range vals.Validators {
		if val.ProposerReptitionTimes != 0 {
			val.ProposerReptitionTimes += 1
			if val.ProposerReptitionTimes > vals.ProposerReptition {
				val.ProposerReptitionTimes = 0
				break
			}
			return val
		}
	}

	// Cap the difference between priorities to be proportional to 2*totalPower by
	// re-normalizing priorities, i.e., rescale all priorities by multiplying with:
	//  2*totalVotingPower/(maxPriority - minPriority)
	diffMax := PriorityWindowSizeFactor * vals.TotalVotingPower()
	vals.RescalePriorities(diffMax)
	vals.shiftByAvgProposerPriority()

	proposer := vals.incrementProposerPriority()
	proposer.ProposerReptitionTimes = 1

	return proposer
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
	for i := int32(0); i < times; i++ {
		proposer = vals.incrementProposerRepetitionTimes()
	}

	vals.Proposer = proposer
}

// RescalePriorities rescales the priorities such that the distance between the
// maximum and minimum is smaller than `diffMax`. Panics if validator set is
// empty.
func (vals *ValidatorSet) RescalePriorities(diffMax int64) {
	if vals.IsNilOrEmpty() {
		panic("empty validator set")
	}
	// NOTE: This check is merely a sanity check which could be
	// removed if all tests would init. voting power appropriately;
	// i.e. diffMax should always be > 0
	if diffMax <= 0 {
		return
	}

	// Calculating ceil(diff/diffMax):
	// Re-normalization is performed by dividing by an integer for simplicity.
	// NOTE: This may make debugging priority issues easier as well.
	diff := computeMaxMinPriorityDiff(vals)
	ratio := (diff + diffMax - 1) / diffMax
	if diff > diffMax {
		for _, val := range vals.Validators {
			val.ProposerPriority /= ratio
		}
	}
}

func (vals *ValidatorSet) incrementProposerPriority() *Validator {
	for _, val := range vals.Validators {
		// Check for overflow for sum.
		newPrio := safeAddClip(val.ProposerPriority, val.VotingPower)
		val.ProposerPriority = newPrio
	}
	// Decrement the validator with most ProposerPriority.
	mostest := vals.getValWithMostPriority()
	// Mind the underflow.
	mostest.ProposerPriority = safeSubClip(mostest.ProposerPriority, vals.TotalVotingPower())

	return mostest
}

// Compute the difference between the max and min ProposerPriority of that set.
func computeMaxMinPriorityDiff(vals *ValidatorSet) int64 {
	if vals.IsNilOrEmpty() {
		panic("empty validator set")
	}
	max := int64(math.MinInt64)
	min := int64(math.MaxInt64)
	for _, v := range vals.Validators {
		if v.ProposerPriority < min {
			min = v.ProposerPriority
		}
		if v.ProposerPriority > max {
			max = v.ProposerPriority
		}
	}
	diff := max - min
	if diff < 0 {
		return -1 * diff
	}
	return diff
}

func (vals *ValidatorSet) getValWithMostPriority() *Validator {
	var res *Validator
	for _, val := range vals.Validators {
		res = res.CompareProposerPriority(val)
	}
	return res
}

func (vals *ValidatorSet) shiftByAvgProposerPriority() {
	if vals.IsNilOrEmpty() {
		panic("empty validator set")
	}
	avgProposerPriority := vals.computeAvgProposerPriority()
	for _, val := range vals.Validators {
		val.ProposerPriority = safeSubClip(val.ProposerPriority, avgProposerPriority)
	}
}

// Should not be called on an empty validator set.
func (vals *ValidatorSet) computeAvgProposerPriority() int64 {
	n := int64(len(vals.Validators))
	sum := big.NewInt(0)
	for _, val := range vals.Validators {
		sum.Add(sum, big.NewInt(val.ProposerPriority))
	}
	avg := sum.Div(sum, big.NewInt(n))
	if avg.IsInt64() {
		return avg.Int64()
	}

	// This should never happen: each val.ProposerPriority is in bounds of int64.
	panic(fmt.Sprintf("Cannot represent avg ProposerPriority as an int64 %v", avg))
}

func safeAdd(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return -1, true
	} else if b < 0 && a < math.MinInt64-b {
		return -1, true
	}
	return a + b, false
}

func safeSub(a, b int64) (int64, bool) {
	if b > 0 && a < math.MinInt64+b {
		return -1, true
	} else if b < 0 && a > math.MaxInt64+b {
		return -1, true
	}
	return a - b, false
}

func safeAddClip(a, b int64) int64 {
	c, overflow := safeAdd(a, b)
	if overflow {
		if b < 0 {
			return math.MinInt64
		}
		return math.MaxInt64
	}
	return c
}

func safeSubClip(a, b int64) int64 {
	c, overflow := safeSub(a, b)
	if overflow {
		if b > 0 {
			return math.MinInt64
		}
		return math.MaxInt64
	}
	return c
}

// Copy each validator into a new ValidatorSet.
func (vals *ValidatorSet) Copy() *ValidatorSet {
	return &ValidatorSet{
		Validators:        validatorListCopy(vals.Validators),
		Proposer:          vals.Proposer,
		ProposerReptition: vals.ProposerReptition,
	}
}

// Returns the one with higher ProposerPriority.
func (v *Validator) CompareProposerPriority(other *Validator) *Validator {
	if v == nil {
		return other
	}
	switch {
	case v.ProposerPriority > other.ProposerPriority:
		return v
	case v.ProposerPriority < other.ProposerPriority:
		return other
	default:
		result := bytes.Compare(v.Address[:], other.Address[:])
		switch {
		case result < 0:
			return v
		case result > 0:
			return other
		default:
			panic("Cannot compare identical validators")
		}
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
			talliedVotingPower += val.VotingPower
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
