package types

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrVoteUnexpectedStep            = errors.New("unexpected step")
	ErrVoteInvalidValidatorIndex     = errors.New("invalid validator index")
	ErrVoteInvalidValidatorAddress   = errors.New("invalid validator address")
	ErrVoteInvalidSignature          = errors.New("invalid signature")
	ErrVoteInvalidBlockHash          = errors.New("invalid block hash")
	ErrVoteNonDeterministicSignature = errors.New("non-deterministic signature")
	ErrVoteNil                       = errors.New("nil vote")
)

type ErrVoteConflictingVotes struct {
	VoteA *Vote
	VoteB *Vote
}

func (err *ErrVoteConflictingVotes) Error() string {
	return fmt.Sprintf("conflicting votes from validator %X", err.VoteA.ValidatorAddress)
}

func NewConflictingVoteError(vote1, vote2 *Vote) *ErrVoteConflictingVotes {
	return &ErrVoteConflictingVotes{
		VoteA: vote1,
		VoteB: vote2,
	}
}

type blockVotes struct {
	peerMaj23 bool    // peer claims to have maj23
	votes     []*Vote // valIndex -> *Vote
	sum       int64   // vote sum
}

func newBlockVotes(peerMaj23 bool, numValidators int) *blockVotes {
	return &blockVotes{
		peerMaj23: peerMaj23,
		votes:     make([]*Vote, numValidators),
		sum:       0,
	}
}

func (vs *blockVotes) addVerifiedVote(vote *Vote, votingPower int64) {
	valIndex := vote.ValidatorIndex
	if existing := vs.votes[valIndex]; existing == nil {
		vs.votes[valIndex] = vote
		vs.sum += votingPower
	}
}

func (vs *blockVotes) getByIndex(index int32) *Vote {
	if vs == nil {
		return nil
	}
	return vs.votes[index]
}

type VoteSet struct {
	chainID       string
	height        uint64
	round         int32
	signedMsgType SignedMsgType
	valSet        *ValidatorSet

	mtx           sync.Mutex
	votesBitArray *BitArray
	votes         []*Vote                     // Primary votes to share
	sum           int64                       // Sum of voting power for seen votes, discounting conflicts
	maj23         *common.Hash                // First 2/3 majority seen
	votesByBlock  map[common.Hash]*blockVotes // string(blockHash|blockParts) -> blockVotes
	peerMaj23s    map[string]common.Hash      // Maj23 for each peer
}

// Constructs a new VoteSet struct used to accumulate votes for given height/round.
func NewVoteSet(chainID string, height uint64, round int32,
	signedMsgType SignedMsgType, valSet *ValidatorSet) *VoteSet {
	if height == 0 {
		panic("Cannot make VoteSet for height == 0, doesn't make sense.")
	}
	return &VoteSet{
		chainID:       chainID,
		height:        height,
		round:         round,
		signedMsgType: signedMsgType,
		valSet:        valSet,
		votesBitArray: NewBitArray(valSet.Size()),
		votes:         make([]*Vote, valSet.Size()),
		sum:           0,
		maj23:         nil,
		votesByBlock:  make(map[common.Hash]*blockVotes, valSet.Size()),
		peerMaj23s:    make(map[string]common.Hash),
	}
}

// Returns added=true if vote is valid and new.
// Otherwise returns err=ErrVote[
//		UnexpectedStep | InvalidIndex | InvalidAddress |
//		InvalidSignature | InvalidBlockHash | ConflictingVotes ]
// Duplicate votes return added=false, err=nil.
// Conflicting votes return added=*, err=ErrVoteConflictingVotes.
// NOTE: vote should not be mutated after adding.
// NOTE: VoteSet must not be nil
// NOTE: Vote must not be nil
func (voteSet *VoteSet) AddVote(vote *Vote) (added bool, err error) {
	if voteSet == nil {
		panic("AddVote() on nil VoteSet")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	return voteSet.addVote(vote)
}

// NOTE: Validates as much as possible before attempting to verify the signature.
func (voteSet *VoteSet) addVote(vote *Vote) (added bool, err error) {
	if vote == nil {
		return false, ErrVoteNil
	}
	valIndex := vote.ValidatorIndex
	valAddr := vote.ValidatorAddress
	blockKey := vote.BlockID

	// Ensure that validator index was set
	if valIndex < 0 {
		return false, fmt.Errorf("index < 0: %w", ErrVoteInvalidValidatorIndex)
	} else if len(valAddr) == 0 {
		return false, fmt.Errorf("empty address: %w", ErrVoteInvalidValidatorAddress)
	}

	// Make sure the step matches.
	if (vote.Height != voteSet.height) ||
		(vote.Round != voteSet.round) ||
		(vote.Type != voteSet.signedMsgType) {
		return false, fmt.Errorf("expected %d/%d/%d, but got %d/%d/%d: %w",
			voteSet.height, voteSet.round, voteSet.signedMsgType,
			vote.Height, vote.Round, vote.Type, ErrVoteUnexpectedStep)
	}

	// Ensure that signer is a validator.
	lookupAddr, val := voteSet.valSet.GetByIndex(valIndex)
	if val == nil {
		return false, fmt.Errorf(
			"cannot find validator %d in valSet of size %d: %w",
			valIndex, voteSet.valSet.Size(), ErrVoteInvalidValidatorIndex)
	}

	// Ensure that the signer has the right address.
	if valAddr != lookupAddr {
		return false, fmt.Errorf(
			"vote.ValidatorAddress (%X) does not match address (%X) for vote.ValidatorIndex (%d)\n"+
				"Ensure the genesis file is correct across all validators: %w",
			valAddr, lookupAddr, valIndex, ErrVoteInvalidValidatorAddress)
	}

	// If we already know of this vote, return false.
	if existing, ok := voteSet.getVote(valIndex, blockKey); ok {
		if bytes.Equal(existing.Signature, vote.Signature) {
			return false, nil // duplicate
		}
		return false, fmt.Errorf("existing vote: %v; new vote: %v: %w", existing, vote, ErrVoteNonDeterministicSignature)
	}

	// Check signature.
	if err := vote.Verify(voteSet.chainID, val.PubKey); err != nil {
		return false, fmt.Errorf("failed to verify vote with ChainID %s and PubKey %s: %w", voteSet.chainID, val.PubKey, err)
	}

	// Add vote and get conflicting vote if any.
	added, conflicting := voteSet.addVerifiedVote(vote, blockKey, val.VotingPower)
	if conflicting != nil {
		return added, NewConflictingVoteError(conflicting, vote)
	}
	if !added {
		panic("Expected to add non-conflicting vote")
	}
	return added, nil
}

// Returns (vote, true) if vote exists for valIndex and blockKey.
func (voteSet *VoteSet) getVote(valIndex int32, blockKey common.Hash) (vote *Vote, ok bool) {
	if existing := voteSet.votes[valIndex]; existing != nil && existing.BlockID == blockKey {
		return existing, true
	}
	if existing := voteSet.votesByBlock[blockKey].getByIndex(valIndex); existing != nil {
		return existing, true
	}
	return nil, false
}

// Assumes signature is valid.
// If conflicting vote exists, returns it.
func (voteSet *VoteSet) addVerifiedVote(
	vote *Vote,
	blockKey common.Hash,
	votingPower int64,
) (added bool, conflicting *Vote) {
	valIndex := vote.ValidatorIndex

	// Already exists in voteSet.votes?
	if existing := voteSet.votes[valIndex]; existing != nil {
		if existing.BlockID == vote.BlockID {
			panic("addVerifiedVote does not expect duplicate votes")
		} else {
			conflicting = existing
		}
		// Replace vote if blockKey matches voteSet.maj23.
		if voteSet.maj23 != nil && *voteSet.maj23 == blockKey {
			voteSet.votes[valIndex] = vote
			voteSet.votesBitArray.SetIndex(int(valIndex), true)
		}
		// Otherwise don't add it to voteSet.votes
	} else {
		// Add to voteSet.votes and incr .sum
		voteSet.votes[valIndex] = vote
		voteSet.votesBitArray.SetIndex(int(valIndex), true)
		voteSet.sum += votingPower
	}

	votesByBlock, ok := voteSet.votesByBlock[blockKey]
	if ok {
		if conflicting != nil && !votesByBlock.peerMaj23 {
			// There's a conflict and no peer claims that this block is special.
			return false, conflicting
		}
		// We'll add the vote in a bit.
	} else {
		// .votesByBlock doesn't exist...
		if conflicting != nil {
			// ... and there's a conflicting vote.
			// We're not even tracking this blockKey, so just forget it.
			return false, conflicting
		}
		// ... and there's no conflicting vote.
		// Start tracking this blockKey
		votesByBlock = newBlockVotes(false, voteSet.valSet.Size())
		voteSet.votesByBlock[blockKey] = votesByBlock
		// We'll add the vote in a bit.
	}

	// Before adding to votesByBlock, see if we'll exceed quorum
	origSum := votesByBlock.sum
	quorum := voteSet.valSet.TotalVotingPower()*2/3 + 1

	// Add vote to votesByBlock
	votesByBlock.addVerifiedVote(vote, votingPower)

	// If we just crossed the quorum threshold and have 2/3 majority...
	if origSum < quorum && quorum <= votesByBlock.sum {
		// Only consider the first quorum reached
		if voteSet.maj23 == nil {
			maj23BlockID := vote.BlockID
			voteSet.maj23 = &maj23BlockID
			// And also copy votes over to voteSet.votes
			for i, vote := range votesByBlock.votes {
				if vote != nil {
					voteSet.votes[i] = vote
				}
			}
		}
	}

	return true, conflicting
}

// If there was a +2/3 majority for blockID, return blockID and true.
// Else, return the empty BlockID{} and false.
func (voteSet *VoteSet) TwoThirdsMajority() (blockID common.Hash, ok bool) {
	if voteSet == nil {
		return common.Hash{}, false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	if voteSet.maj23 != nil {
		return *voteSet.maj23, true
	}
	return common.Hash{}, false
}

func (voteSet *VoteSet) HasTwoThirdsMajority() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

func (voteSet *VoteSet) MakeCommit() *Commit {
	if voteSet.signedMsgType != PrecommitType {
		panic("Cannot MakeCommit() unless VoteSet.Type is PrecommitType")
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()

	// Make sure we have a 2/3 majority
	if voteSet.maj23 == nil {
		panic("Cannot MakeCommit() unless a blockhash has +2/3")
	}

	// For every validator, get the precommit
	commitSigs := make([]CommitSig, len(voteSet.votes))
	for i, v := range voteSet.votes {
		commitSig := v.CommitSig()
		// if block ID exists but doesn't match, exclude sig
		if commitSig.ForBlock() && v.BlockID != *voteSet.maj23 {
			commitSig = NewCommitSigAbsent()
		}
		commitSigs[i] = commitSig
	}

	return NewCommit(voteSet.GetHeight(), voteSet.GetRound(), *voteSet.maj23, commitSigs)
}

// Implements VoteSetReader.
func (voteSet *VoteSet) BitArray() *BitArray {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.votesBitArray.Copy()
}

// Implements VoteSetReader.
func (voteSet *VoteSet) GetHeight() uint64 {
	if voteSet == nil {
		return 0
	}
	return voteSet.height
}

// Implements VoteSetReader.
func (voteSet *VoteSet) GetRound() int32 {
	if voteSet == nil {
		return -1
	}
	return voteSet.round
}

func (voteSet *VoteSet) HasTwoThirdsAny() bool {
	if voteSet == nil {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.sum > voteSet.valSet.TotalVotingPower()*2/3
}

// Implements VoteSetReader.
func (voteSet *VoteSet) Type() byte {
	if voteSet == nil {
		return 0x00
	}
	return byte(voteSet.signedMsgType)
}

// Implements VoteSetReader.
func (voteSet *VoteSet) IsCommit() bool {
	if voteSet == nil {
		return false
	}
	if voteSet.signedMsgType != PrecommitType {
		return false
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.maj23 != nil
}

// Implements VoteSetReader.
func (voteSet *VoteSet) Size() int {
	if voteSet == nil {
		return 0
	}
	return voteSet.valSet.Size()
}

// StringShort returns a short representation of VoteSet.
//
// 1. height
// 2. round
// 3. signed msg type
// 4. first 2/3+ majority
// 5. fraction of voted power
// 6. votes bit array
// 7. 2/3+ majority for each peer
func (voteSet *VoteSet) StringShort() string {
	// if voteSet == nil {
	// 	return nilVoteSetString
	// }
	// voteSet.mtx.Lock()
	// defer voteSet.mtx.Unlock()
	// _, _, frac := voteSet.sumTotalFrac()
	// return fmt.Sprintf(`VoteSet{H:%v R:%v T:%v +2/3:%v(%v) %v %v}`,
	// 	voteSet.height, voteSet.round, voteSet.signedMsgType, voteSet.maj23, frac, voteSet.votesBitArray, voteSet.peerMaj23s)
	// TODO
	return ""
}

// LogString produces a logging suitable string representation of the
// vote set.
func (voteSet *VoteSet) LogString() string {
	// if voteSet == nil {
	// 	return nilVoteSetString
	// }
	// voteSet.mtx.Lock()
	// defer voteSet.mtx.Unlock()
	// voted, total, frac := voteSet.sumTotalFrac()

	// return fmt.Sprintf("Votes:%d/%d(%.3f)", voted, total, frac)
	return ""
}

func (voteSet *VoteSet) HasAll() bool {
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	return voteSet.sum == voteSet.valSet.TotalVotingPower()
}

type RoundVoteSet struct {
	Prevotes   *VoteSet
	Precommits *VoteSet
}

var (
	ErrGotVoteFromUnwantedRound = errors.New(
		"peer has sent a vote that does not match our round for more than one round",
	)
)

type HeightVoteSet struct {
	chainID string
	height  uint64
	valSet  *ValidatorSet

	mtx               sync.Mutex
	round             int32                  // max tracked round
	roundVoteSets     map[int32]RoundVoteSet // keys: [0...round]
	peerCatchupRounds map[string][]int32     // keys: peer.ID; values: at most 2 rounds
}

func NewHeightVoteSet(chainID string, height uint64, valSet *ValidatorSet) *HeightVoteSet {
	hvs := &HeightVoteSet{
		chainID: chainID,
	}
	hvs.Reset(height, valSet)
	return hvs
}

func (hvs *HeightVoteSet) Reset(height uint64, valSet *ValidatorSet) {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()

	hvs.height = height
	hvs.valSet = valSet
	hvs.roundVoteSets = make(map[int32]RoundVoteSet)
	hvs.peerCatchupRounds = make(map[string][]int32)

	hvs.addRound(0)
	hvs.round = 0
}

// Create more RoundVoteSets up to round.
func (hvs *HeightVoteSet) SetRound(round int32) {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()
	newRound := SafeSubInt32(hvs.round, 1)
	if hvs.round != 0 && (round < newRound) {
		panic("SetRound() must increment hvs.round")
	}
	for r := newRound; r <= round; r++ {
		if _, ok := hvs.roundVoteSets[r]; ok {
			continue // Already exists because peerCatchupRounds.
		}
		hvs.addRound(r)
	}
	hvs.round = round
}

func (hvs *HeightVoteSet) addRound(round int32) {
	if _, ok := hvs.roundVoteSets[round]; ok {
		panic("addRound() for an existing round")
	}
	// log.Debug("addRound(round)", "round", round)
	prevotes := NewVoteSet(hvs.chainID, hvs.height, round, PrevoteType, hvs.valSet)
	precommits := NewVoteSet(hvs.chainID, hvs.height, round, PrecommitType, hvs.valSet)
	hvs.roundVoteSets[round] = RoundVoteSet{
		Prevotes:   prevotes,
		Precommits: precommits,
	}
}

// Duplicate votes return added=false, err=nil.
// By convention, peerID is "" if origin is self.
func (hvs *HeightVoteSet) AddVote(vote *Vote, peerID string) (added bool, err error) {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()
	if !IsVoteTypeValid(vote.Type) {
		return
	}
	voteSet := hvs.getVoteSet(vote.Round, vote.Type)
	if voteSet == nil {
		if rndz := hvs.peerCatchupRounds[peerID]; len(rndz) < 2 {
			hvs.addRound(vote.Round)
			voteSet = hvs.getVoteSet(vote.Round, vote.Type)
			hvs.peerCatchupRounds[peerID] = append(rndz, vote.Round)
		} else {
			// punish peer
			err = ErrGotVoteFromUnwantedRound
			return
		}
	}
	added, err = voteSet.AddVote(vote)
	return
}

func (hvs *HeightVoteSet) Prevotes(round int32) *VoteSet {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()
	return hvs.getVoteSet(round, PrevoteType)
}

func (hvs *HeightVoteSet) Precommits(round int32) *VoteSet {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()
	return hvs.getVoteSet(round, PrecommitType)
}

// Last round and blockID that has +2/3 prevotes for a particular block or nil.
// Returns -1 if no such round exists.
func (hvs *HeightVoteSet) POLInfo() (polRound int32, polBlockID common.Hash) {
	hvs.mtx.Lock()
	defer hvs.mtx.Unlock()
	for r := hvs.round; r >= 0; r-- {
		rvs := hvs.getVoteSet(r, PrevoteType)
		polBlockID, ok := rvs.TwoThirdsMajority()
		if ok {
			return r, polBlockID
		}
	}
	return -1, common.Hash{}
}

func (hvs *HeightVoteSet) getVoteSet(round int32, voteType SignedMsgType) *VoteSet {
	rvs, ok := hvs.roundVoteSets[round]
	if !ok {
		return nil
	}
	switch voteType {
	case PrevoteType:
		return rvs.Prevotes
	case PrecommitType:
		return rvs.Precommits
	default:
		panic(fmt.Sprintf("Unexpected vote type %X", voteType))
	}
}

// NOTE: if validator has conflicting votes, returns "canonical" vote
// Implements VoteSetReader.
func (voteSet *VoteSet) GetByIndex(valIndex int32) *Vote {
	if voteSet == nil {
		return nil
	}
	voteSet.mtx.Lock()
	defer voteSet.mtx.Unlock()
	if int(valIndex) >= len(voteSet.votes) {
		return nil
	}
	return voteSet.votes[valIndex]
}
