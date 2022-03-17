package consensus

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// State is a short description of the latest committed block of the Tendermint consensus.
// It keeps all information necessary to validate new blocks,
// including the last validator set and the consensus params.
// All fields are exposed so the struct can be easily serialized,
// but none of them should be mutated directly.
// Instead, use state.Copy() or updateState(...).
// NOTE: not goroutine-safe.
type ChainState struct {
	// immutable
	ChainID       string
	InitialHeight uint64 // should be 1, not 0, when starting from height 1

	// LastBlockHeight=0 at genesis (ie. block(H=0) does not exist)
	LastBlockHeight uint64
	LastBlockID     common.Hash
	LastBlockTime   uint64

	// LastValidators is used to validate block.LastCommit.
	// Validators are persisted to the database separately every time they change,
	// so we can query for historical validator sets.
	// Note that if s.LastBlockHeight causes a valset change,
	// we set s.LastHeightValidatorsChanged = s.LastBlockHeight + 1 + 1
	// Extra +1 due to nextValSet delay.
	Validators                  *ValidatorSet
	LastValidators              *ValidatorSet
	LastHeightValidatorsChanged int64

	// Consensus parameters used for validating blocks.
	// Changes returned by EndBlock and updated after Commit.
	// ConsensusParams                  types.ConsensusParams
	// LastHeightConsensusParamsChanged int64
	Epoch uint64

	// Merkle root of the results from executing prev block
	// LastResultsHash []byte

	// the latest AppHash we've received from calling abci.Commit()
	AppHash []byte
}

// IsEmpty returns true if the State is equal to the empty State.
func (state ChainState) IsEmpty() bool {
	return state.Validators == nil // XXX can't compare to Empty
}

func (state ChainState) Copy() ChainState {
	return ChainState{
		ChainID:       state.ChainID,
		InitialHeight: state.InitialHeight,

		LastBlockHeight: state.LastBlockHeight,
		LastBlockID:     state.LastBlockID,
		LastBlockTime:   state.LastBlockTime,

		Validators:                  state.Validators.Copy(),
		LastValidators:              state.LastValidators.Copy(),
		LastHeightValidatorsChanged: state.LastHeightValidatorsChanged,

		Epoch: state.Epoch,

		// ConsensusParams:                  state.ConsensusParams,
		// LastHeightConsensusParamsChanged: state.LastHeightConsensusParamsChanged,

		AppHash: state.AppHash,

		// LastResultsHash: state.LastResultsHash,
	}
}

func MakeGenesisChainState(chainID string, genesisTimeMs uint64, validatorAddrs []common.Address, votingPowers []int64, epoch uint64, proposerReptition int64) *ChainState {
	vs := NewValidatorSet(validatorAddrs, votingPowers, proposerReptition)
	return &ChainState{
		ChainID:                     chainID,
		InitialHeight:               1,
		LastBlockHeight:             0,
		LastBlockID:                 common.Hash{},
		LastBlockTime:               genesisTimeMs,
		Validators:                  vs,
		LastValidators:              &ValidatorSet{}, // not exist
		LastHeightValidatorsChanged: 1,
		Epoch:                       epoch,
	}
}

func MakeChainState(
	chainID string,
	parentHeight uint64,
	parentHash common.Hash,
	parentTimeMs uint64,
	lastValSet *ValidatorSet,
	valSet *ValidatorSet,
	epoch uint64,
) *ChainState {
	return &ChainState{
		ChainID:                     chainID,
		InitialHeight:               1,
		LastBlockHeight:             parentHeight,
		LastBlockID:                 parentHash,
		LastBlockTime:               parentTimeMs,
		Validators:                  valSet,
		LastValidators:              lastValSet,
		LastHeightValidatorsChanged: 1,
		Epoch:                       epoch,
	}
}

//------------------------------------------------------------------------
// Create a block from the latest state

// MakeBlock builds a block from the current state with the given txs, commit,
// and evidence. Note it also takes a proposerAddress because the state does not
// track rounds, and hence does not know the correct proposer. TODO: fix this!
func (state ChainState) MakeBlock(
	height uint64,
	// txs []types.Tx,
	commit *Commit,
	// evidence []types.Evidence,
	proposerAddress common.Address,
) *FullBlock {

	// Set time.
	var timestamp uint64
	if height == state.InitialHeight {
		timestamp = state.LastBlockTime // genesis time
	} else {
		timestamp = MedianTime(commit, state.LastValidators)
	}

	// Build base block with block data.
	block := &FullBlock{
		Block: types.NewBlock(
			&Header{
				ParentHash:     state.LastBlockID,
				Number:         big.NewInt(int64(height)),
				Time:           timestamp / 1000,
				TimeMs:         timestamp,
				Coinbase:       proposerAddress,
				LastCommitHash: commit.Hash(),
				Difficulty:     big.NewInt(int64(height)),
				Extra:          []byte{},
				BaseFee:        big.NewInt(0), // TODO: update base fee
			},
			nil, nil, nil, trie.NewStackTrie(nil),
		), LastCommit: commit}

	return block
}
