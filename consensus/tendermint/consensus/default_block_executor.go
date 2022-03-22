package consensus

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/syndtr/goleveldb/leveldb"
)

type DefaultBlockExecutor struct {
	db *leveldb.DB
}

func NewDefaultBlockExecutor(db *leveldb.DB) BlockExecutor {
	return &DefaultBlockExecutor{}
}

func (be *DefaultBlockExecutor) VerifyBlock(state ChainState, b *FullBlock) error {
	// TODO: only need to check commit
	return validateBlock(state, b)
}

func (be *DefaultBlockExecutor) ValidateBlock(state ChainState, b *FullBlock) error {
	return validateBlock(state, b)
}

func validateBlock(state ChainState, block *FullBlock) error {

	// Validate basic info.

	if state.LastBlockHeight == 0 && block.NumberU64() != state.InitialHeight {
		return fmt.Errorf("wrong Block.Header.Height. Expected %v for initial block, got %v",
			block.NumberU64(), state.InitialHeight)
	}
	if state.LastBlockHeight > 0 && block.NumberU64() != state.LastBlockHeight+1 {
		return fmt.Errorf("wrong Block.Header.Height. Expected %v, got %v",
			state.LastBlockHeight+1,
			block.NumberU64(),
		)
	}
	// Validate prev block info.
	if block.ParentHash() != state.LastBlockID {
		return fmt.Errorf("wrong Block.Header.LastBlockID.  Expected %v, got %v",
			state.LastBlockID,
			block.ParentHash(),
		)
	}

	// Validate block LastCommit.
	if block.NumberU64() == state.InitialHeight {
		if len(block.LastCommit.Signatures) != 0 {
			return errors.New("initial block can't have LastCommit signatures")
		}
	} else {
		// LastCommit.Signatures length is checked in VerifyCommit.
		if err := state.LastValidators.VerifyCommit(
			state.ChainID, state.LastBlockID, block.NumberU64()-1, block.LastCommit); err != nil {
			return err
		}
	}

	// Don't allow validator change within the epoch
	if block.NumberU64()%state.Epoch != 0 && len(block.NextValidators()) != 0 {
		return errors.New("cannot change validators within epoch")
	}

	// NOTE: We can't actually verify it's the right proposer because we don't
	// know what round the block was first proposed. So just check that it's
	// a legit address and a known validator.
	// The length is checked in ValidateBasic above.
	if !state.Validators.HasAddress(block.Coinbase()) {
		return fmt.Errorf("block.Header.ProposerAddress %X is not a validator",
			block.Coinbase(),
		)
	}

	if block.TimeMs()/1000 != block.Time() {
		return fmt.Errorf("inccorect timestamp")
	}

	// Validate block Time
	switch {
	case block.NumberU64() > state.InitialHeight:
		if block.TimeMs() <= state.LastBlockTime {
			return fmt.Errorf("block time %v not greater than last block time %v",
				block.TimeMs(),
				state.LastBlockTime,
			)
		}
		medianTime := MedianTime(block.LastCommit, state.LastValidators)
		if block.TimeMs() != medianTime {
			return fmt.Errorf("invalid block time. Expected %v, got %v",
				medianTime,
				block.TimeMs(),
			)
		}

	case block.NumberU64() == state.InitialHeight:
		genesisTime := state.LastBlockTime
		if block.TimeMs() != genesisTime {
			return fmt.Errorf("block time %v is not equal to genesis time %v",
				block.TimeMs(),
				genesisTime,
			)
		}

	default:
		return fmt.Errorf("block height %v lower than initial height %v",
			block.NumberU64(), state.InitialHeight)
	}

	return nil
}

// weightedTime for computing a median.
type weightedTime struct {
	TimeMs uint64
	Weight int64
}

// MedianTime computes a median time for a given Commit (based on Timestamp field of votes messages) and the
// corresponding validator set. The computed time is always between timestamps of
// the votes sent by honest processes, i.e., a faulty processes can not arbitrarily increase or decrease the
// computed value.
func MedianTime(commit *Commit, validators *ValidatorSet) uint64 {
	weightedTimes := make([]*weightedTime, len(commit.Signatures))
	totalVotingPower := int64(0)

	for i, commitSig := range commit.Signatures {
		if commitSig.Absent() {
			continue
		}
		_, validator := validators.GetByAddress(commitSig.ValidatorAddress)
		// If there's no condition, TestValidateBlockCommit panics; not needed normally.
		if validator != nil {
			totalVotingPower += validator.VotingPower
			weightedTimes[i] = &weightedTime{TimeMs: commitSig.TimestampMs, Weight: validator.VotingPower}
		}
	}

	return weightedMedian(weightedTimes, totalVotingPower)
}

// weightedMedian computes weighted median time for a given array of WeightedTime and the total voting power.
func weightedMedian(weightedTimes []*weightedTime, totalVotingPower int64) (res uint64) {
	median := totalVotingPower / 2

	sort.Slice(weightedTimes, func(i, j int) bool {
		if weightedTimes[i] == nil {
			return false
		}
		if weightedTimes[j] == nil {
			return true
		}
		return weightedTimes[i].TimeMs < weightedTimes[j].TimeMs
	})

	for _, weightedTime := range weightedTimes {
		if weightedTime != nil {
			if median <= weightedTime.Weight {
				res = weightedTime.TimeMs
				break
			}
			median -= weightedTime.Weight
		}
	}
	return
}

func (be *DefaultBlockExecutor) ApplyBlock(ctx context.Context, state ChainState, block *FullBlock) (ChainState, error) {
	// TOOD: execute the block & new validator change
	// Update the state with the block and responses.
	state, err := updateState(state, block.Hash(), block, []common.Address{}, []int64{})
	if err != nil {
		return state, fmt.Errorf("commit failed for application: %v", err)
	}

	return state, nil
}

func updateState(
	state ChainState,
	blockID common.Hash,
	block *FullBlock,
	nextValidators []common.Address,
	nextVotingPowers []int64,
) (ChainState, error) {

	var nValSet *ValidatorSet

	if len(nextValidators) != 0 {
		if len(nextValidators) != len(nextVotingPowers) {
			panic("len(nextValidators) != len(nextVotingPowers)")
		}
		nValSet = NewValidatorSet(nextValidators, nextVotingPowers, nValSet.ProposerReptition)
	} else {
		nValSet = state.Validators.Copy()
		// Update validator proposer priority and set state variables.
		nValSet.IncrementProposerPriority(1)
	}

	return ChainState{
		ChainID:         state.ChainID,
		InitialHeight:   state.InitialHeight,
		LastBlockHeight: block.NumberU64(),
		LastBlockID:     blockID,
		LastBlockTime:   block.TimeMs(),
		Validators:      nValSet,
		LastValidators:  state.Validators.Copy(),
		AppHash:         nil,
		Epoch:           state.Epoch,
	}, nil
}

func (be *DefaultBlockExecutor) MakeBlock(
	chainState *ChainState, height uint64,
	// txs []types.Tx,
	commit *Commit,
	// evidence []types.Evidence,
	proposerAddress common.Address) *FullBlock {

	return chainState.MakeBlock(height, commit, proposerAddress)
}
