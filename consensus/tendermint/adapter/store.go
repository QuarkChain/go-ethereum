package adapter

import (
	"context"
	"errors"
	"fmt"

	pbft "github.com/QuarkChain/go-minimal-pbft/consensus"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

type Store struct {
	chain            *core.BlockChain
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error
	makeBlock        func(parentHash common.Hash, coinbase common.Address, timestamp uint64) (block *types.Block, err error)
	mux              *event.TypeMux
}

func NewStore(
	chain *core.BlockChain,
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error,
	makeBlock func(parentHash common.Hash, coinbase common.Address, timestamp uint64) (block *types.Block, err error),
	mux *event.TypeMux) *Store {
	return &Store{chain: chain, verifyHeaderFunc: verifyHeaderFunc, makeBlock: makeBlock, mux: mux}
}

func (s *Store) Base() uint64 {
	return 0
}

func (s *Store) Height() uint64 {
	return s.chain.CurrentHeader().Number.Uint64()
}

func (s *Store) Size() uint64 {
	return s.Height() + 1
}

func (s *Store) LoadBlock(height uint64) *types.FullBlock {
	block := s.chain.GetBlockByNumber(height)
	parent := s.chain.GetHeaderByHash(block.Header().ParentHash)
	if parent == nil {
		return &types.FullBlock{Block: block}
	}

	return &types.FullBlock{Block: block, LastCommit: parent.Commit}
}

func (s *Store) LoadBlockCommit(height uint64) *types.Commit {
	header := s.chain.GetHeaderByNumber(height)
	if header == nil {
		return nil
	}

	return header.Commit
}

func (s *Store) LoadSeenCommit() *types.Commit {
	header := s.chain.CurrentHeader()

	return header.Commit
}

func (s *Store) SaveBlock(block *types.FullBlock, commit *types.Commit) {
	bc := s.chain
	header := block.Header()
	header.Commit = commit

	n, err := bc.InsertChain(types.Blocks{block.WithSeal(header)})
	if n == 0 || err != nil {
		log.Warn("SaveBlock", "n", n, "err", err)
	}

	s.mux.Post(core.NewMinedBlockEvent{Block: block.WithCommit(commit).Block})
}

// Validate a block without Commit and with LastCommit.
func (s *Store) ValidateBlock(state pbft.ChainState, block *types.FullBlock) (err error) {
	err = s.verifyHeaderFunc(s.chain, block.Header(), false)
	if err != nil {
		return
	}

	// Validate if the block matches current state.
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

	// Validate basic info without Commit.
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

	// Validate block Time with LastCommit
	switch {
	case block.NumberU64() > state.InitialHeight:
		if block.TimeMs() <= state.LastBlockTime {
			return fmt.Errorf("block time %v not greater than last block time %v",
				block.TimeMs(),
				state.LastBlockTime,
			)
		}
		medianTime := pbft.MedianTime(block.LastCommit, state.LastValidators)
		if block.TimeMs() != medianTime {
			return fmt.Errorf("invalid block time. Expected %v, got %v",
				medianTime,
				block.TimeMs(),
			)
		}

	case block.NumberU64() == state.InitialHeight:
		genesisTime := state.LastBlockTime + 1000
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

	err = s.chain.PreExecuteBlock(block.Block)
	return
}

func (s *Store) ApplyBlock(ctx context.Context, state pbft.ChainState, block *types.FullBlock) (pbft.ChainState, error) {
	// TOOD: execute the block & new validator change
	// Update the state with the block and responses.
	state, err := updateState(state, block.Hash(), block, []common.Address{}, []int64{})
	if err != nil {
		return state, fmt.Errorf("commit failed for application: %v", err)
	}

	return state, nil
}

func updateState(
	state pbft.ChainState,
	blockID common.Hash,
	block *types.FullBlock,
	nextValidators []common.Address,
	nextVotingPowers []int64,
) (pbft.ChainState, error) {

	// Copy the valset so we can apply changes from EndBlock
	// and update s.LastValidators and s.Validators.
	nValSet := state.NextValidators.Copy()

	if len(nextValidators) != 0 {
		// TODO: sanity check
		nValSet = types.NewValidatorSet(nextValidators, nextVotingPowers, nValSet.ProposerReptition)
	}

	// Update validator proposer priority and set state variables.
	nValSet.IncrementProposerPriority(1)

	// // Update the validator set with the latest abciResponses.
	// lastHeightValsChanged := state.LastHeightValidatorsChanged
	// if len(validatorUpdates) > 0 {
	// 	err := nValSet.UpdateWithChangeSet(validatorUpdates)
	// 	if err != nil {
	// 		return state, fmt.Errorf("error changing validator set: %v", err)
	// 	}
	// 	// Change results from this height but only applies to the next next height.
	// 	lastHeightValsChanged = header.Height + 1 + 1
	// }

	// Update the params with the latest abciResponses.
	// nextParams := state.ConsensusParams
	// lastHeightParamsChanged := state.LastHeightConsensusParamsChanged
	// if abciResponses.EndBlock.ConsensusParamUpdates != nil {
	// 	// NOTE: must not mutate s.ConsensusParams
	// 	nextParams = state.ConsensusParams.UpdateConsensusParams(abciResponses.EndBlock.ConsensusParamUpdates)
	// 	err := nextParams.ValidateConsensusParams()
	// 	if err != nil {
	// 		return state, fmt.Errorf("error updating consensus params: %v", err)
	// 	}

	// 	state.Version.App = nextParams.Version.AppVersion

	// 	// Change results from this height but only applies to the next height.
	// 	lastHeightParamsChanged = header.Height + 1
	// }

	// NOTE: the AppHash has not been populated.
	// It will be filled on state.Save.
	return pbft.ChainState{
		ChainID:         state.ChainID,
		InitialHeight:   state.InitialHeight,
		LastBlockHeight: block.NumberU64(),
		LastBlockID:     blockID,
		LastBlockTime:   block.TimeMs(),
		NextValidators:  nValSet,
		Validators:      state.NextValidators.Copy(),
		LastValidators:  state.Validators.Copy(),
		AppHash:         nil,
		Epoch:           state.Epoch,
	}, nil
}

func (s *Store) MakeBlock(
	state *pbft.ChainState,
	height uint64,
	commit *pbft.Commit,
	proposerAddress common.Address,
) *types.FullBlock {

	// Set time.
	var timestampMs uint64
	if height == state.InitialHeight {
		timestampMs = state.LastBlockTime + 1000 // genesis time + 1sec
	} else {
		timestampMs = pbft.MedianTime(commit, state.LastValidators)
	}
	var timestamp = timestampMs / 1000

	block, err := s.makeBlock(state.LastBlockID, proposerAddress, timestamp)
	if err != nil {
		log.Crit("failed to make a block", "err", err)
	}

	// Make a copy of header, and setup TM-related fields
	header := block.Header()
	if header.Time != timestamp {
		log.Crit("make block does not setup header.Time correctly")
	}
	header.TimeMs = timestampMs
	header.LastCommitHash = commit.Hash()

	block = block.WithSeal(header)

	return &types.FullBlock{Block: block, LastCommit: commit}
}
