package adapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	pbft "github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/consensus/tendermint/gov"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var (
	prefix    = []byte("HeaderNumber")
	emptyHash = common.Hash{}
)

type Store struct {
	config           *params.TendermintConfig
	chain            *core.BlockChain
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error
	makeBlock        func(parentHash common.Hash, coinbase common.Address, timestamp uint64) (block *types.Block, err error)
	gov              *gov.Governance
	mux              *event.TypeMux
}

func NewStore(
	config *params.TendermintConfig,
	chain *core.BlockChain,
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error,
	makeBlock func(parentHash common.Hash, coinbase common.Address, timestamp uint64) (block *types.Block, err error),
	gov *gov.Governance,
	mux *event.TypeMux) *Store {
	return &Store{config: config, chain: chain, verifyHeaderFunc: verifyHeaderFunc, makeBlock: makeBlock, gov: gov, mux: mux}
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
		return
	}

	s.mux.Post(core.NewMinedBlockEvent{Block: block.WithCommit(commit).Block})
}

// Validate a block without Commit and with LastCommit.
func (s *Store) ValidateBlock(state pbft.ChainState, block *types.FullBlock, committed bool) (err error) {
	header := block.Header()
	err = s.verifyHeaderFunc(s.chain, header, committed)
	if err != nil || committed {
		return
	}

	validators, powers := []common.Address{}, []uint64{}
	if header.Number.Uint64()%s.config.Epoch == 0 {
		epochId := header.Number.Uint64() / s.config.Epoch
		// if update validator set from contract enable
		if s.config.ValidatorChangeEpochId > 0 && s.config.ValidatorChangeEpochId <= epochId {
			l := len(prefix)
			if len(header.Extra) < l+8+32 || bytes.Equal(header.Extra[:l], prefix) {
				return errors.New("header.Extra missing validator chain block height and hash")
			}

			nb := header.Extra[l : l+8]
			number := binary.BigEndian.Uint64(nb)
			if number == 0 {
				return errors.New("invalid block number in header.Extra")
			}

			hb := header.Extra[l+8 : l+8+32]
			hash := common.BytesToHash(hb)
			if hash == emptyHash {
				return errors.New("invalid remote block hash in header.Extra")
			}
			log.Debug("NextValidatorsAndPowersForProposal", "epoch", epochId)
			validators, powers, err = s.gov.NextValidatorsAndPowersAt(number, hash)
			if err != nil {
				return errors.New(fmt.Sprintf("verifyHeader failed with %s", err.Error()))
			}
		} else {
			// else use default validator set and powers in genesis block
			header := s.chain.GetHeaderByNumber(0)
			validators, powers = header.NextValidators, header.NextValidatorPowers
		}
	}
	if !gov.CompareValidators(header.NextValidators, validators) {
		return errors.New("NextValidators is incorrect")
	}
	if !gov.CompareValidatorPowers(header.NextValidatorPowers, powers) {
		return errors.New("NextValidatorPowers is incorrect")
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
		if block.Block.Header().LastCommitHash != block.LastCommit.Hash() {
			return errors.New("header.LastCommitHash != LastCommit.Hash()")
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
	if err == core.ErrKnownBlock {
		log.Warn("ValidateBlock treated ErrKnownBlock as nil")
		err = nil
	}
	return
}

func (s *Store) ApplyBlock(ctx context.Context, state pbft.ChainState, block *types.FullBlock) (pbft.ChainState, error) {
	// Update the state with the block and responses.
	state, err := updateState(state, block.Hash(), block, block.NextValidators(), types.U64ToI64Array(block.NextValidatorPowers()))
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

	var nValSet *types.ValidatorSet

	if len(nextValidators) != 0 {
		if len(nextValidators) != len(nextVotingPowers) {
			panic("len(nextValidators) != len(nextVotingPowers)")
		}
		nValSet = types.NewValidatorSet(nextValidators, nextVotingPowers, state.Validators.ProposerReptition)
	} else {
		nValSet = state.Validators.Copy()
		// Update validator proposer priority and set state variables.
		nValSet.IncrementProposerPriority(1)
	}

	return pbft.ChainState{
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

	if height%s.config.Epoch == 0 {
		epochId := height / s.config.Epoch
		// if update validator set from contract enable
		if s.config.ValidatorChangeEpochId > 0 && s.config.ValidatorChangeEpochId <= epochId {
			log.Debug("NextValidatorsAndPowersAt", "epoch", epochId)
			validators, powers, number, hash, err := s.gov.NextValidatorsAndPowersForProposal()
			if err != nil {
				log.Error(err.Error())
				return nil
			}

			header.NextValidators, header.NextValidatorPowers = validators, powers

			// add block number and hash to header.Extra
			data := prefix
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, number)
			data = append(data, b...)
			data = append(data, hash.Bytes()...)
			header.Extra = append(data, header.Extra...)
		} else {
			// else use default validator set and powers in genesis block
			h := s.chain.GetHeaderByNumber(0)
			header.NextValidators, header.NextValidatorPowers = h.NextValidators, h.NextValidatorPowers
		}
	} else {
		header.NextValidators, header.NextValidatorPowers = []common.Address{}, []uint64{}
	}

	block = block.WithSeal(header)

	return &types.FullBlock{Block: block, LastCommit: commit}
}
