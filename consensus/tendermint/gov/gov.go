package gov

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type Governance struct {
	config *params.TendermintConfig
	chain  consensus.ChainHeaderReader
}

func New(config *params.TendermintConfig, chain consensus.ChainHeaderReader) *Governance {
	return &Governance{config: config, chain: chain}
}

// Returns the validator sets for last, current, next blocks
func (g *Governance) GetValidatorSets(height uint64) (*types.ValidatorSet, *types.ValidatorSet, *types.ValidatorSet) {
	if height == 0 {
		panic("cannot get genesis validator set")
	}

	last := g.GetValidatorSet(height-1, nil)
	current := g.GetValidatorSet(height, last)
	next := g.GetValidatorSet(height+1, current)
	return last, current, next
}

// GetValidatorSet returns the validator set of a height

func (g *Governance) GetValidatorSet(height uint64, lastVals *types.ValidatorSet) *types.ValidatorSet {
	if height == 0 {
		return &types.ValidatorSet{}
	}

	idxInEpoch := (height - 1) % g.config.Epoch

	if idxInEpoch != 0 && lastVals != nil {
		// use cached version if we do not have a validator change
		cvals := lastVals.Copy()
		cvals.IncrementProposerPriority(1)
		return cvals
	}

	epochNumber := height - 1 - idxInEpoch
	epochHeader := g.chain.GetHeaderByNumber(epochNumber)
	epochVals := types.NewValidatorSet(epochHeader.NextValidators, types.U64ToI64Array(epochHeader.NextValidatorPowers), int64(g.config.Epoch))
	if idxInEpoch != 0 {
		epochVals.IncrementProposerPriority(int32(idxInEpoch))
	}

	return epochVals
}

func (g *Governance) NextValidators(height uint64) []common.Address {
	if height%g.config.Epoch != 0 {
		return []common.Address{}
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators
	default:
		// TODO: get real validators by calling contract, currently use genesis
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators
	}
}

func CompareValidators(lhs, rhs []common.Address) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := 0; i < len(lhs); i++ {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	return true
}

func CompareValidatorPowers(lhs, rhs []uint64) bool {
	if len(lhs) != len(rhs) {
		return false
	}

	for i := 0; i < len(lhs); i++ {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	return true
}

func (g *Governance) NextValidatorPowers(height uint64) []uint64 {
	if height%g.config.Epoch != 0 {
		return []uint64{}
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidatorPowers
	default:
		// TODO get real validators by calling contract
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidatorPowers
	}
}
