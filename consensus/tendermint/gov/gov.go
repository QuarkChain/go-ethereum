package gov

import (
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
)

const validatorsetABI = `` // TODO add it later

type Governance struct {
	config          *params.TendermintConfig
	chain           consensus.ChainHeaderReader
	validatorSetABI abi.ABI
	client          *ethclient.Client
}

func New(config *params.TendermintConfig, chain consensus.ChainHeaderReader, client *ethclient.Client) *Governance {
	vABI, _ := abi.JSON(strings.NewReader(validatorsetABI))
	return &Governance{config: config, chain: chain, client: client, validatorSetABI: vABI}
}

// Returns the validator sets for last, current blocks
func (g *Governance) GetValidatorSets(height uint64) (*types.ValidatorSet, *types.ValidatorSet) {
	if height == 0 {
		panic("cannot get genesis validator set")
	}

	last := g.GetValidatorSet(height-1, nil)
	current := g.GetValidatorSet(height, last)
	return last, current
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
	epochVals := types.NewValidatorSet(epochHeader.NextValidators, types.U64ToI64Array(epochHeader.NextValidatorPowers), int64(g.config.ProposerRepetition))
	if idxInEpoch != 0 {
		epochVals.IncrementProposerPriority(int32(idxInEpoch))
	}

	return epochVals
}

func (g *Governance) NextValidatorsAndPowers(height uint64, number uint64) ([]common.Address, []uint64, error) {
	if height%g.config.Epoch != 0 {
		return []common.Address{}, []uint64{}, nil
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators, header.NextValidatorPowers, nil
	default:
		// TODO: get real validators by calling contract, currently use genesis
		epochId := height / g.config.Epoch
		if g.client == nil || g.config.EnableEpock > epochId {
			header := g.chain.GetHeaderByNumber(0)
			return header.NextValidators, header.NextValidatorPowers, nil
		}

		return g.GetValidatorsAndPowersFromContract(number)
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

// GetValidatorsAndPowersFromContract get current validators
func (c *Governance) GetValidatorsAndPowersFromContract(blockNumber uint64) ([]common.Address, []uint64, error) {
	panic("GetValidatorsAndPowersFromContract")
}
