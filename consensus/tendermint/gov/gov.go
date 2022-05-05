package gov

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

const (
	validatorsetABI           = `[{"inputs": [],"name": "GetEpochValidators","outputs": [{"internalType": "uint256","name": "EpochIdx","type": "uint256"},{"internalType": "address[]","name": "Validators","type": "address[]"},{"internalType": "uint256[]","name": "Powers","type": "uint256[]"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "proposalValidators","outputs": [{"internalType": "address[]","name": "Validators","type": "address[]"},{"internalType": "uint256[]","name": "Powers","type": "uint256[]"}],"stateMutability": "view","type": "function"}]`
	confirmedNumber           = 96
	contractFunc_GetValidator = "proposalValidators"
	gas                       = uint64(math.MaxUint64 / 2)
)

type Governance struct {
	ctx             context.Context
	config          *params.TendermintConfig
	chain           consensus.ChainHeaderReader
	validatorSetABI abi.ABI
	client          *ethclient.Client
	contract        *common.Address
}

func New(config *params.TendermintConfig, chain consensus.ChainHeaderReader, client *ethclient.Client) *Governance {
	vABI, _ := abi.JSON(strings.NewReader(validatorsetABI))
	contract := common.HexToAddress(config.ValidatorContract)
	return &Governance{
		ctx:             context.Background(),
		config:          config,
		chain:           chain,
		client:          client,
		validatorSetABI: vABI,
		contract:        &contract,
	}
}

// GetValidatorSets Returns the validator sets for last, current blocks
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

// NextValidatorsAndPowers get next validators according to block height and config
func (g *Governance) NextValidatorsAndPowers(epochId uint64, remoteChainNumber uint64, hash common.Hash) ([]common.Address, []uint64, uint64, common.Hash, error) {
	log.Info("new epoch", "epoch", epochId)
	if g.config.ValidatorChangeEpochId == 0 || g.config.ValidatorChangeEpochId > epochId {
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators, header.NextValidatorPowers, 0, common.Hash{}, nil
	}

	number, err := g.client.BlockNumber(g.ctx)
	if err != nil {
		return nil, nil, 0, common.Hash{}, err
	}

	if remoteChainNumber == 0 {
		if number <= confirmedNumber {
			return nil, nil, 0, common.Hash{}, fmt.Errorf("remote chain number %d smaller than confirmedNumber %d", number, confirmedNumber)
		}
		remoteChainNumber = number - confirmedNumber
	} else if remoteChainNumber == uint64(math.MaxUint64) {
		return nil, nil, remoteChainNumber, common.Hash{}, fmt.Errorf("parse remoteChainNumber")
	} else {
		if number-confirmedNumber/2*3 > remoteChainNumber || number-confirmedNumber/2 < remoteChainNumber {
			return nil, nil, 0, common.Hash{}, fmt.Errorf("remoteChainNumber %d is out of range [%d, %d]",
				remoteChainNumber, number-confirmedNumber/2*3, number-confirmedNumber/2)
		}
	}

	validators, powers, err := g.getValidatorsAndPowersFromContract(remoteChainNumber)
	if err != nil {
		return nil, nil, 0, common.Hash{}, err
	}

	header, err := g.client.BlockByNumber(g.ctx, new(big.Int).SetUint64(remoteChainNumber))
	if err != nil {
		return nil, nil, 0, common.Hash{}, err
	}

	if hash != header.Hash() {
		fmt.Errorf("block hash mismatch", "remoteChainNumber hash", header.Hash(), "hash", hash)
	}

	log.Info("get validators and powers", "validators", validators, "powers", powers)
	return validators, powers, remoteChainNumber, header.Hash(), err
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

// getValidatorsAndPowersFromContract get next validators from contract
func (g *Governance) getValidatorsAndPowersFromContract(blockNumber uint64) ([]common.Address, []uint64, error) {
	data, err := g.validatorSetABI.Pack(contractFunc_GetValidator)
	if err != nil {
		return nil, nil, err
	}

	// call
	msgData := (hexutil.Bytes)(data)
	msg := ethereum.CallMsg{
		To:   g.contract,
		Gas:  gas,
		Data: msgData,
	}
	result, err := g.client.CallContract(g.ctx, msg, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return nil, nil, err
	}

	type validators struct {
		Validators []common.Address
		Powers     []*big.Int
	}

	var v validators

	if err := g.validatorSetABI.UnpackIntoInterface(&v, contractFunc_GetValidator, result); err != nil {
		return nil, nil, err
	}

	if len(v.Validators) != len(v.Powers) {
		return nil, nil, fmt.Errorf("invalid validator set: validator count %d is mismatch with power count %d",
			len(v.Validators), len(v.Powers))
	}

	powers := make([]uint64, len(v.Powers))
	for i, p := range v.Powers {
		powers[i] = p.Uint64()
	}

	return v.Validators, powers, nil
}
