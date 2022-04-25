package gov

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	pbft "github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	validatorsetABI           = `[{"inputs": [],"name": "GetEpochValidators","outputs": [{"internalType": "uint256","name": "EpochIdx","type": "uint256"},{"internalType": "address[]","name": "Validators","type": "address[]"},{"internalType": "uint256[]","name": "Powers","type": "uint256[]"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "bytes","name": "_epochHeaderBytes","type": "bytes"},{"internalType": "bytes","name": "commitBytes","type": "bytes"}],"name": "createEpochValidators","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [],"name": "epochIdx","outputs": [{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "proposalValidators","outputs": [{"internalType": "address[]","name": "Validators","type": "address[]"},{"internalType": "uint256[]","name": "Powers","type": "uint256[]"}],"stateMutability": "view","type": "function"}]` // TODO add it later
	confirmedNumber           = 96
	contractFunc_GetValidator = "proposalValidators"
	contractFunc_SubmitHeader = "createEpochValidators"
	gas                       = uint64(math.MaxUint64 / 2)
)

type Signer interface {
	SignMessage(message []byte) ([]byte, error)
	Address() common.Address
}

type Governance struct {
	ctx             context.Context
	config          *params.TendermintConfig
	chain           consensus.ChainHeaderReader
	validatorSetABI abi.ABI
	client          *ethclient.Client
	contract        *common.Address
	signer          pbft.PrivValidator
}

func New(config *params.TendermintConfig, chain consensus.ChainHeaderReader, client *ethclient.Client, signer pbft.PrivValidator) *Governance {
	vABI, _ := abi.JSON(strings.NewReader(validatorsetABI))
	contract := common.HexToAddress(config.ValidatorContract)
	return &Governance{
		ctx:             context.Background(),
		config:          config,
		chain:           chain,
		client:          client,
		validatorSetABI: vABI,
		contract:        &contract,
		signer:          signer,
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

func (g *Governance) NextValidatorsAndPowers(height uint64, remoteChainNumber uint64) ([]common.Address, []uint64, uint64, error) {
	if height%g.config.Epoch != 0 {
		return []common.Address{}, []uint64{}, 0, nil
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators, header.NextValidatorPowers, 0, nil
	default:
		epochId := height / g.config.Epoch
		if g.client == nil || g.config.EnableEpock > epochId {
			header := g.chain.GetHeaderByNumber(0)
			return header.NextValidators, header.NextValidatorPowers, 0, nil
		}

		number, err := g.client.BlockNumber(g.ctx)
		if err != nil {
			return nil, nil, 0, err
		}

		if remoteChainNumber == 0 {
			if number <= confirmedNumber {
				return nil, nil, 0, fmt.Errorf("remote chain number %d smaller than confirmedNumber %d", number, confirmedNumber)
			}
			remoteChainNumber = number - confirmedNumber
		} else if remoteChainNumber == uint64(math.MaxUint64) {
			return nil, nil, remoteChainNumber, fmt.Errorf("parse remoteChainNumber")
		} else {
			if number-confirmedNumber/2*3 > remoteChainNumber || number-confirmedNumber/2 < remoteChainNumber {
				return nil, nil, 0, fmt.Errorf("remoteChainNumber %d is out of range [%d, %d]",
					remoteChainNumber, number-confirmedNumber/2*3, number-confirmedNumber/2)
			}
		}
		validators, powers, err := g.GetValidatorsAndPowersFromContract(remoteChainNumber)

		return validators, powers, remoteChainNumber, err
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
func (g *Governance) GetValidatorsAndPowersFromContract(blockNumber uint64) ([]common.Address, []uint64, error) {
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
		EpochIdx   *big.Int
		Validators []common.Address
		Powers     []*big.Int
	}

	var v validators

	if err := g.validatorSetABI.UnpackIntoInterface(&v, contractFunc_GetValidator, result); err != nil {
		return nil, nil, err
	}

	if len(v.Validators) != len(v.Powers) {
		return nil, nil, fmt.Errorf("invalid validator set: validator count %d is mismatch with power count %d.",
			len(v.Validators), len(v.Powers))
	}

	powers := make([]uint64, len(v.Powers))
	for i, p := range v.Powers {
		powers[i] = p.Uint64()
	}

	return v.Validators, powers, nil
}

func (g *Governance) SubmitHeaderToContractWithRetry(header *types.Header) {
	for i := 0; i < 3; i++ {
		if err := g.SubmitHeaderToContract(header); err == nil {
			return
		}
	}
	log.Warn("SubmitHeaderToContractWithRetry failed", "height", header.Number, "hash", header.Hash().Hex())
	// need to manually submit header to remote chain if failed.
}

func (g *Governance) SubmitHeaderToContract(header *types.Header) error {
	cph := types.CopyHeader(header)
	cph.Commit = nil
	eHeader, err := rlp.EncodeToBytes(cph)
	if err != nil {
		return err
	}

	data, err := g.validatorSetABI.Pack(contractFunc_SubmitHeader, eHeader, header.Commit.Signatures)
	if err != nil {
		return err
	}

	gasPrice, err := g.client.SuggestGasPrice(g.ctx)
	if err != nil {
		return err
	}

	nonce, err := g.client.PendingNonceAt(g.ctx, g.signer.Address())
	if err != nil {
		return err
	}

	baseTx := &types.LegacyTx{
		To:       g.contract,
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		Value:    new(big.Int).SetInt64(0),
		Data:     data,
	}

	signedTx, err := g.signer.SignTX(types.NewTx(baseTx), new(big.Int).SetUint64(g.config.ContractChainID))
	if err != nil {
		return err
	}

	return g.client.SendTransaction(g.ctx, signedTx)
}
