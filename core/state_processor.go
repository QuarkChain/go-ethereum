// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
//
// The function is called by either
// - a non-proposer validator to replay the block and verify the MR outputs from its external client (reuseMindReadingOutput == false); or
// - a non-valiator node to replay the block and verify the MR outpus from MR outputs encoded the block (reuseMindReadingOutput == true).
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config, reuseMindReadingOutput bool) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	blockContext := NewEVMBlockContext(header, p.bc, nil)

	mindReadingEnable := p.bc.IsMindReadingEnable(block.Number())
	var mrctx *vm.MindReadingContext
	if mindReadingEnable {
		// 'reuseMindReadingOutput' determines the way of execution for MindReading.
		// e.g. reuseMindReadingOutput = false represents that the node will obtain external data by itself through MindReadingClient
		// e.g. reuseMindReadingOutput = true represents that the node will obtain external data, already produced by the proposer and verified by validators, from the block.uncles
		mrctx = p.bc.mindReading.GenerateVMMindReadingCtx(blockNumber, reuseMindReadingOutput)
	}
	vmenv := vm.NewEVMWithMRC(blockContext, vm.TxContext{}, mrctx, statedb, p.config, cfg)
	iterator := types.NewMindReadingOutputIterator(block)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}

		// obtains mrOuput from the block.unlces[index].extra if the transaction previously produced mrOuput
		reuseableMROutput := iterator.GetNextMindReadingOutput(tx)

		statedb.Prepare(tx.Hash(), i)
		receipt, mrOutput, err := applyTransaction(msg, p.config, p.bc, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, reuseableMROutput)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}

		if mindReadingEnable {
			if !reuseMindReadingOutput {
				// non-proposer validator fails to verify the MR data
				if !bytes.Equal(mrOutput, reuseableMROutput) {
					log.Error("failed to verify MindReadingOutput as validator", "txHash", tx.Hash().Hex(), "Expect MindReadingOutput", common.Bytes2Hex(reuseableMROutput), "MindReadingOutput", common.Bytes2Hex(mrOutput))
					return nil, nil, 0, fmt.Errorf("validator failed to verify MindReading Output, tx: %s", tx.Hash().Hex())
				}
			} else {
				// a non-validator fails to replay the MR data
				if vmenv.GetNextReplayableCCCOutput() != nil {
					log.Error("CCCOutpus is only partially consumed after completing a replay-mind-reading using the produced CCCOutpus", "txHash", tx.Hash().Hex(), "reuseableMROutput", common.Bytes2Hex(reuseableMROutput))
					return nil, nil, 0, fmt.Errorf("CCCOutpus is only partially consumed after completing a replay-mind-reading using the produced CCCOutpus, tx: %s", tx.Hash().Hex())
				}
				if !bytes.Equal(mrOutput, reuseableMROutput) {
					log.Error("produced MindReadingOutput is different with received MindReading Output as sync-node", "txHash", tx.Hash().Hex(), "Expect MindReadingOutput", common.Bytes2Hex(reuseableMROutput), "MindReadingOutput", common.Bytes2Hex(mrOutput))
					return nil, nil, 0, fmt.Errorf("failed to replay MindReading Output, tx: %s", tx.Hash().Hex())
				}
			}
		}

		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	// Make sure all mind reading outputs are consumed
	if iterator.GetIndex() != len(block.Uncles()) {
		return nil, nil, 0, fmt.Errorf("unconsumed MR outputs, isReplay: %t", reuseMindReadingOutput)
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, presetMindReadingOutput []byte) (*types.Receipt, []byte, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)
	err := evm.PresetCCCOutputs(presetMindReadingOutput)
	if err != nil {
		return nil, nil, err
	}
	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		log.Warn("ApplyMessage", "sender", msg.From().Hex(), "tx hash", tx.Hash(), "tx nonce", tx.Nonce(), "tx to", tx.To(), "err", err.Error())
		return nil, nil, err
	}
	if result.Err != nil {
		log.Warn("ApplyMessage", "sender", msg.From().Hex(), "tx hash", tx.Hash(), "tx nonce", tx.Nonce(), "tx to", tx.To(), "result.Err", result.Err.Error())
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, result.CCCOutputs, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
//
// This function is expected to be called by miner.worker by a block proposer.
func ApplyTransaction(config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, []byte, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	mrctx := bc.mindReading.GenerateVMMindReadingCtx(header.Number, false)
	vmenv := vm.NewEVMWithMRC(blockContext, vm.TxContext{}, mrctx, statedb, config, cfg)
	return applyTransaction(msg, config, bc, author, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv, nil)
}
