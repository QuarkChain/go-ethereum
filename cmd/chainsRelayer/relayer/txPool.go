package relayer

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"math/big"
	"sync/atomic"
	"time"
)

type txArg struct {
	to          common.Address
	input       []byte
	value       int64
	receiptChan chan types.Receipt
	errChan     chan error
}

func newTxArg(to common.Address, input []byte, value int64) *txArg {
	receiptChan := make(chan types.Receipt)
	errChan := make(chan error)
	return &txArg{to: to, input: input, value: value, receiptChan: receiptChan, errChan: errChan}
}

type submitTxPool struct {
	config        config.ChainConfig
	relayer       *Relayer
	Executor      *ethclient.Client
	receiveTxArgs chan *txArg

	accNonce *uint64
	ctx      context.Context
}

func newSubmitTxPool(config config.ChainConfig, relayer *Relayer, executor *ethclient.Client, ctx context.Context) *submitTxPool {
	nonce, err := executor.PendingNonceAt(ctx, relayer.Address())
	if err != nil {
		panic(err)
		return nil
	}

	receiveChan := make(chan *txArg, 20)
	return &submitTxPool{config: config, relayer: relayer, Executor: executor, ctx: ctx, accNonce: &nonce, receiveTxArgs: receiveChan}
}

func (p *submitTxPool) AccNonce() uint64 {
	return *p.accNonce
}

func (p *submitTxPool) IncreaseAccNonce() {
	atomic.AddUint64(p.accNonce, 1)
}

func (p *submitTxPool) running() {
	for arg := range p.receiveTxArgs {
		// generate transaction by txArg
		tx, err := p.generateTxWithNonce(*arg, p.AccNonce())
		if err != nil {
			arg.errChan <- err
			continue
		}

		// send transaction to blockchain
		err = p.Executor.SendTransaction(p.ctx, tx)
		if err != nil {
			arg.errChan <- err
			continue
		}

		p.IncreaseAccNonce()

		// waiting receipt
		if arg.receiptChan != nil {
			go func(txHash common.Hash, ec chan error, rc chan types.Receipt) {
				for {
					time.Sleep(15 * time.Second)
					receipt, err2 := p.Executor.TransactionReceipt(p.ctx, txHash)
					if err2 == ethereum.NotFound {
						continue
					}

					if err2 != nil {
						ec <- err2
						return
					}

					rc <- *receipt
					return
				}
			}(tx.Hash(), arg.errChan, arg.receiptChan)
		}
	}
}

func (p *submitTxPool) generateTx(arg txArg) (*types.Transaction, error) {
	relayerAddr := crypto.PubkeyToAddress(p.relayer.prikey.PublicKey)
	nonce, err := p.Executor.PendingNonceAt(p.ctx, relayerAddr)
	if err != nil {
		return nil, err
	}

	//Estimate gasTipCap
	tipCap, err := p.Executor.SuggestGasTipCap(p.ctx)
	if err != nil {
		return nil, err
	}

	latestHeader, err := p.Executor.HeaderByNumber(p.ctx, nil)
	if err != nil {
		return nil, err
	}

	gasFeeCap := new(big.Int).Add(
		tipCap, new(big.Int).Mul(latestHeader.BaseFee, big.NewInt(2)),
	)

	msg := ethereum.CallMsg{
		From:      relayerAddr,
		To:        &arg.to,
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Value:     big.NewInt(arg.value),
		Data:      arg.input,
	}
	gasLimit, err := p.Executor.EstimateGas(p.ctx, msg)
	if err != nil {
		gasLimit = 1500000
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(p.config.ChainId()),
		Nonce:     nonce,
		To:        &arg.to,
		Value:     big.NewInt(arg.value),
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit * 2,
		Data:      arg.input,
	})

	signer := types.LatestSignerForChainID(big.NewInt(p.config.ChainId()))
	signedTx, err := types.SignTx(tx, signer, p.relayer.prikey)
	if err != nil {
		return nil, err
	}
	return signedTx, nil
}

func (p *submitTxPool) sendTxArg(arg *txArg) {
	p.receiveTxArgs <- arg
}

func (p *submitTxPool) generateTxWithNonce(arg txArg, nonce uint64) (*types.Transaction, error) {
	relayerAddr := crypto.PubkeyToAddress(p.relayer.prikey.PublicKey)
	//Estimate gasTipCap
	tipCap, err := p.Executor.SuggestGasTipCap(p.ctx)
	if err != nil {
		return nil, err
	}

	latestHeader, err := p.Executor.HeaderByNumber(p.ctx, nil)
	if err != nil {
		return nil, err
	}

	gasFeeCap := new(big.Int).Add(
		tipCap, new(big.Int).Mul(latestHeader.BaseFee, big.NewInt(2)),
	)

	msg := ethereum.CallMsg{
		From:      relayerAddr,
		To:        &arg.to,
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Value:     big.NewInt(arg.value),
		Data:      arg.input,
	}
	gasLimit, err := p.Executor.EstimateGas(p.ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("EstimateGas Error:%s", err.Error())
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(p.config.ChainId()),
		Nonce:     nonce,
		To:        &arg.to,
		Value:     big.NewInt(arg.value),
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit * 2,
		Data:      arg.input,
	})

	signer := types.LatestSignerForChainID(big.NewInt(p.config.ChainId()))
	signedTx, err := types.SignTx(tx, signer, p.relayer.prikey)
	if err != nil {
		return nil, err
	}
	return signedTx, nil
}
