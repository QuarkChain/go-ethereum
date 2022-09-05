package relayer

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"time"
)

func (c *ChainOperator) SendMintNativeTx(to common.Address, ethChainOperator *ChainOperator) func(types.Log) {
	return func(log types.Log) {

		arg, err := c.generateMintNativeTxArg(to, log.TxHash, int64(log.Index))
		if err != nil {
			panic(err)
		}

		err = SendMintNativeTxToWeb3Q(ethChainOperator, c, log.BlockNumber).Doing(arg)
		//if err != nil {
		//	c.config.logger.Error("failed to send transaction to blockchain", "ChainId", signedTx.ChainId(), "TxHash", signedTx.Hash())
		//	return
		//}
		//c.config.logger.Info("send transaction succeed!", "ChainId", signedTx.ChainId(), "TxHash", signedTx.Hash())

	}
}

type Proof struct {
	Value     []byte `json:"value"`
	ProofPath []byte `json:"proofPath""`
	HpKey     []byte `json:"hpKey"`
}

func (w3q *ChainOperator) SendMintW3qErc20TxAndSubmitHeadTx(contractAddr common.Address, ethChainOperator *ChainOperator, lightClientAddr common.Address) func(types.Log) {
	return func(t types.Log) {

		// get receipt Proof from rpc
		receiptProof, err := w3q.Executor.ReceiptProof(w3q.Ctx, t.TxHash)
		if err != nil {
			panic(err)
		}

		// generate proof
		prf := Proof{
			Value:     receiptProof.ReceiptValue,
			ProofPath: receiptProof.ReceiptPath,
			HpKey:     receiptProof.ReceiptKey,
		}

		// submit this block
		h, err := w3q.Executor.HeaderByNumber(w3q.Ctx, big.NewInt(0).SetUint64(t.BlockNumber))
		if err != nil {
			log.Error("SendMintW3qErc20Tx: get web3q block fail", "err", err, "blockNumber", t.BlockNumber)
		}

		cph := types.CopyHeader(h)
		cph.Commit = nil
		eHeader, err := rlp.EncodeToBytes(cph)
		if err != nil {
			panic(err)
			return
		}
		eCommit, err := rlp.EncodeToBytes(h.Commit)
		if err != nil {
			panic(err)
			return
		}

		arg, err := ethChainOperator.generateSubmitHeadTxArg(lightClientAddr, h.Number, eHeader, eCommit, false)
		if err != nil {
			log.Warn("generateSubmitHeadTxArg fail", "err", err, "blockNumber", h.Number)
		}
		SendTxToEthereum(ethChainOperator, w3q).Doing(arg)

		select {
		case rErr := <-arg.errChan:
			log.Error("SubmitHeader:SendTxToEthereum Happen Error:", "err", rErr)
		case receipt := <-arg.receiptChan:
			log.Info("SubmitHeader Succeed", "TxHash", receipt.TxHash, "BlockNumber", receipt.BlockNumber, "GasUsed:", receipt.GasUsed)
		}

		mintW3qTxArg, err := ethChainOperator.generateMintW3qErc20TxArg(contractAddr, receiptProof.BlockNumber, prf, uint64(t.Index))
		if err != nil {
			ethChainOperator.config.logger.Error("generateMintW3qErc20Tx:happen err", "err", err)
			return
		}
		SendTxToEthereum(ethChainOperator, w3q).Doing(mintW3qTxArg)

		select {
		case rErr := <-mintW3qTxArg.errChan:
			ethChainOperator.config.logger.Error("MintErc20:SendTxToEthereum Happen Error:", "err", rErr)
		case receipt := <-mintW3qTxArg.receiptChan:
			ethChainOperator.config.logger.Info("Mint Erc20 Succeed", "TxHash", receipt.TxHash, "BlockNumber", receipt.BlockNumber, "GasUsed:", receipt.GasUsed)
		}

		return
	}
}

// todo generate proof
func (w3q *ChainOperator) SendMintW3qErc20Tx(contractAddr common.Address, ethChainOperator *ChainOperator) func(types.Log) {
	return func(t types.Log) {

		// get receipt Proof from rpc
		receiptProof, err := w3q.Executor.ReceiptProof(w3q.Ctx, t.TxHash)
		if err != nil {
			panic(err)
		}

		// generate proof
		prf := Proof{
			Value:     receiptProof.ReceiptValue,
			ProofPath: receiptProof.ReceiptPath,
			HpKey:     receiptProof.ReceiptKey,
		}

		time.Sleep(5 * time.Second)
		// generate tx
		retryTimes := 6
		for {
			if retryTimes == 0 {
				break
			}

			txArg, err := ethChainOperator.generateMintW3qErc20TxArg(contractAddr, receiptProof.BlockNumber, prf, uint64(t.Index))
			if err != nil {
				if err.Error() == "execution reverted" {
					ethChainOperator.config.logger.Warn("generateMintW3qErc20Tx:waiting head submit")
					time.Sleep(5 * time.Second)
				} else {
					ethChainOperator.config.logger.Error("generateMintW3qErc20Tx:happen err", "err", err)
				}

				retryTimes--
				continue

			}

			err = SendTxToEthereum(ethChainOperator, w3q).Doing(txArg)
			if err != nil {
				ethChainOperator.config.logger.Error("SendTxToEthereum:happen err", "err", err)
				retryTimes--
				continue
			}

			break

		}

	}
}

func (eth *ChainOperator) SendBatchMintForBridgeTokenAfterSubmitHeaderTx(w3q *ChainOperator, lightClientAddr common.Address, w3qNative common.Address, w3qErc20 common.Address) func(interface{}) {
	return func(val interface{}) {

		h, ok := val.(*types.Header)
		if !ok {
			panic(fmt.Errorf("receive value with invalid type"))
			return
		}

		// Determine whether there is a cross-chain event in this block
		blockHash := h.Hash()
		filter := w3q.getFilterByEventName(w3qNative, "burnNativeToken")
		filter.BlockHash = &blockHash
		logs, err := w3q.Listener.FilterLogs(w3q.Ctx, filter)
		if err != nil {
			log.Error("Filter BurnNativeToken Log Fail", "err", err, "blockNumber", h.Number)
			return
		}

		if len(logs) == 0 {
			log.Warn("The Block does not exist any BurnNativeToken event", "blockNumber", h.Number)
			return
		}

		// generate submitHeader Input
		cph := types.CopyHeader(h)
		cph.Commit = nil
		eHeader, err := rlp.EncodeToBytes(cph)
		if err != nil {
			panic(err)
			return
		}
		eCommit, err := rlp.EncodeToBytes(h.Commit)
		if err != nil {
			panic(err)
			return
		}

		// generate SubmitHeader txArg
		txArg, err := eth.generateSubmitHeadTxArg(lightClientAddr, h.Number, eHeader, eCommit, false)
		if err != nil {
			// todo if the error is "head exist" ,
			log.Warn("generateSubmitHeadTx fail", "err", err, "blockNumber", h.Number)
		}

		SendTxToEthereum(eth, w3q).Doing(txArg)
		select {
		case txErr := <-txArg.errChan:
			log.Error("【SubmitHeader】SendTxToEthereum Fail", "error", txErr)
			return
		case receipt := <-txArg.receiptChan:
			log.Info("【SubmitHeader】SendTxToEthereum Succeed", "txHash", receipt.TxHash, "gasUsed", receipt.GasUsed, "blockNumber", receipt.BlockNumber)
		}

		proofs := make([]Proof, 0)
		logIdxs := make([]*big.Int, 0)
		// get the merkle proof path of the cross chain event
		for _, logData := range logs {
			receiptProof, err := w3q.Executor.ReceiptProof(w3q.Ctx, logData.TxHash)
			if err != nil {
				log.Error("get Receipt Proof Fail", "err", err)
				return
			}

			// generate proof
			prf := Proof{
				Value:     receiptProof.ReceiptValue,
				ProofPath: receiptProof.ReceiptPath,
				HpKey:     receiptProof.ReceiptKey,
			}

			proofs = append(proofs, prf)
			logIdxs = append(logIdxs, big.NewInt(0).SetUint64(uint64(logData.Index)))
		}

		arg, err := eth.generateBatchMintForBridgeTokenTxArg(w3qErc20, h.Number, proofs, logIdxs)
		if err != nil {
			panic(err)
			return
		}

		SendTxToEthereum(eth, w3q).Doing(arg)
		select {
		case txErr := <-arg.errChan:
			log.Error("【BatchMintForBridgeToken】SendTxToEthereum Fail", "error", txErr)
			return
		case receipt := <-arg.receiptChan:
			log.Info("【BatchMintForBridgeToken】SendTxToEthereum Succeed", "txHash", receipt.TxHash, "gasUsed", receipt.GasUsed, "blockNumber", receipt.BlockNumber)
			return
		}

	}
}

func (eth *ChainOperator) SendBatchMintForBridgeTokenWhenSubmitHeaderTx(w3q *ChainOperator, lightClientAddr common.Address, w3qNative common.Address, w3qErc20 common.Address) func(interface{}) {
	return func(val interface{}) {

		h, ok := val.(*types.Header)
		if !ok {
			panic(fmt.Errorf("receive value with invalid type"))
			return
		}

		// generate input
		cph := types.CopyHeader(h)
		cph.Commit = nil
		eHeader, err := rlp.EncodeToBytes(cph)
		if err != nil {
			panic(err)
			return
		}
		eCommit, err := rlp.EncodeToBytes(h.Commit)
		if err != nil {
			panic(err)
			return
		}

		blockHash := h.Hash()
		filter := w3q.getFilterByEventName(w3qNative, "burnNativeToken")
		filter.BlockHash = &blockHash
		logs, err := w3q.Listener.FilterLogs(w3q.Ctx, filter)
		if err != nil {
			log.Error("Filter BurnNativeToken Log Fail", "err", err, "blockNumber", h.Number)
			return
		}

		if len(logs) == 0 {
			log.Debug("The Block does not exist any BurnNativeToken event", "blockNumber", h.Number)
			return
		}

		proofs := make([]Proof, 0)
		logIdxs := make([]*big.Int, 0)
		for _, logData := range logs {
			receiptProof, err := w3q.Executor.ReceiptProof(w3q.Ctx, logData.TxHash)
			if err != nil {
				log.Error("get Receipt Proof Fail", "err", err)
				return
			}

			// generate proof
			prf := Proof{
				Value:     receiptProof.ReceiptValue,
				ProofPath: receiptProof.ReceiptPath,
				HpKey:     receiptProof.ReceiptKey,
			}

			proofs = append(proofs, prf)
			logIdxs = append(logIdxs, big.NewInt(0).SetUint64(uint64(logData.Index)))
		}

		arg, err := eth.generateBatchMintWhenSubmitHeaderTxArg(w3qErc20, h.Number, eHeader, eCommit, false, proofs, logIdxs)
		if err != nil {
			panic(err)
			return
		}

		SendTxToEthereum(eth, w3q).Doing(arg)
		select {
		case txErr := <-arg.errChan:
			log.Error("【BatchMintWhenSubmitHeader】SendTxToEthereum Fail", "error", txErr)
			return
		case receipt := <-arg.receiptChan:
			log.Info("【BatchMintWhenSubmitHeader】SendTxToEthereum Succeed", "txHash", receipt.TxHash, "gasUsed", receipt.GasUsed, "blockNumber", receipt.BlockNumber)
		}

	}
}

func (eth *ChainOperator) sendSubmitHeadTxOnce(w3q *ChainOperator, lightClientAddr common.Address) func(interface{}) {
	return func(val interface{}) {

		retryTimes := 6

		h, ok := val.(*types.Header)
		if !ok {
			panic(fmt.Errorf("receive value with invalid type"))
			return
		}

		// generate input
		cph := types.CopyHeader(h)
		cph.Commit = nil
		eHeader, err := rlp.EncodeToBytes(cph)
		if err != nil {
			panic(err)
			return
		}
		eCommit, err := rlp.EncodeToBytes(h.Commit)
		if err != nil {
			panic(err)
			return
		}

		// submitHead
		for {
			if retryTimes == 0 {
				break
			}
			txArg, err := eth.generateSubmitHeadTxArg(lightClientAddr, h.Number, eHeader, eCommit, false)
			if err != nil {
				// todo if the error is "head exist" ,
				retryTimes--
				eth.config.logger.Warn("generateSubmitHeadTx fail", "err", err, "blockNumber", h.Number)
				continue
			}

			eth.config.logger.Info("sending submitHead tx")
			err = SendTxToEthereum(eth, w3q).Doing(txArg)
			if err != nil {
				// todo if the error is "head exist" ,
				eth.config.logger.Warn("SendTxToEthereum fail", "err", err, "blockNumber", h.Number)
				retryTimes--
				continue
			}
		}

	}
}

func (eth *ChainOperator) generateSubmitHeadTxArg(contractAddr common.Address, height *big.Int, headBytes []byte, commitBytes []byte, lookByIndex bool) (*txArg, error) {
	return eth.generateTxArgForContractMethod("submitHeader", contractAddr, 0, height, headBytes, commitBytes, lookByIndex)
}

func (eth *ChainOperator) generateMintW3qErc20TxArg(contractAddr common.Address, height uint64, proof Proof, logIdx uint64) (*txArg, error) {
	return eth.generateTxArgForContractMethod("mintForBridgeToken", contractAddr, 0, big.NewInt(0).SetUint64(height), proof, big.NewInt(0).SetUint64(logIdx))
}

func (eth *ChainOperator) generateBatchMintForBridgeTokenTxArg(contractAddr common.Address, height *big.Int, proofs []Proof, logIdxs []*big.Int) (*txArg, error) {
	return eth.generateTxArgForContractMethod("batchMintForBridgeToken", contractAddr, 0, height, proofs, logIdxs)
}

func (eth *ChainOperator) generateBatchMintWhenSubmitHeaderTxArg(contractAddr common.Address, height *big.Int, headBytes []byte, commitBytes []byte, lookByIndex bool, proofs []Proof, logIdxs []*big.Int) (*txArg, error) {
	return eth.generateTxArgForContractMethod("batchMintWhenSubmitHeader", contractAddr, 0, height, headBytes, commitBytes, lookByIndex, proofs, logIdxs)
}

func (c *ChainOperator) generateMintNativeTxArg(to common.Address, txHash common.Hash, logIdx int64) (*txArg, error) {
	return c.generateTxArgForContractMethod("mintNative", to, 0, txHash, big.NewInt(logIdx))
}
