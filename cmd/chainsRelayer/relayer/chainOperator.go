package relayer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"io/ioutil"
	"math/big"
	"os"
	"sync"
	"time"
)

type ChainConfig struct {
	logger  log.Logger
	chainId *big.Int
	httpUrl string
	wsUrl   string
	dbFile  string
}

type Relayer struct {
	address  common.Address
	filepath string
	prikey   *ecdsa.PrivateKey
}

// Relayer要实现另外一种方法从keyStore文件中直接获取私钥
func NewRelayerByKeyStore(filepath string, passwd string) (*Relayer, error) {
	b, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(b, passwd)
	if err != nil {
		return nil, err
	}
	return &Relayer{address: key.Address, filepath: filepath, prikey: key.PrivateKey}, nil
}

func NewRelayer(filepath string) (*Relayer, error) {
	key, err := utils.LoadPriKey(filepath)
	if err != nil {
		return nil, err
	}
	return &Relayer{filepath: filepath, prikey: key}, nil
}

func (r *Relayer) Address() common.Address {
	return r.address
}
func NewChainConfig(httpUrl string, wsUrl string, logLevel int, dbf string) *ChainConfig {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(logLevel))
	log.Root().SetHandler(glogger)
	return &ChainConfig{logger: log.Root(), httpUrl: httpUrl, wsUrl: wsUrl, dbFile: dbf}
}

func (this *ChainConfig) ChainId() *big.Int {
	return this.chainId
}

func (this *ChainConfig) setChainId(cid *big.Int) {
	this.chainId = cid
}

type ChainOperator struct {
	config  *ChainConfig
	relayer *Relayer

	// The listener initialized through ws_rpc_url monitors the contract events that are happening
	Listener *ethclient.Client
	// The Executor initialized through http_rpc_url sends a transaction to the blockchain
	Executor *ethclient.Client

	contracts map[common.Address]*Contract

	Ctx        context.Context
	CancelFunc context.CancelFunc

	ListenTaskList []ListenTask

	errChan chan error

	db *leveldb.Database
}

func (this *ChainOperator) name() string {
	return "ChainOperator"
}

func NewChainOperator(config *ChainConfig, r *Relayer, pctx context.Context) (*ChainOperator, error) {
	listener, err := ethclient.Dial(config.wsUrl)
	if err != nil {
		log.Error("ethclient.Dial failed:", "err", err)
		return nil, err
	}

	executor, err := ethclient.Dial(config.httpUrl)
	if err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithCancel(pctx)

	chainId, err := executor.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	config.setChainId(chainId)

	database, err := leveldb.New(config.dbFile, 256, 0, "ChainId_"+config.ChainId().String(), false)
	if err != nil {
		return nil, err
	}

	return &ChainOperator{config: config, relayer: r, Listener: listener, Executor: executor, Ctx: ctx, CancelFunc: cancelFunc, db: database}, nil
}

func (this *ChainOperator) Quit() {
	this.CancelFunc()
}

func (this *ChainOperator) BlockNumber() (uint64, error) {
	return this.Executor.BlockNumber(this.Ctx)
}

func (co *ChainOperator) RegisterContract(address common.Address, abi abi.ABI) {
	if co.contracts == nil {
		co.contracts = make(map[common.Address]*Contract)
	}
	co.contracts[address] = NewContract(address, abi)
}

// InsertListenTask inserts the new listenTask in the end of chainOperator.ListenTaskList and returns the taskIndex
func (co *ChainOperator) InsertListenTask(task ListenTask) int {
	taskIndex := len(co.ListenTaskList)
	co.ListenTaskList = append(co.ListenTaskList, task)
	return taskIndex
}

// SubscribeEvent subscribe the event of the contract by the given eventName and contract address
func (co *ChainOperator) SubscribeEvent(address common.Address, eventName string, handleFunc func(types.Log)) (int, error) {
	receiveChan := make(chan types.Log)
	sCtx, cf := context.WithCancel(co.Ctx)
	sub, err := co.Listener.SubscribeFilterLogs(sCtx, ethereum.FilterQuery{Addresses: []common.Address{address}, Topics: [][]common.Hash{{co.contracts[address].ContractAbi.Events[eventName].ID}}}, receiveChan)
	if err != nil {
		return 0, err
	}
	task := NewListenEventTask(address, eventName, receiveChan, sub, sCtx, cf)

	//
	if handleFunc != nil {
		task.handleFunc = handleFunc
	}

	taskIndex := co.InsertListenTask(task)

	co.contracts[task.address].insertTaskIndex(taskIndex, task.eventName)

	return taskIndex, nil
}

func (co *ChainOperator) getEventTaskIndex(address common.Address, eventName string) int {
	taskIndex := co.contracts[address].getTaskIndex(eventName)
	return taskIndex
}

func (co *ChainOperator) getEventTask(taskIndex int) ListenTask {
	return co.ListenTaskList[taskIndex]
}

func (co *ChainOperator) UnsubscribeEvent(address common.Address, eventName string) bool {
	taskIndex := co.getEventTaskIndex(address, eventName)

	task := co.ListenTaskList[taskIndex]

	if !task.isStart() {
		return false
	}

	task.stop()
	return true
}

func (co *ChainOperator) UnsubscribeEventByIndex(taskIndex int) bool {

	task := co.ListenTaskList[taskIndex]

	if !task.isStart() {
		return false
	}
	task.stop()
	return true
}

func (co *ChainOperator) reSubscribeEvent(task *ListenEventTask) error {
	task.sub.Unsubscribe()
	task.cancleFunc()

	sCtx, cf := context.WithCancel(co.Ctx)
	sub, err := co.Listener.SubscribeFilterLogs(sCtx, ethereum.FilterQuery{Addresses: []common.Address{task.address}, Topics: [][]common.Hash{{co.contracts[task.address].ContractAbi.Events[task.eventName].ID}}}, task.independentReceiveChan)
	if err != nil {
		return err
	}
	task.sub = sub
	task.ctx = sCtx
	task.cancleFunc = cf

	go func() {
		task.running(co)
	}()

	return nil

}

func (co *ChainOperator) StartListening() {
	var wg sync.WaitGroup
	for _, t := range co.ListenTaskList {
		task := t
		if !task.isStart() {
			continue
		}
		wg.Add(1)
		go func() {
			curTask := task
			curTask.running(co)
			defer wg.Done()
		}()
	}
	wg.Wait()
}

func (co *ChainOperator) callContractMethod(methodName string, to common.Address, value int64, args ...interface{}) (*types.Transaction, error) {
	abi, exist := co.contracts[to]
	if !exist {
		return nil, fmt.Errorf("the address has not registered")
	}

	input, err := abi.ContractAbi.Pack(methodName, args...)
	if err != nil {
		return nil, err
	}

	return co.signedTx(to, input, value)
}

func (co *ChainOperator) callContractMethodForce(methodName string, to common.Address, value int64, args ...interface{}) (*types.Transaction, error) {
	abi, exist := co.contracts[to]
	if !exist {
		return nil, fmt.Errorf("the address has not registered")
	}

	input, err := abi.ContractAbi.Pack(methodName, args...)
	if err != nil {
		return nil, err
	}

	return co.signedTxForce(to, input, value)
}

func (co *ChainOperator) signedTx(to common.Address, txdata []byte, value int64) (*types.Transaction, error) {
	relayerAddr := crypto.PubkeyToAddress(co.relayer.prikey.PublicKey)
	nonce, err := co.Executor.PendingNonceAt(co.Ctx, relayerAddr)
	if err != nil {
		return nil, err
	}

	//Estimate gasTipCap
	tipCap, err := co.Executor.SuggestGasTipCap(co.Ctx)
	if err != nil {
		return nil, err
	}

	latestHeader, err := co.Executor.HeaderByNumber(co.Ctx, nil)
	if err != nil {
		return nil, err
	}

	gasFeeCap := new(big.Int).Add(
		tipCap, new(big.Int).Mul(latestHeader.BaseFee, big.NewInt(2)),
	)

	msg := ethereum.CallMsg{
		From:      relayerAddr,
		To:        &to,
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Value:     big.NewInt(value),
		Data:      txdata,
	}
	gasLimit, err := co.Executor.EstimateGas(co.Ctx, msg)
	if err != nil {
		return nil, err
	}
	//fmt.Println(gasLimit)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   co.config.ChainId(),
		Nonce:     nonce,
		To:        &to,
		Value:     big.NewInt(value),
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit * 2,
		Data:      txdata,
	})

	signer := types.LatestSignerForChainID(co.config.chainId)
	signedTx, err := types.SignTx(tx, signer, co.relayer.prikey)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

func (co *ChainOperator) signedTxForce(to common.Address, txdata []byte, value int64) (*types.Transaction, error) {
	relayerAddr := crypto.PubkeyToAddress(co.relayer.prikey.PublicKey)
	nonce, err := co.Executor.PendingNonceAt(co.Ctx, relayerAddr)
	if err != nil {
		return nil, err
	}

	//Estimate gasTipCap
	tipCap, err := co.Executor.SuggestGasTipCap(co.Ctx)
	if err != nil {
		return nil, err
	}

	latestHeader, err := co.Executor.HeaderByNumber(co.Ctx, nil)
	if err != nil {
		return nil, err
	}

	gasFeeCap := new(big.Int).Add(
		tipCap, new(big.Int).Mul(latestHeader.BaseFee, big.NewInt(2)),
	)

	msg := ethereum.CallMsg{
		From:      relayerAddr,
		To:        &to,
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Value:     big.NewInt(value),
		Data:      txdata,
	}
	gasLimit, err := co.Executor.EstimateGas(co.Ctx, msg)
	if err != nil {
		gasLimit = 1500000
	}
	//fmt.Println(gasLimit)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   co.config.ChainId(),
		Nonce:     nonce,
		To:        &to,
		Value:     big.NewInt(value),
		GasTipCap: tipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit * 2,
		Data:      txdata,
	})

	signer := types.LatestSignerForChainID(co.config.chainId)
	signedTx, err := types.SignTx(tx, signer, co.relayer.prikey)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

func (c *ChainOperator) SendMintNativeTx(to common.Address, ethChainOperator *ChainOperator) func(types.Log) {
	return func(log types.Log) {

		// 生成一个已经签名好的交易
		signedTx, err := c.generateMintNativeTx(to, log.TxHash, int64(log.Index))
		if err != nil {
			panic(err)
		}

		err = SendTx_MintNative(ethChainOperator, c, log.BlockNumber).Doing(signedTx)
		if err != nil {
			c.config.logger.Error("failed to send transaction to blockchain", "ChainId", signedTx.ChainId(), "TxHash", signedTx.Hash())
			return
		}
		c.config.logger.Info("send transaction succeed!", "ChainId", signedTx.ChainId(), "TxHash", signedTx.Hash())

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
			ethChainOperator.config.logger.Error("SendMintW3qErc20Tx: get web3q block fail", "err", err, "blockNumber", t.BlockNumber)
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

		signedTx, err := ethChainOperator.generateSubmitHeadTx(lightClientAddr, h.Number, eHeader, eCommit, false)
		if err != nil {
			ethChainOperator.config.logger.Warn("SendMintW3qErc20Tx: generateSubmitHeadTx fail", "err", err, "blockNumber", h.Number)
		}
		err = SendTxToEthereum(ethChainOperator, w3q).Doing(signedTx)
		if err != nil {
			// todo if the error is "head exist" ,
			ethChainOperator.config.logger.Warn("SendMintW3qErc20Tx: SendTxToEthereum fail", "err", err, "blockNumber", h.Number)
		}

		signedTx, err = ethChainOperator.generateMintW3qErc20Tx(contractAddr, receiptProof.BlockNumber, prf, uint64(t.Index))
		if err != nil {
			ethChainOperator.config.logger.Error("generateMintW3qErc20Tx:happen err", "err", err)
			return
		}

		err = SendTxToEthereum(ethChainOperator, w3q).Doing(signedTx)
		if err != nil {
			ethChainOperator.config.logger.Error("SendTxToEthereum:happen err", "err", err)
			return
		} else {
			ethChainOperator.config.logger.Info("mint erc20 succeed!")
		}

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

			signedTx, err := ethChainOperator.generateMintW3qErc20Tx(contractAddr, receiptProof.BlockNumber, prf, uint64(t.Index))
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

			err = SendTxToEthereum(ethChainOperator, w3q).Doing(signedTx)
			if err != nil {
				ethChainOperator.config.logger.Error("SendTxToEthereum:happen err", "err", err)
				retryTimes--
				continue
			}

			break

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
			signedTx, err := eth.generateSubmitHeadTx(lightClientAddr, h.Number, eHeader, eCommit, false)
			if err != nil {
				// todo if the error is "head exist" ,
				retryTimes--
				eth.config.logger.Warn("generateSubmitHeadTx fail", "err", err, "blockNumber", h.Number)
				continue
			}

			eth.config.logger.Info("sending submitHead tx")
			err = SendTxToEthereum(eth, w3q).Doing(signedTx)
			if err != nil {
				// todo if the error is "head exist" ,
				eth.config.logger.Warn("SendTxToEthereum fail", "err", err, "blockNumber", h.Number)
				retryTimes--
				continue
			}
		}

	}
}

func (eth *ChainOperator) sendSubmitHeadTx(w3q *ChainOperator, lightClientAddr common.Address, receiveHeadChan chan interface{}) func(interface{}) {
	return func(val interface{}) {
		retryTimes := 6
		for {

			select {
			case head := <-receiveHeadChan:

				h, ok := head.(*types.Header)
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
				signedTx, err := eth.generateSubmitHeadTx(lightClientAddr, h.Number, eHeader, eCommit, false)
				if err != nil {
					// todo if the error is "head exist" ,
					retryTimes--
					eth.config.logger.Warn("generateSubmitHeadTx fail", "err", err)
					continue
				}

				eth.config.logger.Info("sending submitHead tx....")
				err = SendTxToEthereum(eth, w3q).Doing(signedTx)
				if err != nil {
					// todo if the error is "head exist" ,
					eth.config.logger.Warn("SendTxToEthereum fail", "err", err)
					retryTimes--
					return
				}

			}
		}
	}
}

func (eth *ChainOperator) generateSubmitHeadTx(contractAddr common.Address, height *big.Int, headBytes []byte, commitBytes []byte, lookByIndex bool) (*types.Transaction, error) {
	return eth.callContractMethodForce("submitHeader", contractAddr, 0, height, headBytes, commitBytes, lookByIndex)
}

func (eth *ChainOperator) generateMintW3qErc20Tx(contractAddr common.Address, height uint64, proof Proof, logIdx uint64) (*types.Transaction, error) {
	return eth.callContractMethodForce("mintToBridge", contractAddr, 0, big.NewInt(0).SetUint64(height), proof, big.NewInt(0).SetUint64(logIdx))
}

func (c *ChainOperator) generateMintNativeTx(to common.Address, txHash common.Hash, logIdx int64) (*types.Transaction, error) {
	return c.callContractMethod("mintNative", to, 0, txHash, big.NewInt(logIdx))
}

func SendTx_MintNative(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator, ethTxHappened uint64) *CrossChainCallTask {
	return NewCrossChainCallTask(w3qChainOperator.Ctx, ethChainOperator, w3qChainOperator, true, make(chan struct{}), ethChainOperator.waitingExpectHeight, ethTxHappened+10)
}

func SendTxToEthereum(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator) *CrossChainCallTask {
	return NewCrossChainCallTask(ethChainOperator.Ctx, w3qChainOperator, ethChainOperator, false, nil, nil, 0)
}

func SendTxToWeb3q(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator) *CrossChainCallTask {
	return NewCrossChainCallTask(ethChainOperator.Ctx, ethChainOperator, w3qChainOperator, false, nil, nil, 0)
}

type Task interface {
	Doing(transaction *types.Transaction, height uint64) error
}
