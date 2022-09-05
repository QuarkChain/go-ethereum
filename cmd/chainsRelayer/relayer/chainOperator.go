package relayer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/config"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/log"
	"io/ioutil"
	"math/big"
	"os"
	"sync"
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

func NewRelayer(chainConfig config.ChainConfig) (*Relayer, error) {
	b, err := ioutil.ReadFile(chainConfig.KeyStoreFilePath)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(b, chainConfig.Passwd)
	if err != nil {
		return nil, err
	}
	return &Relayer{address: key.Address, filepath: chainConfig.KeyStoreFilePath, prikey: key.PrivateKey}, nil
}

func NewRelayerByFilePath(filepath string) (*Relayer, error) {
	key, err := utils.LoadPriKey(filepath)
	if err != nil {
		return nil, err
	}
	return &Relayer{filepath: filepath, prikey: key}, nil
}

func (r *Relayer) Address() common.Address {
	return r.address
}

func SetLog(conf config.TomlConfig) log.Logger {
	var gh *log.GlogHandler
	if conf.Log.LogFile != "" {
		file, err := os.Open(conf.Log.LogFile)
		if err != nil {
			panic(err)
		}
		gh = log.NewGlogHandler(log.StreamHandler(file, log.TerminalFormat(true)))
	} else {
		gh = log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(true)))
	}
	gh.Verbosity(log.Lvl(conf.Log.LogLevel))
	log.Root().SetHandler(gh)
	return log.Root()
}

func NewChainConfig(httpUrl string, wsUrl string, logLevel int, dbf string) *ChainConfig {
	return &ChainConfig{logger: log.Root(), httpUrl: httpUrl, wsUrl: wsUrl, dbFile: dbf}
}

type ChainOperator struct {
	config  config.ChainConfig
	relayer *Relayer

	// The listener initialized through ws_rpc_url monitors the contract events that are happening
	Listener *ethclient.Client
	// The Executor initialized through http_rpc_url sends a transaction to the blockchain
	Executor *ethclient.Client

	contracts map[common.Address]*Contract

	Ctx        context.Context
	CancelFunc context.CancelFunc

	ListenTaskList []ListenTask

	submitTxPool *submitTxPool

	errChan chan error

	db *leveldb.Database
}

func NewChainOperator(config config.ChainConfig, r *Relayer, pctx context.Context) (*ChainOperator, error) {
	listener, err := ethclient.Dial(config.WsUrl)
	if err != nil {
		log.Error("ethclient.Dial failed:", "err", err)
		return nil, err
	}

	executor, err := ethclient.Dial(config.RpcUrl)
	if err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithCancel(pctx)

	chainId, err := executor.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	config.SetChainId(chainId)

	database, err := leveldb.New(config.DbFile, 256, 0, "ChainId_"+big.NewInt(config.ChainId()).String(), false)
	if err != nil {
		return nil, err
	}

	pool := newSubmitTxPool(config, r, executor, ctx)

	return &ChainOperator{config: config, relayer: r, Listener: listener, Executor: executor, Ctx: ctx, CancelFunc: cancelFunc, db: database, submitTxPool: pool}, nil
}

func (this *ChainOperator) SendTxArg(arg *txArg) {
	this.submitTxPool.sendTxArg(arg)
}

func (this *ChainOperator) name() string {
	return "ChainOperator"
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

func (co *ChainOperator) getFilterByEventName(contractAddr common.Address, eventName string) ethereum.FilterQuery {
	return ethereum.FilterQuery{Addresses: []common.Address{contractAddr}, Topics: [][]common.Hash{{co.contracts[contractAddr].ContractAbi.Events[eventName].ID}}}
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

	// set the handleFunc if it is not empty
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

func (co *ChainOperator) StartSubmitting() {
	co.submitTxPool.running()
}

func (co *ChainOperator) generateTxArgForContractMethod(methodName string, to common.Address, value int64, args ...interface{}) (*txArg, error) {
	abi, exist := co.contracts[to]
	if !exist {
		return nil, fmt.Errorf("the address has not registered")
	}

	input, err := abi.ContractAbi.Pack(methodName, args...)
	if err != nil {
		return nil, err
	}

	return newTxArg(to, input, value), nil
}

type Task interface {
	Doing(transaction *types.Transaction, height uint64) error
}
