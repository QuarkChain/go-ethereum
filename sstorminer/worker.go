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

package sstorminer

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	sstor "github.com/ethereum/go-ethereum/sstorage"
)

const (
	ABI      = "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"startShardId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"shardLenBits\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"miner\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"minedTs\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"nonce\",\"type\":\"uint256\"},{\"internalType\":\"bytes32[][]\",\"name\":\"proofsDim2\",\"type\":\"bytes32[][]\"},{\"internalType\":\"bytes[]\",\"name\":\"maskedData\",\"type\":\"bytes[]\"}],\"name\":\"mine\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	MineFunc = "mine"
	gas      = uint64(5000000)
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// minRecommitInterval is the minimal time interval to recreate the sealing block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	mineTimeOut = uint64(10)

	transactionOutdatedTime = 120 // Second
)

var (
	maxUint256 = new(big.Int).Sub(new(big.Int).Exp(new(big.Int).SetUint64(2),
		new(big.Int).SetUint64(256), nil), new(big.Int).SetUint64(1))
	vABI, _ = abi.JSON(strings.NewReader(ABI))
)

const (
	TaskStateNoStart = iota
	TaskStateMining
	TaskStateMined
)

type BlockChain interface {
	CurrentBlock() *types.Block

	InsertChain(chain types.Blocks) (int, error)

	GetSstorageMiningInfo(root common.Hash, contract common.Address, shardId uint64) (*core.MiningInfo, error)

	ReadKVsByIndexList(contract common.Address, indexes []uint64, useMaxKVsize bool) ([]*core.KV, error)

	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription

	GetSstorageLastKvIdx(contract common.Address) (uint64, error)

	State() (*state.StateDB, error)
}

type SignTxFn func(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

type TXSigner struct {
	Account accounts.Account // Ethereum address of the signing key
	SignFn  SignTxFn         // Signer function to sign tx
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	worker          *worker
	result          *result
	storageContract common.Address
	minerContract   common.Address
	shardIdx        uint64
	kvSizeBits      uint64
	chunkSizeBits   uint64
	kvEntriesBits   uint64
	miner           common.Address
	running         int32
	info            *core.MiningInfo
	shardManager    *sstor.ShardManager
	startMiningTime uint64
	state           uint64
	mu              sync.RWMutex // The lock used to protect the state
}

func expectedDiff(lastMineTime uint64, difficulty *big.Int, minedTime uint64, cutoff, diffAdjDivisor, minDiff *big.Int) *big.Int {
	interval := new(big.Int).SetUint64(minedTime - lastMineTime)
	diff := difficulty
	if interval.Cmp(cutoff) < 0 {
		// diff = diff + (diff-interval*diff/cutoff)/diffAdjDivisor
		diff = new(big.Int).Add(diff, new(big.Int).Div(
			new(big.Int).Sub(diff, new(big.Int).Div(new(big.Int).Mul(interval, diff), cutoff)), diffAdjDivisor))
		if diff.Cmp(minDiff) < 0 {
			diff = minDiff
		}
	} else {
		// dec := (interval*diff/cutoff - diff) / diffAdjDivisor
		dec := new(big.Int).Div(new(big.Int).Sub(new(big.Int).Div(new(big.Int).Mul(interval, diff), cutoff), diff), diffAdjDivisor)
		if new(big.Int).Add(dec, minDiff).Cmp(diff) > 0 {
			diff = minDiff
		} else {
			diff = new(big.Int).Sub(diff, dec)
		}
	}

	return diff
}

func (t *task) expectedDiff(minedTime uint64) *big.Int {
	return expectedDiff(t.info.LastMineTime, t.info.Difficulty, minedTime,
		t.worker.config.Cutoff, t.worker.config.DiffAdjDivisor, t.worker.config.MinimumDiff)
}

func (t *task) getState() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *task) setState(state uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
}

// start sets the running status as 1 and triggers new work submitting.
func (t *task) start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	atomic.StoreInt32(&t.running, 1)
}

// stop sets the running status as 0.
func (t *task) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	atomic.StoreInt32(&t.running, 0)
}

// isRunning returns an indicator whether worker is running or not.
func (t *task) isRunning() bool {
	return atomic.LoadInt32(&t.running) == 1
}

type tasks []*task

func (t tasks) Len() int { return len(t) }
func (t tasks) Less(i, j int) bool {
	minedTs := uint64(time.Now().Unix())
	return t[i].expectedDiff(minedTs).Cmp(t[j].expectedDiff(minedTs)) < 0
}
func (t tasks) Swap(i, j int) { t[i], t[j] = t[j], t[i] }

type result struct {
	task         *task
	startShardId uint64
	shardLenBits uint64
	miner        common.Address
	minedTs      uint64
	nonce        uint64
	kvIdxs       []uint64
	chunkIdxs    []uint64
	encodedData  [][]byte
	proofs       [][]common.Hash
	submitTxHash common.Hash
	submitTxTime int64
}

type txSorter struct {
	txs     []*types.Transaction
	baseFee *big.Int
}

func newSorter(txs []*types.Transaction, baseFee *big.Int) *txSorter {
	return &txSorter{
		txs:     txs,
		baseFee: baseFee,
	}
}

func (s *txSorter) Len() int { return len(s.txs) }
func (s *txSorter) Swap(i, j int) {
	s.txs[i], s.txs[j] = s.txs[j], s.txs[i]
}
func (s *txSorter) Less(i, j int) bool {
	// It's okay to discard the error because a tx would never be
	// accepted into a block with an invalid effective tip.
	tip1, _ := s.txs[i].EffectiveGasTip(s.baseFee)
	tip2, _ := s.txs[j].EffectiveGasTip(s.baseFee)
	return tip1.Cmp(tip2) < 0
}

type priceOracle struct {
	chainConfig   *params.ChainConfig
	baseFee       *big.Int
	suggestGasTip *big.Int
	blockNumber   uint64
	ignoreUnder   *big.Int
	limit         int
}

// The TipGap provided in the SuggestGasTipCap method (provided by EthAPIBackend) will extract the smallest 3 TipGaps
// from each of the latest n blocks, sort them, and take the median according to the set percentile.
//
// To make it simple, if the transaction volume is small, suggestGasTip set to 0, otherwise the third smallest GasTip
// in the latest block is used.
//
// updatePriceOracle update suggestGasTip according to block.
func (o *priceOracle) updatePriceOracle(block *types.Block) {
	if block.NumberU64() < o.blockNumber {
		return
	}
	// if block GasUsed smaller than GasLimit / 2, only baseFee is needed,
	// so suggestGasTip can be set to 0.
	if block.GasUsed() < block.GasLimit()/2 {
		o.suggestGasTip = new(big.Int).SetUint64(0)
		return
	}

	// otherwise, the third smallest GasTip is used.
	signer := types.MakeSigner(o.chainConfig, block.Number())
	sorter := newSorter(block.Transactions(), block.BaseFee())
	sort.Sort(sorter)

	var prices []*big.Int
	for _, tx := range sorter.txs {
		tip, _ := tx.EffectiveGasTip(block.BaseFee())
		if o.ignoreUnder != nil && tip.Cmp(o.ignoreUnder) == -1 {
			continue
		}
		sender, err := types.Sender(signer, tx)
		if err == nil && sender != block.Coinbase() {
			prices = append(prices, tip)
			if len(prices) >= o.limit {
				break
			}
		}
	}
	if len(prices) > 0 {
		o.suggestGasTip = prices[len(prices)-1]
	}
}

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	timestamp int64
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	eth         Backend
	apiBackend  apiBackend
	chain       BlockChain
	priceOracle *priceOracle

	// Subscriptions
	mux          *event.TypeMux
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	client       *ethclient.Client
	signer       *TXSigner

	// Channels
	newWorkCh          chan *newWorkReq
	taskCh             chan *task
	resultCh           chan *result
	startCh            chan struct{}
	taskStartCh        chan struct{}
	resultSubmitFailCh chan struct{}
	exitCh             chan struct{}
	taskDoneCh         chan struct{}
	resubmitIntervalCh chan time.Duration

	wg sync.WaitGroup
	mu sync.RWMutex // The lock used to protect the coinbase and extra fields

	tasks   tasks
	running int32

	newTaskHook   func(*task)
	newResultHook func(*result)
}

func newWorker(config *Config, chainConfig *params.ChainConfig, eth Backend, api apiBackend, chain BlockChain,
	mux *event.TypeMux, txSigner *TXSigner, minerContract common.Address, init bool) *worker {
	worker := &worker{
		config:             config,
		chainConfig:        chainConfig,
		eth:                eth,
		apiBackend:         api,
		mux:                mux,
		chain:              chain,
		tasks:              make([]*task, 0),
		chainHeadCh:        make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:          make(chan *newWorkReq),
		taskCh:             make(chan *task),
		resultCh:           make(chan *result, resultQueueSize),
		exitCh:             make(chan struct{}),
		startCh:            make(chan struct{}, 1),
		resubmitIntervalCh: make(chan time.Duration),
		taskDoneCh:         make(chan struct{}),
		taskStartCh:        make(chan struct{}),
		resultSubmitFailCh: make(chan struct{}),
		signer:             txSigner,
	}
	for addr, sm := range sstor.ContractToShardManager {
		for idx, shard := range sm.ShardMap() {
			task := task{
				worker:          worker,
				storageContract: addr,
				minerContract:   minerContract,
				shardIdx:        idx,
				kvSizeBits:      sm.MaxKvSizeBits(),
				chunkSizeBits:   sm.ChunksPerKvBits(),
				kvEntriesBits:   sm.KvEntriesBits(),
				miner:           shard.Miner(),
				shardManager:    sm,
				running:         1,
				info:            nil,
			}
			worker.tasks = append(worker.tasks, &task)
		}
	}

	curBlock := eth.BlockChain().CurrentBlock()
	worker.priceOracle = &priceOracle{
		chainConfig: chainConfig,
		baseFee:     curBlock.BaseFee(),
		blockNumber: curBlock.NumberU64(),
		ignoreUnder: new(big.Int).SetUint64(2 * params.GWei),
		limit:       3,
	}
	worker.priceOracle.updatePriceOracle(curBlock)

	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}

	worker.wg.Add(4)
	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop() // can change to multi threads to run task

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}
	return worker
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	select {
	case w.resubmitIntervalCh <- interval:
	case <-w.exitCh:
	}
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	atomic.StoreInt32(&w.running, 1)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	atomic.StoreInt32(&w.running, 0)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// start sets the running status as 1 for a task and triggers task start chan.
func (w *worker) startTask(contract common.Address, shardIdx uint64) {
	for _, task := range w.tasks {
		if task.storageContract == contract && task.shardIdx == shardIdx && !task.isRunning() {
			task.start()
			w.taskStartCh <- struct{}{}
		}
	}
}

// stop sets the running status as 0 for a task.
func (w *worker) stopTask(contract common.Address, shardIdx uint64) {
	for _, task := range w.tasks {
		if task.storageContract == contract && task.shardIdx == shardIdx && task.isRunning() {
			task.stop()
		}
	}
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	atomic.StoreInt32(&w.running, 0)
	close(w.exitCh)
	w.wg.Wait()
}

// newWorkLoop is a standalone goroutine to submit new sealing work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	defer w.wg.Done()
	var (
		minRecommit = recommit // minimal resubmit interval specified by user.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	for {
		select {
		case <-w.startCh:
			w.updateTaskInfo(w.chain.CurrentBlock().Root(), time.Now().Unix())
			timer.Reset(recommit)

		case head := <-w.chainHeadCh:
			w.updateTaskInfo(head.Block.Root(), time.Now().Unix())
			timer.Reset(recommit)

		case <-timer.C:
			// If sealing is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() {
				timer.Reset(recommit)
				w.updateTaskInfo(w.chain.CurrentBlock().Root(), time.Now().Unix())
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			recommit = interval

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is responsible for generating and submitting sealing work based on
// the received event. It can support two modes: automatically generate task and
// submit it or return task according to given parameters for various proposes.
func (w *worker) mainLoop() {
	defer w.wg.Done()
	defer w.chainHeadSub.Unsubscribe()

	var stopCh chan struct{}
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}

	for {
		select {
		case <-w.newWorkCh:
			interrupt()
			stopCh = make(chan struct{})
			w.commitWork(stopCh)

		case <-w.taskDoneCh:
			interrupt()
			stopCh = make(chan struct{})
			w.commitWork(stopCh)

		case <-w.taskStartCh:
			interrupt()
			stopCh = make(chan struct{})
			w.commitWork(stopCh)

		case <-w.resultSubmitFailCh:
			interrupt()
			stopCh = make(chan struct{})
			w.commitWork(stopCh)

		case <-w.exitCh:
			return
		case <-w.chainHeadSub.Err():
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	defer w.wg.Done()

	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			_, err := w.mineTask(task)
			if err != nil {
				log.Warn("mine task fail", "err", err.Error())
			}
			w.taskDoneCh <- struct{}{}

		case <-w.exitCh:
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	defer w.wg.Done()
	for {
		select {
		case result := <-w.resultCh:
			if w.newResultHook != nil {
				w.newResultHook(result)
			}

			// todo refer to the current layer 2 to process submissions
			err := w.submitMinedResult(result)
			if err != nil {
				result.task.setState(TaskStateNoStart)
				w.resultSubmitFailCh <- struct{}{}
				log.Warn("w.submitMinedResult", "MiningHash", result.task.info.MiningHash.Hex(),
					"LastMineTime", result.task.info.LastMineTime, "miner", result.miner, "error", err.Error())
			}

		case <-w.exitCh:
			return
		}
	}
}

func (w *worker) isTransactionOutdated(txHash common.Hash, submitTxTime int64) bool {
	tx := w.apiBackend.GetPoolTransaction(txHash)
	if tx != nil && submitTxTime+transactionOutdatedTime < time.Now().Unix() {
		return false
	}
	return true
}

// updateTaskInfo aborts in-flight transaction execution with given signal and resubmits a new one.
func (w *worker) updateTaskInfo(root common.Hash, timestamp int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isRunning() {
		return
	}
	updated := false
	for _, t := range w.tasks {
		info, err := w.chain.GetSstorageMiningInfo(root, t.minerContract, t.shardIdx)
		if err != nil {
			log.Warn("failed to get sstorage mining info", "error", err.Error())
			continue
		}
		if t.info == nil || !info.Equal(t.info) {
			t.info = info
			t.result = nil
			t.setState(TaskStateNoStart)
			updated = true
			log.Info("update t info", "shard idx", t.shardIdx, "MiningHash", info.MiningHash.Hex(),
				"LastMineTime", t.info.LastMineTime, "Difficulty", info.Difficulty, "BlockMined", info.BlockMined)
			continue
		}
		if t.result != nil && t.result.submitTxTime != 0 { // result has been submitted
			ctx := context.Background()
			receipts, _ := w.apiBackend.GetReceipts(ctx, t.result.submitTxHash)
			if receipts != nil && receipts[0].Status == types.ReceiptStatusSuccessful {
				// tx has been exec and success, this should not happen, it should be covered by info update.
				continue
			} else if receipts == nil {
				// if tx in pool less than 120 seconds, then wait for tx to exec, otherwise re-mine task
				isOutdated := w.isTransactionOutdated(t.result.submitTxHash, t.result.submitTxTime)
				if !isOutdated {
					continue
				}
				log.Warn("need Wait Transaction To Execute", "tx hash", t.result.submitTxHash.Hex())
			}

			t.result = nil
			t.setState(TaskStateNoStart)
			updated = true
		}
	}

	if updated {
		select {
		case w.newWorkCh <- &newWorkReq{timestamp: timestamp}:
		case <-w.exitCh:
			return
		}
	}
}

// commitWork generates several new sealing tasks based on the parent block
// and submit them to the sealer.
func (w *worker) commitWork(stopCh chan struct{}) {
	if !w.isRunning() {
		return
	}
	// sort and find the task with smallest diff to mine
	sort.Sort(w.tasks)
	go func() {
		for _, t := range w.tasks {
			if t.isRunning() && t.getState() < TaskStateMined {
				select {
				case w.taskCh <- t:
					log.Info("add task", "shard idx", t.shardIdx)
				case <-w.exitCh:
					log.Info("Worker has exited")
				case <-stopCh:
					log.Info("cancel commitWork")
				}
				break
			}
		}
	}()
}

func (w *worker) calculateDiffAndInitHash(t *task, shardLen, minedTs uint64) (diff *big.Int, diffs []*big.Int, hash0 common.Hash, err error) {
	diffs = make([]*big.Int, shardLen)
	diff = new(big.Int).SetUint64(0)
	hash0 = common.Hash{}
	for i := uint64(0); i < shardLen; i++ {
		shardId := t.shardIdx + i
		if minedTs < t.info.LastMineTime {
			err = fmt.Errorf("minedTs too small")
		}
		diffs[i] = t.expectedDiff(minedTs)
		diff = new(big.Int).Add(diff, diffs[i])
		hash0 = crypto.Keccak256Hash(hash0.Bytes(), uint64ToByte32(shardId), t.info.MiningHash.Bytes())
	}

	return diff, diffs, hash0, nil
}

func (w *worker) verifyResult(r *result) error {
	var (
		shardLenBits uint64 = 0
	)
	diff, _, hash0, err := w.calculateDiffAndInitHash(r.task, uint64(1)<<shardLenBits, r.minedTs)
	if err != nil {
		return err
	}
	hash0 = crypto.Keccak256Hash(hash0.Bytes(), addressToByte32(r.miner), uint64ToByte32(r.minedTs), uint64ToByte32(r.nonce))
	hash0, err = w.hashimotoMerkleProof(r.task, hash0, r.miner, r.proofs, r.encodedData, r.kvIdxs, r.chunkIdxs)
	if err != nil {
		return err
	}
	requiredDiff := new(big.Int).Div(maxUint256, diff)
	if requiredDiff.Cmp(new(big.Int).SetBytes(hash0.Bytes())) < 0 {
		return fmt.Errorf("diff not match")
	}

	return nil
}

func (w *worker) hashimotoMerkleProof(t *task, hash0 common.Hash, miner common.Address,
	proofsDim2 [][]common.Hash, maskedData [][]byte, kvIdxes []uint64, chunkIdxes []uint64) (common.Hash, error) {
	if len(proofsDim2) != w.config.RandomChecks {
		return common.Hash{}, fmt.Errorf("data vs checks: length mismatch")
	}
	if len(maskedData) != w.config.RandomChecks {
		return common.Hash{}, fmt.Errorf("proofs vs checks: length mismatch")
	}
	stateDB, err := w.chain.State()
	if err != nil {
		return common.Hash{}, err
	}
	rowBits := t.kvEntriesBits + t.chunkSizeBits
	for i := 0; i < w.config.RandomChecks; i++ {
		if uint64(len(maskedData[i])) != sstor.CHUNK_SIZE {
			return common.Hash{}, fmt.Errorf("invalid proof size")
		}
		chunkIdx := new(big.Int).SetBytes(hash0.Bytes()).Uint64()%(uint64(1)<<rowBits) + t.shardIdx<<(t.kvEntriesBits+t.chunkSizeBits)
		kvIdx := chunkIdx >> t.chunkSizeBits
		cIdx := chunkIdx % (1 << t.chunkSizeBits)
		if kvIdx != kvIdxes[i] || cIdx != chunkIdxes[i] {
			return common.Hash{}, fmt.Errorf("kv idx %d vs %d, chunk idx %d vs %d", kvIdx, kvIdxes[i], cIdx, chunkIdxes[i])
		}
		meta, kvInfo, _ := core.GetSstorageMetadata(stateDB, t.storageContract, kvIdx)
		if bytes.Compare(meta.Bytes(), make([]byte, 32)) == 0 {
			kvInfo = &core.SstorageMetadata{kvIdx, 0, make([]byte, 24)}
		}

		unmaskedData, err := unmaskData(maskedData[i], common.BytesToHash(kvInfo.HashInMeta), chunkIdx, miner)
		if err != nil {
			return common.Hash{}, err
		}
		hash := common.Hash{}
		lastKvIdx, err := w.chain.GetSstorageLastKvIdx(t.storageContract)
		if err != nil {
			return common.Hash{}, err
		}
		if lastKvIdx > kvIdxes[i] {
			off := sstor.CHUNK_SIZE * chunkIdxes[i]

			if kvInfo.KVSize > off {
				if kvInfo.KVSize < off+sstor.CHUNK_SIZE {
					unmaskedData = unmaskedData[:kvInfo.KVSize-off]
				}
				hash = crypto.Keccak256Hash(unmaskedData)
			}
		}
		verifyWithMinTree(kvInfo.HashInMeta, hash, chunkIdxes[i], proofsDim2[i])

		hash0 = crypto.Keccak256Hash(hash0.Bytes(), maskedData[i])
	}
	return hash0, nil
}

func verifyWithMinTree(root []byte, dataHash common.Hash, chunkIdx uint64, proofs []common.Hash) bool {
	nMinChunkBits := uint64(len(proofs))
	if chunkIdx >= uint64(1)<<nMinChunkBits {
		return bytes.Compare(dataHash.Bytes(), make([]byte, 32)) == 0
	}
	r, err := sstor.CalculateRootWithProof(dataHash, chunkIdx, proofs)
	if err != nil {
		return false
	}

	return bytes.Compare(root[:24], r.Bytes()[:24]) == 0
}

func unmaskData(maskedChunkData []byte, kvHash common.Hash, chunkIdx uint64, miner common.Address) ([]byte, error) {
	if uint64(len(maskedChunkData)) != sstor.CHUNK_SIZE {
		return nil, fmt.Errorf("the length of maskedChunk no equals to CHUNK_SIZE")
	}

	// get encoded key and decode masked chunk
	encodeKey := sstor.CalcEncodeKey(kvHash, chunkIdx, miner)
	unmaskedChunk := sstor.DecodeChunk(maskedChunkData, 2, encodeKey)
	if bytes.Compare(unmaskedChunk[:20], make([]byte, 20)) != 0 {
		log.Warn("worker unmaskData returns", "chunkIdx", chunkIdx, "kvHash", kvHash, "miner", miner,
			"datalen", len(maskedChunkData), "masked chunk data", maskedChunkData[:20], "unmasked chunk data", unmaskedChunk[:20])
	}
	return unmaskedChunk, nil
}

func (w *worker) hashimoto(t *task, shardLenBits uint64, hash0 common.Hash) (common.Hash, [][]byte, []uint64, []uint64, error) {
	dataSet := make([][]byte, w.config.RandomChecks)
	kvIdxs, chunkIdxs := make([]uint64, w.config.RandomChecks), make([]uint64, w.config.RandomChecks)
	rowBits := t.kvEntriesBits + t.chunkSizeBits + shardLenBits
	for i := 0; i < w.config.RandomChecks; i++ {
		chunkIdx := new(big.Int).SetBytes(hash0.Bytes()).Uint64()%(uint64(1)<<rowBits) + t.shardIdx<<(t.kvEntriesBits+t.chunkSizeBits)
		data, exist, err := t.shardManager.TryReadChunkEncoded(chunkIdx)
		if exist && err == nil {
			dataSet[i] = data
			kvIdxs[i] = chunkIdx >> t.chunkSizeBits
			chunkIdxs[i] = chunkIdx % (1 << t.chunkSizeBits)
			hash0 = crypto.Keccak256Hash(hash0.Bytes(), data)
		} else {
			if !exist {
				err = fmt.Errorf("chunk not support: chunkIdxs %d", chunkIdx)
			}
			return hash0, dataSet, kvIdxs, chunkIdxs, err
		}
	}

	return hash0, dataSet, kvIdxs, chunkIdxs, nil
}

func (w *worker) mineTask(t *task) (bool, error) {
	if t.getState() == TaskStateMined {
		return true, nil
	}
	minedTs := uint64(time.Now().Unix())
	// using random nonce, so we can run multi mine with threads
	rand.Seed(int64(minedTs))
	nonce := rand.Uint64() % 1000000
	var (
		dataSet      [][]byte
		kvIdxs       []uint64
		chunkIdxs    []uint64
		shardLenBits uint64 = 0
	)

	// todo shard len can be not 1 later
	diff, _, hash0, err := w.calculateDiffAndInitHash(t, uint64(1)<<shardLenBits, minedTs)
	log.Warn("calculateDiffAndInitHash", "diff", diff, "hash0", hash0.Hex(), "minedTs", minedTs,
		"MiningHash", t.info.MiningHash, "LastMineTime", t.info.LastMineTime)
	if err != nil {
		return false, err
	}

	requiredDiff := new(big.Int).Div(maxUint256, diff)
	t.setState(TaskStateMining)

	// if the worker has stoped or task has been stoped or task state has change to
	// TaskStateNoStart (mean miningInfo has been change, so the diff need to )
	for w.isRunning() && t.isRunning() && t.getState() == uint64(TaskStateMining) && minedTs+mineTimeOut > uint64(time.Now().Unix()) {
		hash1 := crypto.Keccak256Hash(hash0.Bytes(), addressToByte32(t.miner), uint64ToByte32(minedTs), uint64ToByte32(nonce))
		hash1, dataSet, kvIdxs, chunkIdxs, err = w.hashimoto(t, shardLenBits, hash1)

		if requiredDiff.Cmp(new(big.Int).SetBytes(hash1.Bytes())) >= 0 {
			log.Warn("calculate a valid hash", "random check kvIdxs", kvIdxs, "random check chunkIdxs",
				chunkIdxs, "diff", diff, "hash1", hash1.Hex(), "minedTs", minedTs, "MiningHash", t.info.MiningHash,
				"LastMineTime", t.info.LastMineTime, "nonce", nonce, "miner", t.miner.Hex())
			proofs := make([][]common.Hash, len(kvIdxs))
			kvs, err := w.chain.ReadKVsByIndexList(t.storageContract, kvIdxs, true)
			if err != nil {
				return false, err
			}
			if len(kvs) != len(kvIdxs) {
				return false, fmt.Errorf("fail to get all the kvs %v", kvIdxs)
			}

			for i := 0; i < len(dataSet); i++ {
				if kvs[i].Idx == kvIdxs[i] {
					ps, err := sstor.GetProofWithMinTree(kvs[i].Data, t.chunkSizeBits, chunkIdxs[i])
					if err != nil {
						return false, err
					}
					proofs[i] = ps
				}
			}
			t.setState(TaskStateMined)
			r := &result{
				task:         t,
				startShardId: t.shardIdx,
				shardLenBits: 0,
				miner:        t.miner,
				minedTs:      minedTs,
				nonce:        nonce,
				kvIdxs:       kvIdxs,
				chunkIdxs:    chunkIdxs,
				encodedData:  dataSet,
				proofs:       proofs,
				submitTxTime: 0,
			}
			if err := w.verifyResult(r); err != nil {
				log.Warn("Got result but verify result fail", "err", err.Error())
				return false, err
			}
			if t.result == nil || t.result.submitTxTime+transactionOutdatedTime > time.Now().Unix() {
				t.result = r
				w.resultCh <- r
			}

			return true, nil
		}
		nonce++
	}

	return false, nil
}

func (w *worker) submitMinedResult(result *result) error {
	ctx := context.Background()
	data, err := vABI.Pack(MineFunc, new(big.Int).SetUint64(result.task.shardIdx), new(big.Int).SetUint64(0), result.task.miner,
		new(big.Int).SetUint64(result.minedTs), new(big.Int).SetUint64(result.nonce), result.proofs, result.encodedData)
	if err != nil {
		return err
	}

	nonce, _ := w.apiBackend.GetPoolNonce(ctx, w.signer.Account.Address)
	gasPrice, err := w.apiBackend.SuggestGasTipCap(ctx)
	gasPrice = new(big.Int).Add(gasPrice, w.chain.CurrentBlock().BaseFee())
	if err != nil {
		return err
	}

	baseTx := &types.LegacyTx{
		To:       &result.task.minerContract,
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		Value:    new(big.Int).SetInt64(0),
		Data:     data,
	}

	signedTx, err := w.signer.SignFn(w.signer.Account, types.NewTx(baseTx), w.chainConfig.ChainID)
	if err != nil {
		log.Warn("worker::submitMinedResult() >>>>>> sign tx error <<<<<<", "err", err)
		return err
	}

	err = w.apiBackend.SendTx(ctx, signedTx)
	if err != nil {
		return fmt.Errorf("SendTransaction hash %s, ERROR %s ", signedTx.Hash().Hex(), err.Error())
	}
	result.submitTxTime = time.Now().Unix()
	result.submitTxHash = signedTx.Hash()
	log.Warn("Submit mining tx", "hash", signedTx.Hash().Hex())
	return nil
}

func uint64ToByte32(u uint64) []byte {
	return common.BigToHash(new(big.Int).SetUint64(u)).Bytes()
}

func addressToByte32(addr common.Address) []byte {
	return common.BytesToHash(addr.Bytes()).Bytes()
}
