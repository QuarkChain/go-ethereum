// Copyright 2018 The go-ethereum Authors
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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/sstorage"
	"github.com/holiman/uint256"
)

const (
	// testCode is the testing contract binary code which will initialises some
	// variables in constructor
	testCode = "0x60806040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0060005534801561003457600080fd5b5060fc806100436000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80630c4dae8814603757806398a213cf146053575b600080fd5b603d607e565b6040518082815260200191505060405180910390f35b607c60048036036020811015606757600080fd5b81019080803590602001909291905050506084565b005b60005481565b806000819055507fe9e44f9f7da8c559de847a3232b57364adc0354f15a2cd8dc636d54396f9587a6000546040518082815260200191505060405180910390a15056fea265627a7a723058208ae31d9424f2d0bc2a3da1a5dd659db2d71ec322a17db8f87e19e209e3a1ff4a64736f6c634300050a0032"

	// testGas is the gas required for contract deployment.
	testGas = 144109
)

var (
	// Test chain configurations
	testTxPoolConfig  core.TxPoolConfig
	ethashChainConfig *params.ChainConfig

	// Test accounts
	testBankKey, _  = crypto.GenerateKey()
	testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
	testBankFunds   = big.NewInt(1000000000000000000)

	testUserKey, _  = crypto.GenerateKey()
	testUserAddress = crypto.PubkeyToAddress(testUserKey.PublicKey)

	// Test transactions
	pendingTxs []*types.Transaction
	newTxs     []*types.Transaction

	minerContract = common.HexToAddress("0x0000000000000000000000000000000000000001")
	contract      = common.HexToAddress("0x0000000000000000000000000000000003330001")
	kvEntriesBits = uint64(9)
	kvEntries     = uint64(1) << 9
	blocks        = 5

	defaultConfig = &Config{
		RandomChecks:      16,
		MinimumDiff:       new(big.Int).SetUint64(1),
		TargetIntervalSec: new(big.Int).SetUint64(3),
		Cutoff:            new(big.Int).SetUint64(40),
		DiffAdjDivisor:    new(big.Int).SetUint64(1024),
		Recommit:          1 * time.Second,
	}

	diff       = new(big.Int).SetUint64(1024)
	blockMined = new(big.Int).SetUint64(1)
)

func init() {
	testTxPoolConfig = core.DefaultTxPoolConfig
	testTxPoolConfig.Journal = ""
	ethashChainConfig = new(params.ChainConfig)
	*ethashChainConfig = *params.TestChainConfig

	signer := types.LatestSigner(params.TestChainConfig)
	tx1 := types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
		ChainID:  params.TestChainConfig.ChainID,
		Nonce:    0,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	pendingTxs = append(pendingTxs, tx1)

	tx2 := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    1,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	newTxs = append(newTxs, tx2)

	rand.Seed(time.Now().UnixNano())
}

type wrapBlockChain struct {
	*core.BlockChain
	stateDB *state.StateDB
}

func (bc *wrapBlockChain) GetSstorageMiningInfo(root common.Hash, contract common.Address, shardId uint64) (*core.MiningInfo, error) {
	return bc.GetSstorageMiningInfoWithStateDB(bc.stateDB, contract, shardId)
}

func (bc *wrapBlockChain) State() (*state.StateDB, error) {
	return bc.stateDB, nil
}

func (bc *wrapBlockChain) ReadKVsByIndexList(contract common.Address, indexes []uint64, useMaxKVsize bool) ([]*core.KV, error) {
	return bc.BlockChain.ReadKVsByIndexListWithState(bc.stateDB, contract, indexes, useMaxKVsize)
}

func hashAdd(hash common.Hash, i uint64) common.Hash {
	return common.BytesToHash(new(big.Int).Add(hash.Big(), new(big.Int).SetUint64(i)).Bytes())
}

func (bc *wrapBlockChain) saveMiningInfo(shardId uint64, info *core.MiningInfo) {
	position := getSlotHash(3, uint256.NewInt(shardId).Bytes32())
	bc.stateDB.SetState(minerContract, position, info.MiningHash)
	bc.stateDB.SetState(minerContract, hashAdd(position, 1), common.BigToHash(new(big.Int).SetUint64(info.LastMineTime)))
	bc.stateDB.SetState(minerContract, hashAdd(position, 2), common.BigToHash(info.Difficulty))
	bc.stateDB.SetState(minerContract, hashAdd(position, 3), common.BigToHash(info.BlockMined))
}

func (bc *wrapBlockChain) initMiningInfos(shardIdxList []uint64, diff *big.Int, blockMined *big.Int) map[uint64]*core.MiningInfo {
	infos := make(map[uint64]*core.MiningInfo)
	for _, idx := range shardIdxList {
		info := new(core.MiningInfo)
		info.MiningHash = crypto.Keccak256Hash()
		info.LastMineTime = uint64(time.Now().Unix())
		info.Difficulty = diff
		info.BlockMined = blockMined
		bc.saveMiningInfo(idx, info)
		infos[idx] = info
	}
	return infos
}

// testWorkerBackend implements worker.Backend interfaces and wraps all information needed during the testing.
type testWorkerBackend struct {
	db          ethdb.Database
	txPool      *core.TxPool
	chain       *core.BlockChain
	testTxFeed  event.Feed
	genesis     *core.Genesis
	miningInfos map[uint64]*core.MiningInfo
}

func newTestWorkerBackend(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, shardIdxList []uint64,
	db ethdb.Database, n int, shardIsFull bool) *testWorkerBackend {
	var gspec = core.Genesis{
		Config: chainConfig,
		Alloc:  core.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
	}

	genesis := gspec.MustCommit(db)

	chain, _ := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec.Config, engine, vm.Config{}, nil, nil)
	txpool := core.NewTxPool(testTxPoolConfig, chainConfig, chain)

	// Generate a small n-block chain and an uncle block for it
	if n > 0 {
		blocks, _ := core.GenerateChain(chainConfig, genesis, engine, db, n, func(i int, gen *core.BlockGen) {
			gen.SetCoinbase(testBankAddress)
		})
		if _, err := chain.InsertChain(blocks); err != nil {
			t.Fatalf("failed to insert origin chain: %v", err)
		}
	}

	return &testWorkerBackend{
		db:      db,
		chain:   chain,
		txPool:  txpool,
		genesis: &gspec,
	}
}

func (b *testWorkerBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *testWorkerBackend) TxPool() *core.TxPool         { return b.txPool }
func (b *testWorkerBackend) StateAtBlock(block *types.Block, reexec uint64, base *state.StateDB, checkLive bool, preferDisk bool) (statedb *state.StateDB, err error) {
	return nil, errors.New("not supported")
}

func newTestWorker(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, shardIdxList []uint64,
	chunkSizeBits uint64, shardIsFull bool) (*worker, map[uint64]*core.MiningInfo, []string, *testWorkerBackend) {
	shards, files := createSstorage(contract, shardIdxList, sstorage.CHUNK_SIZE_BITS+chunkSizeBits, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	backend := newTestWorkerBackend(t, chainConfig, engine, shardIdxList, db, blocks, shardIsFull)
	backend.txPool.AddLocals(pendingTxs)

	stateDB, _ := backend.chain.State()
	wchain := wrapBlockChain{
		BlockChain: backend.chain,
		stateDB:    stateDB,
	}
	infos := wchain.initMiningInfos(shardIdxList, diff, blockMined)
	makeKVStorage(stateDB, contract, shardIdxList, 1<<kvEntriesBits, shardIsFull)

	signer := &TXSigner{
		Account: accounts.Account{Address: testBankAddress},
		SignFn: func(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
			return types.SignTx(tx, types.NewEIP2930Signer(chainConfig.ChainID), testBankKey)
		},
	}
	w := newWorker(defaultConfig, chainConfig, backend, &wchain, new(event.TypeMux), signer, minerContract, false)
	return w, infos, files, backend
}

func createSstorage(contract common.Address, shardIdxList []uint64, kvSizeBits,
	kvEntriesBits, filePerShard uint64, miner common.Address) (map[common.Address][]uint64, []string) {
	sm := sstorage.NewShardManager(contract, kvSizeBits, kvEntriesBits)
	sstorage.ContractToShardManager[contract] = sm
	kvSize := uint64(1) << kvSizeBits
	kvEntries := uint64(1) << kvEntriesBits

	files := make([]string, 0)
	for _, shardIdx := range shardIdxList {
		sm.AddDataShard(shardIdx)
		for i := uint64(0); i < filePerShard; i++ {
			fileId := shardIdx*filePerShard + i
			fileName := fmt.Sprintf(".\\ss%d.dat", fileId)
			files = append(files, fileName)
			chunkPerfile := kvEntries * kvSize / sstorage.CHUNK_SIZE / filePerShard
			startChunkId := fileId * chunkPerfile
			endChunkId := (fileId + 1) * chunkPerfile
			_, err := sstorage.Create(fileName, startChunkId, endChunkId, 0, kvSize, sstorage.ENCODE_KECCAK_256, miner)
			if err != nil {
				log.Crit("open failed", "error", err)
			}

			var df *sstorage.DataFile
			df, err = sstorage.OpenDataFile(fileName)
			if err != nil {
				log.Crit("open failed", "error", err)
			}
			sm.AddDataFile(df)
		}
	}

	shards := make(map[common.Address][]uint64)
	shards[contract] = shardIdxList
	return shards, files
}

// getSlotHash generate slot hash to fetch Data from stateDB
func getSlotHash(slotIdx uint64, key common.Hash) common.Hash {
	slot := uint256.NewInt(slotIdx).Bytes32()
	keyData := key.Bytes()
	slotData := slot[:]
	data := append(keyData, slotData...)

	return crypto.Keccak256Hash(data)
}

func generateMetadata(idx, size uint64, hash common.Hash) common.Hash {
	meta := make([]byte, 0)
	meta = append(meta, hash[:24]...)

	size_bs := make([]byte, 8)
	binary.BigEndian.PutUint64(size_bs, size)
	meta = append(meta, size_bs[5:]...)

	idx_bs := make([]byte, 8)
	binary.BigEndian.PutUint64(idx_bs, idx)
	meta = append(meta, idx_bs[3:]...)

	return common.BytesToHash(meta)
}

func getSKey(contract common.Address, idx uint64) common.Hash {
	slot := uint256.NewInt(idx).Bytes32()

	keydata := contract.Bytes()
	slotdata := slot[:]
	data := append(keydata, slotdata...)

	return crypto.Keccak256Hash(data)
}

// makeKVStorage generate a range of storage Data and its metadata
func makeKVStorage(stateDB *state.StateDB, contract common.Address, shards []uint64, kvCount uint64, shardIsFull bool) {
	sm, _ := sstorage.ContractToShardManager[contract]

	lastKvIdx := uint64(0)
	for _, sidx := range shards {
		last := (sidx + 1) * kvCount
		if sidx == shards[len(shards)-1] && !shardIsFull {
			last = sidx*kvCount + rand.Uint64()%kvCount
		}
		for i := sidx * kvCount; i < (sidx+1)*kvCount; i++ {
			val := make([]byte, 0)
			metaHash := common.Hash{}
			if i < last {
				val = make([]byte, 8)
				binary.BigEndian.PutUint64(val, i)
				val = append(contract.Bytes(), val...)
				skey := getSKey(contract, i)
				key := getSlotHash(2, uint256.NewInt(i).Bytes32())
				stateDB.SetState(contract, key, skey)

				metaHash = merkleRootWithMinTree(val, sstorage.CHUNK_SIZE)
				meta := generateMetadata(i, uint64(len(val)), metaHash)
				key = getSlotHash(1, skey)
				stateDB.SetState(contract, key, meta)
			}

			sm.TryWrite(i, val, common.BytesToHash(metaHash[:24]))
		}
		if last > lastKvIdx {
			lastKvIdx = last
		}
	}
	stateDB.SetState(contract, uint256.NewInt(0).Bytes32(), uint256.NewInt(lastKvIdx).Bytes32())
}

func updateMiningInfoAndInsertNewBlock(pinfo *core.MiningInfo, chain *wrapBlockChain, engine *ethash.Ethash, db ethdb.Database) error {
	info := new(core.MiningInfo)
	info.MiningHash = crypto.Keccak256Hash(pinfo.MiningHash.Bytes())
	info.LastMineTime = uint64(time.Now().Unix())
	info.Difficulty = diff
	info.BlockMined = blockMined
	chain.saveMiningInfo(0, info)
	blocks, _ := core.GenerateChain(ethashChainConfig, chain.CurrentBlock(), engine, db, 1, func(i int, gen *core.BlockGen) {
		gen.SetCoinbase(testBankAddress)
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		return fmt.Errorf("failed to insert origin chain: %v", err)
	}
	return nil
}

func verifyTaskResult(stateDB *state.StateDB, chain BlockChain, r *result) error {
	val := stateDB.GetState(contract, uint256.NewInt(0).Bytes32())
	lastKvIdx := new(big.Int).SetBytes(val.Bytes()).Uint64()
	for i, proofs := range r.proofs {
		hash := common.Hash{}
		root := make([]byte, 24)
		if lastKvIdx > r.kvIdxs[i] {
			off := sstorage.CHUNK_SIZE * r.chunkIdxs[i]
			_, meta, _ := core.GetSstorageMetadata(stateDB, contract, r.kvIdxs[i])

			if meta.KVSize > off {
				data, got, err := r.task.shardManager.TryReadChunk(r.kvIdxs[i]*r.task.shardManager.ChunksPerKv()+r.chunkIdxs[i], common.BytesToHash(meta.HashInMeta))
				if err != nil {
					return err
				}
				if !got {
					return fmt.Errorf("fail to get data for storageContract %s vkidx %d", contract.Hex(), r.kvIdxs[i])
				}
				if meta.KVSize < off+sstorage.CHUNK_SIZE {
					data = data[:meta.KVSize-off]
				}
				hash = crypto.Keccak256Hash(data)
			}

			root = meta.HashInMeta
		}

		vr := verifyWithMinTree(root, hash, r.chunkIdxs[i], proofs)
		if !vr {
			return fmt.Errorf("verify proofs fail for index %d fail", r.kvIdxs[i])
		}
	}
	return nil
}

func verifyTask(t *task, expectInfo *core.MiningInfo) bool {
	if t == nil {
		return false
	}
	return t.info.Equal(expectInfo)
}

func TestWork_SingleShard(test *testing.T) {
	var (
		shardIdxList = []uint64{0}
		engine       = ethash.NewFaker()
	)

	w, infos, files, _ := newTestWorker(test, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), shardIdxList, 5, true)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	var (
		taskMined int
		resultGet int
		taskCh    = make(chan *task, 2)
		resultCh  = make(chan *result, 2)
	)
	w.newTaskHook = func(task *task) {
		taskMined += 1
		taskCh <- task
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.start() // Start mining!
	for i := 0; i < 2; i += 1 {
		select {
		case t := <-taskCh:
			info, ok := infos[t.shardIdx]
			if !ok || info == nil {
				test.Error("new task timeout")
			}
			if !verifyTask(t, info) {
				test.Error("verify task fail")
			}
		case r := <-resultCh:
			stateDB, _ := w.chain.State()
			if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
				test.Error("verify mined result failed:", err.Error())
			}
			return
		case <-time.NewTimer(3 * time.Second).C:
			test.Error("new task timeout")
		}
	}
}

func TestWork_MultiShards(test *testing.T) {
	var (
		shardIdxList = []uint64{0, 1}
		engine       = ethash.NewFaker()
	)

	w, _, files, _ := newTestWorker(test, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), shardIdxList, 5, true)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	var (
		taskMined int
		resultGet int
		resultCh  = make(chan *result, 2)
	)
	w.newTaskHook = func(task *task) {
		taskMined += 1
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.start() // Start mining!
	for i := 0; i < 2; i += 1 {
		select {
		case r := <-resultCh:
			stateDB, _ := w.chain.State()
			if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
				test.Error("verify mined result failed", err.Error())
			}
		case <-time.NewTimer(3 * time.Second).C:
			test.Error("new task timeout")
		}
	}
	if resultGet != 2 {
		test.Error("expected result count is 2")
	}
}

func TestWork_TriggerByNewBlock(test *testing.T) {
	var (
		shardIdxList = []uint64{0}
		engine       = ethash.NewFaker()
		db           = rawdb.NewMemoryDatabase()
	)

	w, _, files, _ := newTestWorker(test, ethashChainConfig, engine, db, shardIdxList, 5, true)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	var (
		taskMined int
		resultGet int
		resultCh  = make(chan *result, 2)
	)
	w.newTaskHook = func(task *task) {
		taskMined += 1
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.start() // Start mining!
	for i := 0; i < 2; i += 1 {
		select {
		case r := <-resultCh:
			stateDB, _ := w.chain.State()
			if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
				test.Error("verify mined result failed", err.Error())
			}
			updateMiningInfoAndInsertNewBlock(r.task.info, w.chain.(*wrapBlockChain), engine, db)
		case <-time.NewTimer(3 * time.Second).C:
			test.Error("new task timeout")
		}
	}
	if resultGet != 2 {
		test.Error("expected result count is 2")
	}
}

func TestWork_ShardIsNotFull(test *testing.T) {
	var (
		taskMined    int
		resultGet    int
		resultCh     = make(chan *result, 2)
		shardIdxList = []uint64{0}
		engine       = ethash.NewFaker()
		db           = rawdb.NewMemoryDatabase()
	)

	w, _, files, _ := newTestWorker(test, ethashChainConfig, engine, db, shardIdxList, 5, false)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	w.newTaskHook = func(task *task) {
		taskMined += 1
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.start() // Start mining!
	select {
	case r := <-resultCh:
		stateDB, _ := w.chain.State()
		if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
			test.Error("verify mined result failed", err.Error())
		}
	case <-time.NewTimer(3 * time.Second).C:
		test.Error("new task timeout")
	}
}

func TestWork_StartAndStopTask(test *testing.T) {
	var (
		shardIdxList = []uint64{0, 1, 2}
		engine       = ethash.NewFaker()
	)

	w, _, files, _ := newTestWorker(test, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), shardIdxList, 5, true)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	var (
		taskMined int
		resultGet int
		resultCh  = make(chan *result, 2)
	)
	w.newTaskHook = func(task *task) {
		taskMined += 1
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.stopTask(contract, 0)
	w.start() // Start mining!
	for i := 0; i < 3; i += 1 {
		select {
		case r := <-resultCh:
			stateDB, _ := w.chain.State()
			if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
				test.Error("verify mined result failed", err.Error())
			}
		case <-time.NewTimer(2 * time.Second).C:
			fmt.Println("get new result time out")
		}
	}
	if resultGet != 2 {
		test.Error("expected result count is 2")
	}

	w.startTask(contract, 0)
	select {
	case r := <-resultCh:
		stateDB, _ := w.chain.State()
		if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
			test.Error("verify mined result failed", err.Error())
		}
	case <-time.NewTimer(3 * time.Second).C:
		test.Error("new task timeout")
	}
	if resultGet != 3 {
		test.Error("expected result count is 3")
	}
}

func TestWork_SmallKV(test *testing.T) {
	var (
		shardIdxList = []uint64{0}
		engine       = ethash.NewFaker()
		db           = rawdb.NewMemoryDatabase()
	)

	w, _, files, _ := newTestWorker(test, ethashChainConfig, engine, db, shardIdxList, 0, true)

	defer w.close()
	defer engine.Close()
	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	var (
		taskMined int
		resultGet int
		resultCh  = make(chan *result, 2)
	)
	w.newTaskHook = func(task *task) {
		taskMined += 1
	}
	w.newResultHook = func(result *result) {
		resultGet += 1
		resultCh <- result
	}

	w.start()
	select {
	case r := <-resultCh:
		stateDB, _ := w.chain.State()
		if err := verifyTaskResult(stateDB, w.chain, r); err != nil {
			test.Error("verify mined result failed:", err.Error())
		}
	case <-time.NewTimer(3 * time.Second).C:
		test.Error("new task timeout")
	}
}

func TestWork_ProofsCreateAndVerify(test *testing.T) {
	type testCase struct {
		chunkPerKVBits uint64
		val            []byte
	}

	testCases := []testCase{
		{
			chunkPerKVBits: uint64(0),
			val:            contract.Bytes(),
		},
		{
			chunkPerKVBits: uint64(0),
			val:            make([]byte, 0),
		},
		{
			chunkPerKVBits: uint64(1),
			val:            contract.Bytes(),
		},
		{
			chunkPerKVBits: uint64(1),
			val:            make([]byte, 0),
		},
		{
			chunkPerKVBits: uint64(4),
			val:            make([]byte, 0),
		},
		{
			chunkPerKVBits: uint64(4),
			val:            contract.Bytes(),
		},
		{
			chunkPerKVBits: uint64(4),
			val:            append(make([]byte, sstorage.CHUNK_SIZE), contract.Bytes()...),
		},
		{
			chunkPerKVBits: uint64(4),
			val:            append(make([]byte, sstorage.CHUNK_SIZE*2), contract.Bytes()...),
		},
		{
			chunkPerKVBits: uint64(4),
			val:            append(make([]byte, sstorage.CHUNK_SIZE*3), contract.Bytes()...),
		},
		{
			chunkPerKVBits: uint64(7),
			val:            contract.Bytes(),
		},
		{
			chunkPerKVBits: uint64(7),
			val:            append(make([]byte, sstorage.CHUNK_SIZE), contract.Bytes()...),
		},
	}

	for _, tc := range testCases {
		testWork_ProofsCreateAndVerify(test, tc.val, tc.chunkPerKVBits)
	}
	for _, tc := range testCases {
		testWork_ProofsCreateAndVerifyWithMinTree(test, tc.val, tc.chunkPerKVBits)
	}
}

func testWork_ProofsCreateAndVerify(test *testing.T, val []byte, chunkPerKVBits uint64) {
	chunkPerKV := uint64(1) << chunkPerKVBits
	dataLen := uint64(len(val))

	root := merkleRoot(val, chunkPerKV, sstorage.CHUNK_SIZE)
	for i := uint64(0); i < chunkPerKV; i++ {
		hash := common.Hash{}
		off := i * sstorage.CHUNK_SIZE

		ps, err := getProof(val, sstorage.CHUNK_SIZE, chunkPerKVBits, i)
		if err != nil {
			test.Error("error:", err.Error())
		}
		if off < dataLen {
			size := dataLen - off
			if size > sstorage.CHUNK_SIZE {
				size = sstorage.CHUNK_SIZE
			}
			hash = crypto.Keccak256Hash(val[off : off+size])
		}
		vr := verify(root.Bytes()[:24], hash, i, ps)
		if !vr {
			test.Error("verify proof fail, chunk ", i)
		}
	}
}

func testWork_ProofsCreateAndVerifyWithMinTree(test *testing.T, val []byte, chunkPerKVBits uint64) {
	chunkPerKV := uint64(1) << chunkPerKVBits
	dataLen := uint64(len(val))

	root := merkleRootWithMinTree(val, sstorage.CHUNK_SIZE)
	for i := uint64(0); i < chunkPerKV; i++ {
		hash := common.Hash{}
		off := i * sstorage.CHUNK_SIZE

		ps, err := getProofWithMinTree(val, sstorage.CHUNK_SIZE, chunkPerKVBits, i)
		if err != nil {
			test.Error("error:", err.Error())
		}
		if off < dataLen {
			size := dataLen - off
			if size > sstorage.CHUNK_SIZE {
				size = sstorage.CHUNK_SIZE
			}
			hash = crypto.Keccak256Hash(val[off : off+size])
		}
		vr := verifyWithMinTree(root.Bytes()[:24], hash, i, ps)
		if !vr {
			test.Error("verify proof fail, chunk ", i)
		}
	}
}
