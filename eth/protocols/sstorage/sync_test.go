// Copyright 2020 The go-ethereum Authors
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

package sstorage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/event"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/sstorage"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

var (
	contract      = common.HexToAddress("0x0000000000000000000000000000000003330001")
	kvEntriesBits = uint64(9)
	kvEntries     = uint64(1) << 9
)

type (
	kvHandlerFunc func(t *testPeer, id uint64, contract common.Address, shardId uint64, kvList []uint64) error
)

type blockChain struct {
	block     *types.Block
	stateDB   *state.StateDB
	lastKvIdx uint64
}

func (c *blockChain) StateAt(root common.Hash) (*state.StateDB, error) {
	return c.stateDB, nil
}

func (c *blockChain) CurrentBlock() *types.Block {
	return c.block
}

func (bc *blockChain) FillSstorWithEmptyKV(contract common.Address, start, limit uint64) (uint64, error) {
	sm := sstorage.ContractToShardManager[contract]
	if sm == nil {
		return start, fmt.Errorf("kv verify fail: contract not support, contract: %s", contract.Hex())
	}

	empty := make([]byte, 0)
	lastKvIdx, err := bc.GetSstorageLastKvIdx(contract)
	if err != nil {
		return start, fmt.Errorf("get lastKvIdx for FillEmptyKV fail, err: %s", err.Error())
	}
	for idx := start; idx <= limit; idx++ {
		if lastKvIdx > idx {
			continue
		}
		_, err = sm.TryWrite(idx, empty, common.Hash{})
		if err != nil {
			err = fmt.Errorf("write empty to kv file fail, index: %d; error: %s", idx, err.Error())
			return idx, err
		}
	}

	return limit + 1, nil
}

func (c *blockChain) VerifyAndWriteKV(contract common.Address, data map[uint64][]byte, providerAddr common.Address) (uint64, uint64, []uint64, error) {
	var (
		synced      uint64
		syncedBytes uint64
		inserted    = make([]uint64, 0)
	)
	sm := sstorage.ContractToShardManager[contract]
	if sm == nil {
		return 0, 0, inserted, fmt.Errorf("kv verify fail: contract not support, contract: %s", contract.Hex())
	}

	for idx, val := range data {
		synced++
		syncedBytes += uint64(len(val))

		_, meta, err := core.GetSstorageMetadata(c.stateDB, contract, idx)
		if err != nil || meta == nil {
			log.Warn("processKVResponse: get vkv MetaHash for verification fail", "error", err)
			continue
		}

		rawData, err := core.VerifyKV(sm, idx, val, meta, true, providerAddr)
		if err != nil {
			log.Warn("processKVResponse: verify vkv fail", "error", err)
			continue
		}

		success, err := sm.TryWrite(idx, rawData, common.BytesToHash(meta.HashInMeta))
		if err != nil {
			log.Warn("write kv fail", "error", err)
			continue
		}
		if success {
			inserted = append(inserted, idx)
		}
	}
	return synced, syncedBytes, inserted, nil
}

func (c *blockChain) ReadEncodedKVsByIndexList(contract common.Address, shardId uint64, indexes []uint64) (common.Address, []*core.KV, error) {
	sm := sstorage.ContractToShardManager[contract]
	if sm == nil {
		return common.Address{}, nil, fmt.Errorf("shard manager for contract %s is not support", contract.Hex())
	}
	miner, ok := sm.GetShardMiner(shardId)
	if !ok {
		return common.Address{}, nil, fmt.Errorf("shard %d do not support for contract %s", shardId, contract.Hex())
	}

	res := make([]*core.KV, 0)
	for _, idx := range indexes {
		_, meta, err := core.GetSstorageMetadata(c.stateDB, contract, idx)
		if err != nil {
			continue
		}
		data, ok, err := sm.TryReadEncoded(idx, int(meta.KVSize))
		if ok && err == nil {
			kv := core.KV{Idx: idx, Data: data}
			res = append(res, &kv)
		}
	}

	return miner, res, nil
}

func (c *blockChain) ReadEncodedKVsByIndexRange(contract common.Address, shardId uint64, origin uint64, limit uint64,
	bytes uint64) (common.Address, []*core.KV, error) {
	sm := sstorage.ContractToShardManager[contract]
	if sm == nil {
		return common.Address{}, nil, fmt.Errorf("shard manager for contract %s is not support", contract.Hex())
	}
	miner, ok := sm.GetShardMiner(shardId)
	if !ok {
		return common.Address{}, nil, fmt.Errorf("shard %d do not support for contract %s", shardId, contract.Hex())
	}

	res := make([]*core.KV, 0)
	read := uint64(0)
	for idx := origin; idx <= limit; idx++ {
		_, meta, err := core.GetSstorageMetadata(c.stateDB, contract, idx)
		if err != nil {
			continue
		}
		data, ok, err := sm.TryReadEncoded(idx, int(meta.KVSize))
		if ok && err == nil {
			kv := core.KV{Idx: idx, Data: data}
			res = append(res, &kv)
			read += meta.KVSize
			if read > bytes {
				break
			}
		}
	}

	return miner, res, nil
}

func (c *blockChain) GetSstorageLastKvIdx(contract common.Address) (uint64, error) {
	return c.lastKvIdx, nil
}

type testPeer struct {
	id                    string
	test                  *testing.T
	remote                *Syncer
	stateDB               *state.StateDB
	logger                log.Logger
	shardData             map[common.Address]map[uint64][]byte
	shards                map[common.Address][]uint64
	kvRangeRequestHandler kvHandlerFunc
	kvHealRequestHandler  kvHandlerFunc
	term                  func()

	// counters
	nKVRequests int
}

func newTestPeer(id string, stateDB *state.StateDB, t *testing.T, term func()) *testPeer {
	peer := &testPeer{
		id:                    id,
		test:                  t,
		logger:                log.New("id", id),
		kvRangeRequestHandler: defaultKVRangeRequestHandler,
		kvHealRequestHandler:  defaultKVHealRequestHandler,
		term:                  term,
		stateDB:               stateDB,
	}
	return peer
}

func (t *testPeer) ID() string { return t.id }

func (t *testPeer) Log() log.Logger { return t.logger }

func (t *testPeer) IsShardExist(contract common.Address, shardId uint64) bool {
	res := false
	if ids, ok := t.shards[contract]; ok {
		for _, id := range ids {
			if id == shardId {
				res = true
				break
			}
		}
	}

	return res
}

func (t *testPeer) RequestKVs(id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	t.logger.Trace("Fetching range of kvs", "contract", contract, "shardId", shardId, "kvList", len(kvList))
	t.nKVRequests++
	go t.kvHealRequestHandler(t, id, contract, shardId, kvList)
	return nil
}

func (t *testPeer) RequestKVRange(id uint64, contract common.Address, shardId uint64, origin uint64, limit uint64) error {
	t.nKVRequests++
	kvList := make([]uint64, 0)
	for i := origin; i <= limit; i++ {
		kvList = append(kvList, i)
	}
	go t.kvRangeRequestHandler(t, id, contract, shardId, kvList)
	return nil
}

// RequestShardList fetches shard list support by the peer
func (t *testPeer) RequestShardList(shards map[common.Address][]uint64) error {
	t.logger.Trace("Fetching Shard list", "shards", shards)
	return nil
}

func delayRandomTime(max uint64, duration time.Duration) {
	d := time.Duration(rand.Uint64() % max)
	time.Sleep(d * duration)
}

// defaultKVRangeRequestHandler is a well-behaving handler for KVsRequests
func defaultKVRangeRequestHandler(t *testPeer, id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	vals := createKVRequestResponse(t, id, t.stateDB, contract, shardId, kvList)
	delayRandomTime(5000, time.Microsecond)
	if vals == nil {
		t.test.Error("CreateKVRequestResponse fail: vals is nul.")
	}
	if err := t.remote.OnKVRange(t, id, common.Address{}, vals); err != nil {
		t.test.Errorf("Remote side rejected our delivery: %v", err)
		t.term()
		return err
	}
	return nil
}

// defaultKVHealRequestHandler is a well-behaving handler for KVsRequests
func defaultKVHealRequestHandler(t *testPeer, id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	vals := createKVRequestResponse(t, id, t.stateDB, contract, shardId, kvList)
	delayRandomTime(5000, time.Microsecond)
	if vals == nil {
		t.test.Error("CreateKVRequestResponse fail: vals is nul.")
	}
	if err := t.remote.OnKVs(t, id, common.Address{}, vals); err != nil {
		t.test.Errorf("Remote side rejected our delivery: %v", err)
		t.term()
		return err
	}
	return nil
}

func createKVRequestResponse(t *testPeer, id uint64, stateDB *state.StateDB, contract common.Address, shardId uint64, kvList []uint64) (values []*core.KV) {
	values = make([]*core.KV, 0)
	smData, ok := t.shardData[contract]
	if !ok {
		return nil
	}

	sm, ok := sstorage.ContractToShardManager[contract]
	if !ok {
		return nil
	}

	for _, idx := range kvList {
		data, ok := smData[idx]
		if ok {
			_, meta, err := core.GetSstorageMetadata(stateDB, contract, idx)
			if err != nil {
				return nil
			}
			bs, _, _ := sm.EncodeKV(idx, data, common.BytesToHash(meta.HashInMeta), common.Address{})
			if uint64(len(bs)) > meta.KVSize {
				values = append(values, &core.KV{Idx: idx, Data: bs[:meta.KVSize]})
			} else {
				values = append(values, &core.KV{Idx: idx, Data: bs})
			}
		}
	}

	return values
}

// emptyRequestKVRangeFn is a rejects AccountRangeRequests
func emptyRequestKVRangeFn(t *testPeer, id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	t.remote.OnKVRange(t, id, common.Address{}, nil)
	return nil
}

func nonResponsiveRequestKVRangeFn(t *testPeer, id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	return nil
}

func setupSyncer(shards map[common.Address][]uint64, stateDB *state.StateDB, lastKvIdx uint64, peers ...*testPeer) *Syncer {
	db := rawdb.NewMemoryDatabase()
	blockEnc := common.FromHex("f90260f901f9a083cafc574e1f51ba9dc0568fc617a08ea2429fb384059c972f13b19fa1c8dd55a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ef1552a40b7165c3cd773806b9e0c165b75356e0314bf0706f279c729f51e017a05fe50b260da6308036625b850b5d6ced6d0a9f814c0688bc91ffb7b7a3a54b67a0bc37d79753ad738a6dac4921e57392f145d8887476de3f783dfa7edae9283e52b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008302000001832fefd8825208845506eb0780a0bd4472abb6659ebe3ee06ee4d7b72a00a9f4d001caca51342001075469aff49888a13a5a8c8f2bb1c4f861f85f800a82c35094095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba09bea4c4daac7c7c52e093e6a4c35dbbcf8856f1af7b059ba20253e70848d094fa08a8fae537ce25ed8cb5af9adac3f141af69bd515bd2ba031522df09b97dd72b1c0")
	var block types.Block
	rlp.DecodeBytes(blockEnc, &block)
	chain := blockChain{block: &block, stateDB: stateDB}
	chain.lastKvIdx = lastKvIdx
	syncer := NewSyncer(db, &chain, new(event.TypeMux), shards)
	for _, peer := range peers {
		syncer.Register(peer)
		peer.remote = syncer
	}
	return syncer
}

// getCodeHash returns a pseudo-random code hash
func getSKey(contract common.Address, idx uint64) common.Hash {
	slot := uint256.NewInt(idx).Bytes32()

	keydata := contract.Bytes()
	slotdata := slot[:]
	data := append(keydata, slotdata...)

	return hash(data)
}

func hash(data []byte) common.Hash {
	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hasher.Write(data)

	hashRes := common.Hash{}
	hasher.Read(hashRes[:])

	return hashRes
}

func checkStall(t *testing.T, term func()) chan struct{} {
	testDone := make(chan struct{})
	go func() {
		select {
		case <-time.After(2 * time.Second):
			t.Log("Sync stalled")
			term()
		case <-testDone:
			return
		}
	}()
	return testDone
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

// getSlotHash generate slot hash to fetch Data from stateDB
func getSlotHash(slotIdx uint64, key common.Hash) common.Hash {
	slot := uint256.NewInt(slotIdx).Bytes32()

	keydata := key.Bytes()
	slotdata := slot[:]
	data := append(keydata, slotdata...)

	return crypto.Keccak256Hash(data)
}

// makeKVStorage generate a range of storage Data and its metadata
func makeKVStorage(stateDB *state.StateDB, contract common.Address, shards []uint64,
	kvCount uint64) (map[common.Address]map[uint64][]byte, map[common.Address][]uint64) {
	shardData := make(map[common.Address]map[uint64][]byte)
	shardList := make(map[common.Address][]uint64)
	shardList[contract] = shards
	smData := make(map[uint64][]byte)
	shardData[contract] = smData

	for _, sidx := range shards {
		for i := sidx * kvCount; i < (sidx+1)*kvCount; i++ {
			val := make([]byte, 8)
			binary.BigEndian.PutUint64(val, i)
			val = append(contract.Bytes(), val...)

			if stateDB != nil {
				skey := getSKey(contract, i)
				key := getSlotHash(2, uint256.NewInt(i).Bytes32())
				stateDB.SetState(contract, key, skey)

				meta := generateMetadata(i, uint64(len(val)), hash(val))
				key = getSlotHash(1, skey)
				stateDB.SetState(contract, key, meta)
			}

			smData[i] = val
		}
	}

	return shardData, shardList
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
		for i := shardIdx * sm.KvEntries(); i < (shardIdx+1)*sm.KvEntries(); i++ {
			sm.TryWrite(i, empty, common.Hash{})
		}
	}

	shards := make(map[common.Address][]uint64)
	shards[contract] = shardIdxList
	return shards, files
}

func verifyKVs(stateDB *state.StateDB, data map[common.Address]map[uint64][]byte,
	destroyedList map[uint64]struct{}, t *testing.T) {
	for contract, shards := range data {
		shardData := sstorage.ContractToShardManager[contract]
		if shardData == nil {
			t.Fatalf("sstorage manager for contract %s do not exist.", contract.Hex())
		}
		for idx, val := range shards {
			_, meta, err := core.GetSstorageMetadata(stateDB, contract, idx)
			if err != nil {
				t.Fatalf("get MetaHash data fail with err: %s.", err.Error())
			}

			sval, ok, err := shardData.TryRead(idx, len(val), common.BytesToHash(meta.HashInMeta))
			if err != nil {
				t.Fatalf("TryRead sstorage Data fail. err: %s", err.Error())
			}
			if !ok {
				t.Fatalf("TryRead sstroage Data fail. err: %s, index %d", "shard Idx not support", idx)
			}

			if _, ok := destroyedList[idx]; ok {
				val = make([]byte, sstorage.CHUNK_SIZE)
				sval, ok, err = shardData.TryReadChunk(idx, common.BytesToHash(make([]byte, 24)))
				if err != nil {
					t.Fatalf("TryReadChunk fail. err: %s", err.Error())
				}
				if !ok {
					t.Fatalf("TryReadChunk fail. err: %s", "shard Idx not support")
				}
			}
			if !bytes.Equal(val, sval) {
				t.Fatalf("verify KV failed; index: %d; val: %s; sval: %s",
					idx, common.Bytes2Hex(val), common.Bytes2Hex(sval))
			}
		}
	}
}

func getRandomU64InRange(excludeList map[uint64]struct{}, start, end, count uint64) []uint64 {
	i := uint64(0)
	list := make([]uint64, 0)
	for i < count {
		idx := rand.Uint64()%(end-start) + start
		if _, ok := excludeList[idx]; ok {
			continue
		}
		excludeList[idx] = struct{}{}
		list = append(list, idx)
		i++
	}
	return list
}

func destoryData(data map[common.Address]map[uint64][]byte, excludeList map[uint64]struct{}, start, end, count uint64) map[uint64]struct{} {
	// destroy data
	list := make(map[uint64]struct{})
	fdata := []byte("fake data")
	idxes := getRandomU64InRange(excludeList, start, end, count)
	for _, idx := range idxes {
		data[contract][idx] = fdata
		list[idx] = struct{}{}
	}
	return list
}

func createKvTask(contract common.Address, kvEntries uint64, sid uint64, lastKvIndex uint64, count uint64) *kvTask {
	first, limit := kvEntries*sid, kvEntries*(sid+1)-1
	if first > lastKvIndex {
		return nil
	}
	if lastKvIndex > 0 && limit > lastKvIndex {
		limit = lastKvIndex
	}
	task := kvTask{
		Contract:       contract,
		ShardId:        sid,
		statelessPeers: make(map[string]struct{}),
		done:           false,
	}

	healTask := kvHealTask{
		kvTask:  &task,
		Indexes: make(map[uint64]int64),
	}
	list := getRandomU64InRange(make(map[uint64]struct{}), first, limit, count)
	for _, idx := range list {
		healTask.Indexes[idx] = 0
	}
	subTasks := make([]*kvSubTask, 0)

	maxTaskSize := (limit - first + maxConcurrency) / maxConcurrency
	if maxTaskSize < minSubTaskSize {
		maxTaskSize = minSubTaskSize
	}

	for first < limit {
		last := first + maxTaskSize
		if last > limit {
			last = limit
		}
		subTask := kvSubTask{
			kvTask: &task,
			next:   first,
			First:  first,
			Last:   last,
			done:   false,
		}

		subTasks = append(subTasks, &subTask)
		first = last + 1
	}

	task.HealTask, task.KvSubTasks = &healTask, subTasks
	return &task
}

func compareTasks(tasks1, tasks2 []*kvTask) error {
	if err := checkTasksWithBaskTasks(tasks1, tasks2); err != nil {
		return err
	}
	if err := checkTasksWithBaskTasks(tasks2, tasks1); err != nil {
		return err
	}
	return nil
}

func checkTasksWithBaskTasks(baseTasks, tasks []*kvTask) error {
	for _, task1 := range baseTasks {
		var task2 *kvTask = nil
		for _, stask := range tasks {
			if task1.Contract == stask.Contract && task1.ShardId == stask.ShardId {
				task2 = stask
				break
			}
		}
		if task2 == nil {
			return fmt.Errorf("compare tasks failed. error: missing task; contract %s & shardId %d",
				task1.Contract.Hex(), task1.ShardId)
		}
		if len(task1.KvSubTasks) != len(task2.KvSubTasks) {
			return fmt.Errorf("compare tasks failed: error: subtask len mismatch; contract %s & shardId %d, len 1 %d, len 2 %d",
				task1.Contract.Hex(), task1.ShardId, len(task1.KvSubTasks), len(task2.KvSubTasks))
		}
		if len(task1.HealTask.Indexes) != len(task2.HealTask.Indexes) {
			return fmt.Errorf("compare tasks failed: error: index len in heal task mismatch; contract %s & shardId %d, len 1 %d, len 2 %d",
				task1.Contract.Hex(), task1.ShardId, len(task1.HealTask.Indexes), len(task2.HealTask.Indexes))
		}

		for _, subTask1 := range task1.KvSubTasks {
			exist := false
			for _, subTask2 := range task2.KvSubTasks {
				if subTask1.next == subTask2.next && subTask1.Last == subTask2.Last {
					exist = true
					break
				}
			}
			if !exist {
				return fmt.Errorf("compare tasks failed: error: missing subtask; contract %s & shardId %d, Next %d, Last %d",
					task1.Contract.Hex(), task1.ShardId, subTask1.next, subTask1.Last)
			}
		}

		for idx, _ := range task1.HealTask.Indexes {
			if _, ok := task2.HealTask.Indexes[idx]; !ok {
				return fmt.Errorf("compare tasks failed: error: index missing; contract %s & shardId %d, index %d",
					task1.Contract.Hex(), task1.ShardId, idx)
			}
		}
	}
	return nil
}

// test cases:
// test sync with one peer
// test sync with multi peer
// test sync with Many Useless
// test sync return empty result
// test sync return fewer result
// test sync return result mismatch with local node
// test sync with multi sstorage files for one shard
//

// TestReadWrite tests a basic sstorage read/wrtie
func TestReadWrite(t *testing.T) {
	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	sm := sstorage.ContractToShardManager[contract]
	success, err := sm.TryWrite(0, []byte{1}, common.Hash{})
	if !success || err != nil {
		t.Fatalf("failed to write")
	}
	rdata, success, err := sm.TryRead(0, 1, common.Hash{})
	if !success || err != nil {
		t.Fatalf("failed to read")
	}
	if !bytes.Equal([]byte{1}, rdata) {
		t.Fatalf("failed to compare")
	}
}

// TestSync tests a basic sync with one peer
func TestSync(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, kvEntries)
	syncer := setupSyncer(shards, stateDB, kvEntries, mkSource("source", shards, data))
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestSync tests a basic sync with one peer
func TestMultiSubTasksSync(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		entriesBits   = uint64(10)
		entries       = uint64(1) << 10
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, entriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, entries)
	syncer := setupSyncer(shards, stateDB, entries, mkSource("source", shards, data))
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestMultiSync tests a basic sync with multiple peers
func TestMultiSync(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0, 1, 2, 3, 4}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	peers := make([]*testPeer, 0)
	dataList := make([]map[common.Address]map[uint64][]byte, 0)
	for i := 0; i < 5; i++ {
		data, shards := makeKVStorage(stateDB, contract, []uint64{uint64(i)}, kvEntries)
		dataList = append(dataList, data)
		peer := mkSource(fmt.Sprintf("source_%d", i), shards, data)
		peers = append(peers, peer)
	}

	syncer := setupSyncer(shards, stateDB, kvEntries*5, peers...)
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	for _, data := range dataList {
		verifyKVs(stateDB, data, destroyedList, t)
	}
}

// TestSyncWithEmptyResponse tests a basic sync with one peer
func TestSyncWithEmptyResponse(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		source.kvRangeRequestHandler = emptyRequestKVRangeFn
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, kvEntries)
	syncer := setupSyncer(shards, stateDB, kvEntries, mkSource("source", shards, data))
	for i := uint64(0); i < kvEntries; i++ {
		destroyedList[i] = struct{}{}
	}
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != ErrCancelled {
		t.Fatalf("sync cancelled error is expected: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestSyncWithNoResponse tests a basic sync with one peer
func TestSyncWithNoResponse(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		source.kvRangeRequestHandler = nonResponsiveRequestKVRangeFn
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, kvEntries)
	syncer := setupSyncer(shards, stateDB, kvEntries, mkSource("source", shards, data))
	for i := uint64(0); i < kvEntries; i++ {
		destroyedList[i] = struct{}{}
	}
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != ErrCancelled {
		t.Fatalf("sync cancelled error is expected: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestSyncWithFewerResult tests a basic sync with one peer
func TestSyncWithFewerResult(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
		reduce = rand.Uint64()%(kvEntriesBits/2) - 1
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, kvEntries-reduce)
	syncer := setupSyncer(shards, stateDB, kvEntries-reduce, mkSource("source", shards, data))
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestSyncMismatchWithMeta test sync return result mismatch with local node
func TestSyncMismatchWithMeta(t *testing.T) {
	var (
		once       sync.Once
		cancel     = make(chan struct{})
		stateDB, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term       = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	shards, files := createSstorage(contract, []uint64{0}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	data, _ := makeKVStorage(stateDB, contract, []uint64{0}, kvEntries)
	destroyedList := destoryData(data, make(map[uint64]struct{}), 0, kvEntries, 8)
	syncer := setupSyncer(shards, stateDB, kvEntries, mkSource("source", shards, data))
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != ErrCancelled {
		t.Fatalf("sync cancelled error is expected: %v", err)
	}
	close(done)
	verifyKVs(stateDB, data, destroyedList, t)
}

// TestMultiSyncWithDataOverlay test sync with multi sstorage files for one shard
func TestMultiSyncWithDataOverlay(t *testing.T) {
	var (
		once          sync.Once
		cancel        = make(chan struct{})
		destroyedList = make(map[uint64]struct{})
		stateDB, _    = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term          = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	_, files := createSstorage(contract, []uint64{0, 1, 2, 3}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	expectedData, localShards := makeKVStorage(stateDB, contract, []uint64{0, 1, 2, 3}, kvEntries)
	data, shards := makeKVStorage(nil, contract, []uint64{0, 1, 2}, kvEntries)
	peer0 := mkSource("source_0", shards, data)
	data, shards = makeKVStorage(nil, contract, []uint64{2, 3}, kvEntries)
	peer1 := mkSource("source_1", shards, data)
	/*	data, shards = makeKVStorage(nil, contract, []uint64{2, 3}, kvEntriesBits)
		peer2 := mkSource("source_2", shards, data)*/

	syncer := setupSyncer(localShards, stateDB, kvEntries*4, peer0, peer1)
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	verifyKVs(stateDB, expectedData, destroyedList, t)
}

// TestMultiSyncWithDataOverlayWithDestroyed test sync with multi sstorage files for one shard
func TestMultiSyncWithDataOverlayWithDestroyed(t *testing.T) {
	var (
		once       sync.Once
		cancel     = make(chan struct{})
		stateDB, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term       = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	requestTimeoutInMillisecond = 50 * time.Millisecond // Millisecond
	_, files := createSstorage(contract, []uint64{0, 1, 2}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	expectedData, localShards := makeKVStorage(stateDB, contract, []uint64{0, 1, 2}, kvEntries)
	data, shards := makeKVStorage(nil, contract, []uint64{0, 1, 2}, kvEntries)
	list := destoryData(data, make(map[uint64]struct{}), 0, kvEntries*3, 8)
	peer0 := mkSource("source_0", shards, data)
	data, shards = makeKVStorage(nil, contract, []uint64{0, 1, 2}, kvEntries)
	_ = destoryData(data, list, 0, kvEntries*3, 8)
	peer1 := mkSource("source_1", shards, data)

	syncer := setupSyncer(localShards, stateDB, kvEntries*3, peer0, peer1)
	done := checkStall(t, term)
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	close(done)
	verifyKVs(stateDB, expectedData, make(map[uint64]struct{}), t)
}

// TestMultiSyncWithDataOverlayWithDestroyed test sync with multi sstorage files for one shard
func TestAddPeerDuringSyncing(t *testing.T) {
	var (
		once       sync.Once
		cancel     = make(chan struct{})
		stateDB, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		term       = func() {
			once.Do(func() {
				close(cancel)
			})
		}
	)

	requestTimeoutInMillisecond = 50 * time.Millisecond // Millisecond
	_, files := createSstorage(contract, []uint64{0, 1, 2}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	mkSource := func(name string, shards map[common.Address][]uint64,
		data map[common.Address]map[uint64][]byte) *testPeer {
		source := newTestPeer(name, stateDB, t, term)
		source.shardData = data
		source.shards = shards
		return source
	}

	expectedData, localShards := makeKVStorage(stateDB, contract, []uint64{0, 1, 2}, kvEntries)
	data, shards := makeKVStorage(nil, contract, []uint64{0, 1, 2}, kvEntries)
	list := destoryData(data, make(map[uint64]struct{}), 0, kvEntries*3, 8)
	peer0 := mkSource("source_0", shards, data)
	data, shards = makeKVStorage(nil, contract, []uint64{0, 1, 2}, kvEntries)
	_ = destoryData(data, list, 0, kvEntries*3, 8)
	peer1 := mkSource("source_1", shards, data)

	syncer := setupSyncer(localShards, stateDB, kvEntries*3, peer0)
	done := checkStall(t, term)
	go func() {
		time.Sleep(100 * time.Millisecond)
		syncer.Register(peer1)
		peer1.remote = syncer
	}()
	if err := syncer.Sync(cancel); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(syncer.peers) != 2 {
		t.Fatalf("peer count expected: 2, real: %d\r\n", len(syncer.peers))
	}
	close(done)
	verifyKVs(stateDB, expectedData, make(map[uint64]struct{}), t)
}

func TestSaveAndLoadSyncStatus(t *testing.T) {
	var (
		stateDB, _  = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		entries     = kvEntriesBits * 10
		lastKvIndex = entries*3 - kvEntriesBits - 9
	)
	shards, files := createSstorage(contract, []uint64{0, 1, 2}, sstorage.CHUNK_SIZE_BITS, kvEntriesBits, 1, common.Address{})
	if shards == nil {
		t.Fatalf("createSstorage failed")
	}

	defer func(files []string) {
		for _, file := range files {
			os.Remove(file)
		}
	}(files)

	syncer := setupSyncer(shards, stateDB, kvEntries)
	task0 := createKvTask(contract, entries, 0, lastKvIndex, 20)
	task0.KvSubTasks = make([]*kvSubTask, 0)
	task1 := createKvTask(contract, entries, 1, lastKvIndex, 4)
	task2 := createKvTask(contract, entries, 2, lastKvIndex, 0)

	tasks := []*kvTask{task0, task1, task2}
	syncer.tasks = tasks
	syncer.saveSyncStatus()

	syncer.tasks = make([]*kvTask, 0)
	syncer.loadSyncStatus()
	if err := compareTasks(tasks, syncer.tasks); err != nil {
		t.Fatalf("compare kv task fail. err: %s", err.Error())
	}
}
