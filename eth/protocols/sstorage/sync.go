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
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/msgrate"
	"github.com/ethereum/go-ethereum/sstorage"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

const (
	// maxRequestSize is the maximum number of bytes to request from a remote peer.
	// This number is used as the high cap for kv range requests.
	maxRequestSize = uint64(512 * 1024)
)

// ErrCancelled is returned from sstorage syncing if the operation was prematurely
// terminated.
var ErrCancelled = errors.New("sync cancelled")

var (
	emptyHash = common.Hash{}

	requestTimeoutInMillisecond = 10000 * time.Millisecond // Millisecond
)

// kvRequest tracks a pending kv request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: kv requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the Data to
// construct the response without accessing runloop internals (i.e. task). That
// is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type kvRequest struct {
	peer string    // Peer to which this request is assigned
	id   uint64    // Request ID of this request
	time time.Time // Timestamp when the request was sent

	deliver chan *kvResponse // Channel to deliver successful response on
	revert  chan *kvRequest  // Channel to deliver request failure on
	cancel  chan struct{}    // Channel to track sync cancellation
	timeout *time.Timer      // Timer to track delivery timeout
	stale   chan struct{}    // Channel to signal the request was dropped

	contract common.Address
	shardId  uint64
	indexes  []uint64

	task *kvTask // kvTask which this request is filling (only access fields through the runloop!!)
}

// kvResponse is an already verified remote response to a kv request.
type kvResponse struct {
	reqId    uint64         // Request ID of this response
	task     *kvTask        // kvTask which this request is filling
	contract common.Address // contract
	shardId  uint64         // shardId
	kvs      []*KV          // kvs to store into the sharded storage
}

// kvTask represents the sync task for a sstorage shard.
type kvTask struct {
	// These fields get serialized to leveldb on shutdown
	contract  common.Address   // contract address
	shardId   uint64           // shardId
	indexes   map[uint64]int64 // indexes kv index to sync time map
	batchSize uint64

	statelessPeers map[string]struct{} // Peers that failed to deliver kv Data

	// These fields are internals used during runtime
	req map[uint64]*kvRequest  // Pending request to fill this task
	res map[uint64]*kvResponse // Validate response filling this task

	filled bool // Flag whether the task has been filled
	done   bool // Flag whether the task can be removed
}

func (t *kvTask) getKVIndexesForRequest(batch uint64) []uint64 {
	indexes := make([]uint64, 0)
	l := uint64(0)
	for idx, tm := range t.indexes {
		if time.Now().UnixMilli()-tm > requestTimeoutInMillisecond.Milliseconds() {
			indexes = append(indexes, idx)
			l++
		}
		if l >= batch {
			break
		}
	}

	return indexes
}

// SyncProgress is a database entry to allow suspending and resuming a sstorage state
// sync. Opposed to full and fast sync, there is no way to restart a suspended
// sstorage sync without prior knowledge of the suspension point.
type SyncProgress struct {
	Tasks []*kvTask // The suspended kv tasks

	// Status report during syncing phase
	KVSynced uint64             // Number of kvs downloaded
	KVBytes  common.StorageSize // Number of kv bytes downloaded
}

// SyncPeer abstracts out the methods required for a peer to be synced against
// with the goal of allowing the construction of mock peers without the full
// blown networking.
type SyncPeer interface {
	// ID retrieves the peer's unique identifier.
	ID() string

	// IsShardExist is the peer support this shardId
	IsShardExist(contract common.Address, shardId uint64) bool

	// RequestKVs fetches a batch of kvs with a kv list
	RequestKVs(id uint64, contract common.Address, shardId uint64, kvList []uint64) error

	// RequestShardList fetches shard list support by the peer
	RequestShardList(shards map[common.Address][]uint64) error

	// Log retrieves the peer's own contextual logger.
	Log() log.Logger

	LogPeerInfo()
}

type BlockChain interface {
	StateAt(root common.Hash) (*state.StateDB, error)

	CurrentBlock() *types.Block

	LockInsertChain()

	UnlockInsertChain()
}

// Syncer is a sstorage syncer based the sstorage protocol. It's purpose is to
// download all kvs from remote peers.
//
// Every network request has a variety of failure events:
//   - The peer disconnects after task assignment, failing to send the request
//   - The peer disconnects after sending the request, before delivering on it
//   - The peer remains connected, but does not deliver a response in time
//   - The peer delivers a stale response after a previous timeout
//   - The peer delivers a refusal to serve the requested state
type Syncer struct {
	db    ethdb.KeyValueStore // Database to store the sync state
	chain BlockChain
	tasks []*kvTask

	sstorageInfo map[common.Address][]uint64 // Map for contract address to support shardIds
	syncDone     bool                        // Flag to signal that sstorage phase is done
	update       chan struct{}               // Notification channel for possible sync progression

	peers map[string]SyncPeer // Currently active peers to download from

	peerJoin *event.Feed       // Event feed to react to peers joining
	peerDrop *event.Feed       // Event feed to react to peers dropping
	rates    *msgrate.Trackers // Message throughput rates for peers

	// Request tracking during syncing phase
	kvIdlers map[string]struct{}   // Peers that aren't serving kv requests
	kvReqs   map[uint64]*kvRequest // KV requests currently running

	kvSynced  uint64             // Number of kvs downloaded
	kvBytes   common.StorageSize // Number of kv bytes downloaded
	kvSyncing uint64             // Number of kvs downloading

	startTime time.Time // Time instance when sstorage sync started
	logTime   time.Time // Time instance when status was last reported

	pend sync.WaitGroup // Tracks network request goroutines for graceful shutdown
	lock sync.RWMutex   // Protects fields that can change outside of sync (peers, reqs, root)
	once sync.Once      // make loadSyncStatus run once
}

// NewSyncer creates a new sstorage syncer to download the sharded storage content over the sstorage protocol.
func NewSyncer(db ethdb.KeyValueStore, chain BlockChain, sstorageInfo map[common.Address][]uint64) *Syncer {
	return &Syncer{
		db: db,

		tasks:        make([]*kvTask, 0),
		sstorageInfo: sstorageInfo,
		chain:        chain,

		peers:    make(map[string]SyncPeer),
		peerJoin: new(event.Feed),
		peerDrop: new(event.Feed),
		rates:    msgrate.NewTrackers(log.New("proto", "sstorage")),
		update:   make(chan struct{}, 1),

		kvIdlers: make(map[string]struct{}),
		kvReqs:   make(map[uint64]*kvRequest),
	}
}

// Register injects a new Data source into the syncer's peerset.
func (s *Syncer) Register(peer SyncPeer) error {
	// Make sure the peer is not registered yet
	id := peer.ID()

	s.lock.Lock()
	if _, ok := s.peers[id]; ok {
		log.Error("Sstorage peer already registered", "id", id)

		s.lock.Unlock()
		return errors.New("already registered")
	}
	s.peers[id] = peer
	s.rates.Track(id, msgrate.NewTracker(s.rates.MeanCapacities(), s.rates.MedianRoundTrip()))

	// Mark the peer as idle, even if no sync is running
	s.kvIdlers[id] = struct{}{}
	s.lock.Unlock()

	// Notify any active syncs that a new peer can be assigned Data
	s.peerJoin.Send(id)
	return nil
}

// Unregister injects a new Data source into the syncer's peerset.
func (s *Syncer) Unregister(id string) error {
	// Remove all traces of the peer from the registry
	s.lock.Lock()
	if _, ok := s.peers[id]; !ok {
		log.Error("Sstorage peer not registered", "id", id)

		s.lock.Unlock()
		return errors.New("not registered")
	}
	delete(s.peers, id)
	s.rates.Untrack(id)

	// Remove status markers, even if no sync is running
	for _, task := range s.tasks {
		delete(task.statelessPeers, id)
	}

	delete(s.kvIdlers, id)
	s.lock.Unlock()

	// Notify any active syncs that pending requests need to be reverted
	s.peerDrop.Send(id)
	return nil
}

// Sync starts (or resumes a previous) sync cycle to iterate over all the kvs
// for storage shards the node support and reconstruct the node storage.
// Previously downloaded segments will not be redownloaded of fixed.
func (s *Syncer) Sync(cancel chan struct{}) error {
	if s.startTime == (time.Time{}) {
		s.startTime = time.Now()
	}
	// Retrieve the previous sync status from LevelDB and abort if already synced
	s.once.Do(s.loadSyncStatus)
	if len(s.tasks) == 0 {
		log.Debug("Sstorage sync already completed")
		return nil
	}
	defer func() { // Persist any progress, independent of failure
		s.cleanKVTasks()
	}()

	for addr, ids := range s.sstorageInfo {
		log.Debug("Starting Sstorage sync cycle", "contract", addr.Hex(), "shards", ids)
	}

	// Whether sync completed or not, disregard any future packets
	defer func() {
		s.lock.Lock()
		s.kvReqs = make(map[uint64]*kvRequest)
		s.lock.Unlock()
		s.report(true)
	}()
	// Keep scheduling sync tasks
	peerJoin := make(chan string, 16)
	peerJoinSub := s.peerJoin.Subscribe(peerJoin)
	defer peerJoinSub.Unsubscribe()

	peerDrop := make(chan string, 16)
	peerDropSub := s.peerDrop.Subscribe(peerDrop)
	defer peerDropSub.Unsubscribe()

	// Create a set of unique channels for this sync cycle. We need these to be
	// ephemeral so a Data race doesn't accidentally deliver something stale on
	// a persistent channel across syncs
	var (
		kvReqFails = make(chan *kvRequest)
		kvResps    = make(chan *kvResponse)
		i          = 0
	)
	for {
		// Remove all completed tasks and terminate sync if everything's done
		s.cleanKVTasks()
		if len(s.tasks) == 0 {
			return nil
		}
		// Assign all the Data retrieval tasks to any free peers
		s.assignKVTasks(kvResps, kvReqFails, cancel)

		// Wait for something to happen
		select {
		case <-time.After(requestTimeoutInMillisecond):

		case <-s.update:
			// Something happened (new peer, delivery, timeout), recheck tasks
		case <-peerJoin:
			// A new peer joined, try to schedule it new tasks
		case id := <-peerDrop:
			s.revertRequests(id)
		case <-cancel:
			return ErrCancelled

		case req := <-kvReqFails:
			s.revertKVRequest(req)

		case res := <-kvResps:
			s.processKVResponse(res)
		}
		// Report stats if something meaningful happened
		s.report(false)
		i++
	}
}

// loadSyncStatus retrieves a previously aborted sync status from the database,
// or generates a fresh one if none is available.
func (s *Syncer) loadSyncStatus() {
	// Start a fresh sync for retrieval.
	s.kvSynced, s.kvBytes = 0, 0

	// create tasks
	for contract, shards := range s.sstorageInfo {
		sm := sstorage.ContractToShardManager[contract]
		for _, sid := range shards {
			task := kvTask{
				contract:       contract,
				shardId:        sid,
				batchSize:      maxRequestSize / sm.MaxKvSize(),
				indexes:        make(map[uint64]int64),
				statelessPeers: make(map[string]struct{}),
				filled:         false,
				done:           false,
			}

			s.tasks = append(s.tasks, &task)
		}
	}

	// fill in tasks async
	go func() {
		for true {
			log.Info("loadSyncStatus", "block number", s.chain.CurrentBlock().Number())
			stateDB, err := s.chain.StateAt(s.chain.CurrentBlock().Root())
			if err != nil {
				log.Error("load syc status failed, fail to get state DB.",
					"block number", s.chain.CurrentBlock().NumberU64(), "err", err.Error())
				time.Sleep(30 * time.Second)
				continue
			}
			for _, task := range s.tasks {
				sm := sstorage.ContractToShardManager[task.contract]
				cnt := 0
				for i := sm.KvEntries() * task.shardId; i < sm.KvEntries()*(task.shardId+1); i++ {
					_, meta, err := getSstorageMetadata(stateDB, task.contract, i)
					if err != nil {
						log.Warn("getSstorageMetadata", "err", err.Error())
						continue
					}
					if data, ok, err := sm.TryRead(i, int(meta.kvSize), common.BytesToHash(meta.hashInMeta)); ok && err == nil {
						kv := KV{i, data}
						if err := verifyKV(sm, &kv, meta, false); err == nil {
							continue
						}
					}
					task.indexes[i] = 0
					cnt++
				}
				log.Info("load task state.", "contract", task.contract.Hex(), "shard", task.shardId, "count", cnt)
				task.filled = true
				if len(task.indexes) == 0 {
					task.done = true
				}
			}
			log.Info("load task done.", "len", len(s.tasks))
			break
		}
	}()
	time.Sleep(100 * time.Millisecond)
}

// Progress returns the sstorage sync status statistics.
func (s *Syncer) Progress() (*SyncProgress, uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	progress := &SyncProgress{
		KVSynced: s.kvSynced,
		KVBytes:  s.kvBytes,
	}
	return progress, s.kvSyncing
}

// cleanKVTasks removes kv range retrieval tasks that have already been completed.
func (s *Syncer) cleanKVTasks() {
	// If the sync was already done before, don't even bother
	if len(s.tasks) == 0 {
		return
	}
	// Sync wasn't finished previously, check for any task that can be finalized
	for i := 0; i < len(s.tasks); i++ {
		if s.tasks[i].done {
			s.tasks = append(s.tasks[:i], s.tasks[i+1:]...)
			i--
		}
	}
	// If everything was just finalized, generate the account trie and start heal
	if len(s.tasks) == 0 {
		s.lock.Lock()
		s.syncDone = true
		s.lock.Unlock()

		// Push the final sync report
		s.report(true)
	}
}

// assignKVTasks attempts to match idle peers to pending code retrievals.
func (s *Syncer) assignKVTasks(success chan *kvResponse, fail chan *kvRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.kvIdlers) == 0 {
		return
	}
	idlers := make([]string, 0, len(s.kvIdlers))
	for id := range s.kvIdlers {
		idlers = append(idlers, id)
	}

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		// All the kvs are downloading, wait for request time or success
		batch := maxRequestSize / sstorage.ContractToShardManager[task.contract].MaxKvSize()
		indexes := task.getKVIndexesForRequest(batch)
		if len(indexes) == 0 {
			continue
		}
		// kvTask pending retrieval, try to find an idle peer. If no such peer
		// exists, we probably assigned tasks for all (or they are stateless).
		// Abort the entire assignment mechanism.
		if len(idlers) == 0 {
			return
		}
		var (
			peer SyncPeer = nil
		)
		for i, id := range idlers {
			p := s.peers[id]
			if _, ok := task.statelessPeers[id]; ok {
				continue
			}
			p.LogPeerInfo()
			if p.IsShardExist(task.contract, task.shardId) {
				peer = p
				if i < len(idlers)-1 {
					idlers = append(idlers[:i], idlers[i+1:]...)
				} else { // last one
					idlers = idlers[:i]
				}
				break
			}
		}
		if peer == nil {
			log.Info("peer for request no found", "contract", task.contract.Hex(), "shard id",
				task.shardId, "index len", len(task.indexes), "peers", len(s.peers), "idlers", len(idlers))
			return
		}

		// Matched a pending task to an idle peer, allocate a unique request id
		var reqid uint64
		for {
			reqid = uint64(rand.Int63())
			if reqid == 0 {
				continue
			}
			if _, ok := s.kvReqs[reqid]; ok {
				continue
			}
			break
		}

		req := &kvRequest{
			peer:     peer.ID(),
			id:       reqid,
			contract: task.contract,
			shardId:  task.shardId,
			indexes:  indexes,
			time:     time.Now(),
			deliver:  success,
			revert:   fail,
			cancel:   cancel,
			stale:    make(chan struct{}),
			task:     task,
		}
		req.timeout = time.AfterFunc(s.rates.TargetTimeout(), func() {
			peer.Log().Debug("KV request timed out", "reqid", reqid)
			s.rates.Update(peer.ID(), KVsMsg, 0, 0)
			s.scheduleRevertKVRequest(req)
		})
		s.kvReqs[reqid] = req
		delete(s.kvIdlers, peer.ID())

		s.pend.Add(1)
		go func() {
			defer s.pend.Done()

			// Attempt to send the remote request and revert if it fails
			if err := peer.RequestKVs(reqid, req.task.contract, req.shardId, req.indexes); err != nil {
				log.Debug("Failed to request kvs", "err", err)
				s.scheduleRevertKVRequest(req)
			}
		}()
		for _, idx := range indexes {
			task.indexes[idx] = time.Now().UnixMilli()
		}
	}
}

// revertRequests locates all the currently pending reuqests from a particular
// peer and reverts them, rescheduling for others to fulfill.
func (s *Syncer) revertRequests(peer string) {
	// Gather the requests first, revertals need the lock too
	s.lock.Lock()
	var kvReqs []*kvRequest
	for _, req := range s.kvReqs {
		if req.peer == peer {
			kvReqs = append(kvReqs, req)
		}
	}
	s.lock.Unlock()

	// Revert all the requests matching the peer
	for _, req := range kvReqs {
		s.revertKVRequest(req)
	}
}

// scheduleRevertKVRequest asks the event loop to clean up a kv request
// and return all failed retrieval tasks to the scheduler for reassignment.
func (s *Syncer) scheduleRevertKVRequest(req *kvRequest) {
	select {
	case req.revert <- req:
		// Sync event loop notified
	case <-req.cancel:
		// Sync cycle got cancelled
	case <-req.stale:
		// Request already reverted
	}
}

// revertKVRequest cleans up a kv request and returns all failed
// retrieval tasks to the scheduler for reassignment.
//
// Note, this needs to run on the event runloop thread to reschedule to idle peers.
// On peer threads, use scheduleRevertKVRequest.
func (s *Syncer) revertKVRequest(req *kvRequest) {
	log.Debug("Reverting kv request", "peer", req.peer)
	select {
	case <-req.stale:
		log.Trace("KV request already reverted", "peer", req.peer, "reqid", req.id)
		return
	default:
	}
	close(req.stale)

	// Remove the request from the tracked set
	s.lock.Lock()
	delete(s.kvReqs, req.id)
	s.lock.Unlock()

	// If there's a timeout timer still running, abort it and mark the code
	// retrievals as not-pending, ready for resheduling
	req.timeout.Stop()
	for _, index := range req.indexes {
		req.task.indexes[index] = 0
	}
}

// processKVResponse integrates an already validated kv response
// into the account tasks.
func (s *Syncer) processKVResponse(res *kvResponse) {
	var (
		synced      uint64
		syncedBytes uint64
	)
	if res.task.contract != res.contract {
		log.Error("processKVResponse fail: contract mismatch",
			"task", res.task.contract.Hex(), "res", res.contract.Hex())
		return
	}
	sm := sstorage.ContractToShardManager[res.contract]
	if sm == nil {
		log.Error("processKVResponse fail: contract not support",
			"res contract", res.contract.Hex())
		return
	}

	vkvs := make([]*VerifiedKV, 0)
	state, err := s.chain.StateAt(s.chain.CurrentBlock().Root())

	if err != nil {
		log.Error("processKVResponse: get state for verification fail", "error", err)
		return
	}

	for _, kv := range res.kvs {
		synced++
		syncedBytes += uint64(len(kv.Data))

		metaHash, meta, err := getSstorageMetadata(state, res.contract, kv.Idx)
		if err != nil || meta == nil {
			log.Warn("processKVResponse: get vkv MetaHash for verification fail", "error", err)
			continue
		}

		err = verifyKV(sm, kv, meta, true)
		if err != nil {
			log.Warn("processKVResponse: verify vkv fail", "error", err)
			continue
		}
		vkvs = append(vkvs, &VerifiedKV{kv.Idx, kv.Data, metaHash})
	}

	s.chain.LockInsertChain()
	defer s.chain.UnlockInsertChain()

	successCount, root, st := 0, s.chain.CurrentBlock().Root(), time.Now()
	state, err = s.chain.StateAt(root)
	if err != nil {
		log.Error("processKVResponse: get state for write vkv fail", "error", err)
		return
	}

	for _, vkv := range vkvs {
		metaHash, meta, err := getSstorageMetadata(state, res.contract, vkv.Idx)
		if err != nil || meta == nil {
			log.Warn("processKVResponse: get vkv MetaHash for write vkv fail", "error", err)
			continue
		}

		if metaHash != vkv.MetaHash {
			log.Warn("processKVResponse: verify vkv fail", "error", err)
			continue
		}

		success, err := sm.TryWriteMaskedKV(vkv.Idx, vkv.Data)
		if !success || err != nil {
			res.task.indexes[vkv.Idx] = 0
		} else {
			delete(res.task.indexes, vkv.Idx)
			successCount++
		}
	}

	// set peer to stateless peer if fail too much
	req, ok := res.task.req[res.reqId]
	if successCount == 0 && ok {
		res.task.statelessPeers[req.peer] = struct{}{}
	}

	s.kvSynced += synced
	s.kvBytes += common.StorageSize(syncedBytes)
	log.Info("Persisted set of kvs", "count", synced, "bytes", syncedBytes, "time (Milliseconds)", time.Since(st).Milliseconds())

	// If this delivery completed the last pending task, forward the account task
	// to the next vkv
	if len(res.task.indexes) == 0 && res.task.filled {
		log.Info("task done", "shardId", res.task.shardId)
		res.task.done = true
	}
	log.Debug("remain index for sync", "shardId", res.task.shardId, "len", len(res.task.indexes))
}

type metadata struct {
	kvIdx      uint64
	kvSize     uint64
	hashInMeta []byte
}

// verifyKV verify kv using metadata
func verifyKV(sm *sstorage.ShardManager, kv *KV, meta *metadata, isMasked bool) error {
	if kv.Idx != meta.kvIdx {
		return fmt.Errorf("verifyKV fail: kvIdx mismatch; kv Idx: %d; MetaHash kvIdx: %d", kv.Idx, meta.kvIdx)
	}

	data := make([]byte, len(kv.Data))
	copy(data, kv.Data)
	if isMasked {
		if sm == nil {
			return fmt.Errorf("empty sm to verify KV")
		}
		d, r, err := sm.UnmaskKV(meta.kvIdx, data, common.BytesToHash(meta.hashInMeta))
		if !r || err != nil {
			return fmt.Errorf("Unmask KV fail, err: %v", err)
		}

		if meta.kvSize != uint64(len(data)) {
			return fmt.Errorf("verifyKV fail: size error; Data size: %d; MetaHash kvSize: %d", len(kv.Data), meta.kvSize)
		}
		data = d
	}

	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hasher.Write(data)
	hash := common.Hash{}
	hasher.Read(hash[:])

	if bytes.Compare(hash[:24], meta.hashInMeta) != 0 {
		return fmt.Errorf("verifyKV fail: size error; Data hash: %s; MetaHash hash (24): %s",
			common.Bytes2Hex(hash[:24]), common.Bytes2Hex(meta.hashInMeta))
	}

	return nil
}

// getSlotHash generate slot hash to fetch Data from stateDB
func getSlotHash(slotIdx uint64, key common.Hash) common.Hash {
	slot := uint256.NewInt(slotIdx).Bytes32()

	keydata := key.Bytes()
	slotdata := slot[:]
	data := append(keydata, slotdata...)

	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hasher.Write(data)

	hashRes := common.Hash{}
	hasher.Read(hashRes[:])

	return hashRes
}

func getSstorageMetadata(s *state.StateDB, contract common.Address, index uint64) (common.Hash, *metadata, error) {
	// according to https://github.com/web3q/web3q-contracts/blob/main/contracts/DecentralizedKV.sol,
	// it need to fetch the skey from idxMap (slot 6) using storage index,
	// then get metadata from kvMap (slot 5) using skey. the metadata struct is as following
	// struct PhyAddr {
	// 	uint40 kvIdx;
	// 	uint24 kvSize;
	// 	bytes24 hash;
	// }
	position := getSlotHash(2, uint256.NewInt(index).Bytes32())
	skey := s.GetState(contract, position)
	if skey == emptyHash {
		return emptyHash, nil, fmt.Errorf("fail to get skey for index %d", index)
	}

	position = getSlotHash(1, skey)
	meta := s.GetState(contract, position)
	if meta == emptyHash {
		return emptyHash, nil, fmt.Errorf("fail to get metadata for skey %s", skey.Hex())
	}

	return meta, &metadata{
			new(big.Int).SetBytes(meta[27:]).Uint64(),
			new(big.Int).SetBytes(meta[24:27]).Uint64(),
			meta[:24]},
		nil
}

// OnKVs is a callback method to invoke when a batch of contract
// bytes codes are received from a remote peer.
func (s *Syncer) OnKVs(peer SyncPeer, id uint64, kvs []*KV) error {
	var size common.StorageSize
	for _, kv := range kvs {
		if kv != nil {
			size += common.StorageSize(len(kv.Data))
		}
	}
	logger := peer.Log().New("reqid", id)
	logger.Trace("Delivering set of kvs", "kvs", len(kvs), "bytes", size)

	// Whether or not the response is valid, we can mark the peer as idle and
	// notify the scheduler to assign a new task. If the response is invalid,
	// we'll drop the peer in a bit.
	s.lock.Lock()
	if _, ok := s.peers[peer.ID()]; ok {
		s.kvIdlers[peer.ID()] = struct{}{}
	}
	select {
	case s.update <- struct{}{}:
	default:
	}
	// Ensure the response is for a valid request
	req, ok := s.kvReqs[id]
	if !ok {
		// Request stale, perhaps the peer timed out but came through in the end
		logger.Warn("Unexpected kv packet")
		s.lock.Unlock()
		return nil
	}
	delete(s.kvReqs, id)
	s.rates.Update(peer.ID(), KVsMsg, time.Since(req.time), len(kvs))

	// Clean up the request timeout timer, we'll see how to proceed further based
	// on the actual delivered content
	if !req.timeout.Stop() {
		// The timeout is already triggered, and this request will be reverted+rescheduled
		s.lock.Unlock()
		return nil
	}

	// get id range and check range
	sm := sstorage.ContractToShardManager[req.contract]
	if sm == nil {
		logger.Debug("Peer rejected kv request")
		req.task.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVRequest(req)
		return nil
	}
	startIdx, endIdx := sm.KvEntries()*req.shardId, sm.KvEntries()*(req.shardId+1)-1
	kvInRange := make([]*KV, 0)
	for _, kv := range kvs {
		if startIdx <= kv.Idx && endIdx >= kv.Idx {
			kvInRange = append(kvInRange, kv)
		}
	}
	if len(kvs) > len(kvInRange) {
		logger.Warn("Drop unexpected kvs", "count", len(kvs)-len(kvInRange))
	}

	// Response is valid, but check if peer is signalling that it does not have
	// the requested Data. For kv range queries that means the peer is not
	// yet synced.
	if len(kvInRange) == 0 {
		logger.Debug("Peer rejected kv request")
		req.task.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Response validated, send it to the scheduler for filling
	response := &kvResponse{
		task:     req.task,
		reqId:    req.id,
		contract: req.contract,
		shardId:  req.shardId,
		kvs:      kvs,
	}
	select {
	case req.deliver <- response:
	case <-req.cancel:
	case <-req.stale:
	}
	return nil
}

// report calculates various status reports and provides it to the user.
func (s *Syncer) report(force bool) {
	// Don't report anything until we have a meaningful progress
	synced := s.kvSynced
	if synced == 0 {
		return
	}
	kvsToSync := uint64(0)
	for _, task := range s.tasks {
		kvsToSync = kvsToSync + uint64(len(task.indexes))
	}
	s.logTime = time.Now()

	elapsed := time.Since(s.startTime)
	estTime := elapsed / time.Duration(synced) * time.Duration(kvsToSync+synced)

	// Create a mega progress report
	var (
		progress = fmt.Sprintf("%.2f%%", float64(synced)*100/float64(kvsToSync+synced))
		kv       = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.kvSynced), s.kvBytes.TerminalString())
	)
	log.Info("State sync in progress", "synced", progress, "state", synced,
		"kv", kv, "eta", common.PrettyDuration(estTime-elapsed))
}
