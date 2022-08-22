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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/msgrate"
	"github.com/ethereum/go-ethereum/sstorage"
)

// todo
const (
	// minSstoragePeer is the minimum number of peers for each shard.
	minSstoragePeers = 16

	// maxRequestSize is the maximum number of bytes to request from a remote peer.
	// This number is used as the high cap for chunk range requests.
	maxRequestSize = uint64(512 * 1024)

	requestTimeoutInSecond = 30 // Second
)

// ErrCancelled is returned from sstorage syncing if the operation was prematurely
// terminated.
var ErrCancelled = errors.New("sync cancelled")

var emptyHash = common.Hash{}

// chunkRequest tracks a pending chunk request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: chunk requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the data to
// construct the response without accessing runloop internals (i.e. task). That
// is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type chunkRequest struct {
	peer string    // Peer to which this request is assigned
	id   uint64    // Request ID of this request
	time time.Time // Timestamp when the request was sent

	deliver chan *chunkResponse // Channel to deliver successful response on
	revert  chan *chunkRequest  // Channel to deliver request failure on
	cancel  chan struct{}       // Channel to track sync cancellation
	timeout *time.Timer         // Timer to track delivery timeout
	stale   chan struct{}       // Channel to signal the request was dropped

	contract common.Address
	shardId  uint64
	indexes  []uint64

	task *chunkTask // chunkTask which this request is filling (only access fields through the runloop!!)
}

// chunkResponse is an already verified remote response to a chunk request.
type chunkResponse struct {
	reqId    uint64         // Request ID of this response
	task     *chunkTask     // chunkTask which this request is filling
	contract common.Address // contract
	shardId  uint64         // shardId
	chunks   []*Chunk       // chunks to store into the sharded storage
}

// chunkTask represents the sync task for a sstorage shard.
type chunkTask struct {
	// These fields get serialized to leveldb on shutdown
	contract  common.Address   // contract address
	shardId   uint64           // shardId
	indexes   map[uint64]int64 // indexes chunk index to sync time map
	batchSize uint64

	// These fields are internals used during runtime
	req map[uint64]*chunkRequest  // Pending request to fill this task
	res map[uint64]*chunkResponse // Validate response filling this task

	done bool // Flag whether the task can be removed
}

func (t *chunkTask) getChunkIndexesForRequest() []uint64 {
	indexes := make([]uint64, 0)
	for idx, t := range t.indexes {
		if time.Now().Unix()-t > requestTimeoutInSecond {
			indexes = append(indexes, idx)
		}
	}

	return indexes
}

// SyncProgress is a database entry to allow suspending and resuming a sstorage state
// sync. Opposed to full and fast sync, there is no way to restart a suspended
// sstorage sync without prior knowledge of the suspension point.
type SyncProgress struct {
	Tasks []*chunkTask // The suspended chunk tasks

	// Status report during syncing phase
	ChunkSynced uint64             // Number of chunks downloaded
	ChunkBytes  common.StorageSize // Number of chunk bytes downloaded
}

// SyncPeer abstracts out the methods required for a peer to be synced against
// with the goal of allowing the construction of mock peers without the full
// blown networking.
type SyncPeer interface {
	// ID retrieves the peer's unique identifier.
	ID() string

	// IsShardExist is the peer support this shardId
	IsShardExist(contract common.Address, shardId uint64) bool

	// RequestChunks fetches a batch of chunks ranging between startIdx and endIdx
	RequestChunks(id uint64, contract common.Address, shardId uint64, chunkList []uint64) error

	// Log retrieves the peer's own contextual logger.
	Log() log.Logger
}

type BlockChain interface {
	StateAt(root common.Hash) (*state.StateDB, error)

	CurrentBlock() *types.Block
}

// Syncer is a sstorage syncer based the sstorage protocol. It's purpose is to
// download all chunks from remote peers.
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
	tasks []*chunkTask

	sstorageInfo map[common.Address][]uint64 // Map for contract address to support shardIds
	syncDone     bool                        // Flag to signal that sstorage phase is done
	update       chan struct{}               // Notification channel for possible sync progression

	peers map[string]SyncPeer // Currently active peers to download from

	peerJoin *event.Feed       // Event feed to react to peers joining
	peerDrop *event.Feed       // Event feed to react to peers dropping
	rates    *msgrate.Trackers // Message throughput rates for peers

	// Request tracking during syncing phase
	statelessPeers map[string]struct{} // Peers that failed to deliver chunk data
	chunkIdlers    map[string]struct{} // Peers that aren't serving chunk requests

	chunkReqs map[uint64]*chunkRequest // Chunk requests currently running

	chunkSynced  uint64             // Number of chunks downloaded
	chunkBytes   common.StorageSize // Number of chunk bytes downloaded
	chunkSyncing uint64             // Number of chunks downloading

	stateWriter ethdb.Batch // Shared batch writer used for persisting raw states

	startTime time.Time // Time instance when sstorage sync started
	logTime   time.Time // Time instance when status was last reported

	pend sync.WaitGroup // Tracks network request goroutines for graceful shutdown
	lock sync.RWMutex   // Protects fields that can change outside of sync (peers, reqs, root)
}

// NewSyncer creates a new sstorage syncer to download the sharded storage content over the sstorage protocol.
func NewSyncer(db ethdb.KeyValueStore, chain BlockChain, sstorageInfo map[common.Address][]uint64) *Syncer {
	return &Syncer{
		db: db,

		tasks:        make([]*chunkTask, 0),
		sstorageInfo: sstorageInfo,

		peers:    make(map[string]SyncPeer),
		peerJoin: new(event.Feed),
		peerDrop: new(event.Feed),
		rates:    msgrate.NewTrackers(log.New("proto", "sstorage")),
		update:   make(chan struct{}, 1),

		chunkIdlers: make(map[string]struct{}),
		chunkReqs:   make(map[uint64]*chunkRequest),
		stateWriter: db.NewBatch(),
	}
}

// Register injects a new data source into the syncer's peerset.
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
	s.chunkIdlers[id] = struct{}{}
	s.lock.Unlock()

	// Notify any active syncs that a new peer can be assigned data
	s.peerJoin.Send(id)
	return nil
}

// Unregister injects a new data source into the syncer's peerset.
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
	delete(s.statelessPeers, id)

	delete(s.chunkIdlers, id)
	s.lock.Unlock()

	// Notify any active syncs that pending requests need to be reverted
	s.peerDrop.Send(id)
	return nil
}

// Sync starts (or resumes a previous) sync cycle to iterate over all the chunks
// for storage shards the node support and reconstruct the node storage.
// Previously downloaded segments will not be redownloaded of fixed.
func (s *Syncer) Sync(shards map[common.Address][]uint64, cancel chan struct{}) error {
	// Revert stateless markers for any peers and initialize the syncer if it was not yet run
	s.lock.Lock()

	s.statelessPeers = make(map[string]struct{})
	s.lock.Unlock()

	if s.startTime == (time.Time{}) {
		s.startTime = time.Now()
	}
	// Retrieve the previous sync status from LevelDB and abort if already synced
	s.loadSyncStatus()
	if len(s.tasks) == 0 {
		log.Debug("Sstorage sync already completed")
		return nil
	}
	defer func() { // Persist any progress, independent of failure
		s.cleanChunkTasks()
		s.saveSyncStatus()
	}()

	for addr, ids := range shards {
		log.Debug("Starting Sstorage sync cycle", "contract", addr.Hex(), "shards", ids)
	}

	defer s.report(true)

	// Whether sync completed or not, disregard any future packets
	defer func() {
		for addr, ids := range shards {
			log.Debug("Terminating Sstorage sync cycle", "contract", addr.Hex(), "shards", ids)
		}
		s.lock.Lock()
		s.chunkReqs = make(map[uint64]*chunkRequest)
		s.lock.Unlock()
	}()
	// Keep scheduling sync tasks
	peerJoin := make(chan string, 16)
	peerJoinSub := s.peerJoin.Subscribe(peerJoin)
	defer peerJoinSub.Unsubscribe()

	peerDrop := make(chan string, 16)
	peerDropSub := s.peerDrop.Subscribe(peerDrop)
	defer peerDropSub.Unsubscribe()

	// Create a set of unique channels for this sync cycle. We need these to be
	// ephemeral so a data race doesn't accidentally deliver something stale on
	// a persistent channel across syncs
	var (
		chunkReqFails = make(chan *chunkRequest)
		chunkResps    = make(chan *chunkResponse)
	)
	for {
		// Remove all completed tasks and terminate sync if everything's done
		s.cleanChunkTasks()
		if len(s.tasks) == 0 {
			return nil
		}
		// Assign all the data retrieval tasks to any free peers
		s.assignChunkTasks(chunkResps, chunkReqFails, cancel)

		// Wait for something to happen
		select {
		case <-s.update:
			// Something happened (new peer, delivery, timeout), recheck tasks
		case <-peerJoin:
			// A new peer joined, try to schedule it new tasks
		case id := <-peerDrop:
			s.revertRequests(id)
		case <-cancel:
			return ErrCancelled

		case req := <-chunkReqFails:
			s.revertChunkRequest(req)

		case res := <-chunkResps:
			s.processChunkResponse(res)
		}
		// Report stats if something meaningful happened
		s.report(false)
	}
}

// loadSyncStatus retrieves a previously aborted sync status from the database,
// or generates a fresh one if none is available.
func (s *Syncer) loadSyncStatus() {
	var progress SyncProgress

	if status := rawdb.ReadSstorageSyncStatus(s.db); status != nil {
		if err := json.Unmarshal(status, &progress); err != nil {
			log.Error("Failed to decode sstorage sync status", "err", err)
		} else {
			for _, task := range progress.Tasks {
				log.Debug("Scheduled sstorage sync task", "contract", task.contract.Hex(),
					"shard", task.shardId, "count", len(task.indexes))
			}
			s.tasks = progress.Tasks
			s.syncDone = len(s.tasks) == 0

			s.chunkSynced = progress.ChunkSynced
			s.chunkBytes = progress.ChunkBytes
			return
		}
	}
	// Either we've failed to decode the previus state, or there was none.
	// Start a fresh sync for retrieval.
	s.chunkSynced, s.chunkBytes = 0, 0

	for contract, shards := range s.sstorageInfo {
		for _, id := range shards {
			sm := sstorage.ContractToShardManager[contract]
			task := chunkTask{
				contract:  contract,
				shardId:   id,
				batchSize: maxRequestSize / sm.MaxKvSize(),
				indexes:   make(map[uint64]int64),
			}
			for i := sm.KvEntries() * id; i < sm.KvEntries()*(id+1); i++ {
				task.indexes[i] = 0
			}

			s.tasks = append(s.tasks, &task)
		}
	}
}

// saveSyncStatus marshals the remaining sync tasks into leveldb.
func (s *Syncer) saveSyncStatus() {
	// Store the actual progress markers
	progress := &SyncProgress{
		Tasks:       s.tasks,
		ChunkSynced: s.chunkSynced,
		ChunkBytes:  s.chunkBytes,
	}
	status, err := json.Marshal(progress)
	if err != nil {
		panic(err) // This can only fail during implementation
	}
	rawdb.WriteSstorageSyncStatus(s.db, status)
}

// Progress returns the snap sync status statistics.
func (s *Syncer) Progress() (*SyncProgress, uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	progress := &SyncProgress{
		ChunkSynced: s.chunkSynced,
		ChunkBytes:  s.chunkBytes,
	}
	return progress, s.chunkSyncing
}

// cleanChunkTasks removes chunk range retrieval tasks that have already been completed.
func (s *Syncer) cleanChunkTasks() {
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

// assignChunkTasks attempts to match idle peers to pending code retrievals.
func (s *Syncer) assignChunkTasks(success chan *chunkResponse, fail chan *chunkRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Sort the peers by download capacity to use faster ones if many available
	idlers := make([]string, 0, len(s.chunkIdlers))
	for id := range s.chunkIdlers {
		if _, ok := s.statelessPeers[id]; ok {
			continue
		}
		idlers = append(idlers, id)
	}
	if len(idlers) == 0 {
		return
	}

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		// All the chunks are downloading, wait for request time or success
		indexes := task.getChunkIndexesForRequest()
		if len(indexes) == 0 {
			continue
		}
		// chunkTask pending retrieval, try to find an idle peer. If no such peer
		// exists, we probably assigned tasks for all (or they are stateless).
		// Abort the entire assignment mechanism.
		if len(idlers) == 0 {
			return
		}

		var (
			idle = idlers[0]
			peer = s.peers[idle]
		)
		for i, id := range idlers {
			p := s.peers[id]
			if p.IsShardExist(task.contract, task.shardId) {
				peer = p
				idlers = append(idlers[:i], idlers[i+1:]...)
			}
		}

		// Matched a pending task to an idle peer, allocate a unique request id
		var reqid uint64
		for {
			reqid = uint64(rand.Int63())
			if reqid == 0 {
				continue
			}
			if _, ok := s.chunkReqs[reqid]; ok {
				continue
			}
			break
		}

		req := &chunkRequest{
			peer:     idle,
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
			peer.Log().Debug("Chunk request timed out", "reqid", reqid)
			s.rates.Update(idle, ChunksMsg, 0, 0)
			s.scheduleRevertChunkRequest(req)
		})
		s.chunkReqs[reqid] = req
		delete(s.chunkIdlers, idle)

		s.pend.Add(1)
		go func() {
			defer s.pend.Done()

			// Attempt to send the remote request and revert if it fails
			if err := peer.RequestChunks(reqid, req.task.contract, req.shardId, req.indexes); err != nil {
				log.Debug("Failed to request chunks", "err", err)
				s.scheduleRevertChunkRequest(req)
			}
		}()
	}
}

// revertRequests locates all the currently pending reuqests from a particular
// peer and reverts them, rescheduling for others to fulfill.
func (s *Syncer) revertRequests(peer string) {
	// Gather the requests first, revertals need the lock too
	s.lock.Lock()
	var chunkReqs []*chunkRequest
	for _, req := range s.chunkReqs {
		if req.peer == peer {
			chunkReqs = append(chunkReqs, req)
		}
	}
	s.lock.Unlock()

	// Revert all the requests matching the peer
	for _, req := range chunkReqs {
		s.revertChunkRequest(req)
	}
}

// scheduleRevertChunkRequest asks the event loop to clean up a chunk request
// and return all failed retrieval tasks to the scheduler for reassignment.
func (s *Syncer) scheduleRevertChunkRequest(req *chunkRequest) {
	select {
	case req.revert <- req:
		// Sync event loop notified
	case <-req.cancel:
		// Sync cycle got cancelled
	case <-req.stale:
		// Request already reverted
	}
}

// revertChunkRequest cleans up a chunk request and returns all failed
// retrieval tasks to the scheduler for reassignment.
//
// Note, this needs to run on the event runloop thread to reschedule to idle peers.
// On peer threads, use scheduleRevertChunkRequest.
func (s *Syncer) revertChunkRequest(req *chunkRequest) {
	log.Debug("Reverting chunk request", "peer", req.peer)
	select {
	case <-req.stale:
		log.Trace("Chunk request already reverted", "peer", req.peer, "reqid", req.id)
		return
	default:
	}
	close(req.stale)

	// Remove the request from the tracked set
	s.lock.Lock()
	delete(s.chunkReqs, req.id)
	s.lock.Unlock()

	// If there's a timeout timer still running, abort it and mark the code
	// retrievals as not-pending, ready for resheduling
	req.timeout.Stop()
	for _, index := range req.indexes {
		req.task.indexes[index] = 0
	}
}

// processChunkResponse integrates an already validated chunk response
// into the account tasks.
func (s *Syncer) processChunkResponse(res *chunkResponse) {
	var (
		synced      uint64
		syncedBytes uint64
	)
	if res.task.contract != res.contract {
		log.Error("processChunkResponse fail: contract mismatch",
			"task", res.task.contract.Hex(), "res", res.contract.Hex())
		return
	}
	sm := sstorage.ContractToShardManager[res.contract]
	if sm == nil {
		log.Error("processChunkResponse fail: contract not support",
			"res contract", res.contract.Hex())
		return
	}
	state, err := s.chain.StateAt(s.chain.CurrentBlock().Hash())
	if err != nil {
		log.Error("processChunkResponse get state fail", "error", err)
		return
	}

	successCount, failureCount := 0, 0
	for _, chunk := range res.chunks {
		// 1. get chunk meta
		// 2. verify chunk
		// 3.1. if pass, write to storage and delete(res.task.indexes, idx)
		// 3.2. if fail, set res.task.indexes[idx] = 0
		synced++
		syncedBytes += uint64(len(chunk.data))

		meta, err := getSstorageMetadata(state, res.contract, chunk.idx)
		if err != nil || meta == nil {
			log.Warn("processChunkResponse get chunk meta fail", "error", err)
			failureCount++
			continue
		}

		err = verifyChunk(chunk, meta)
		if err != nil {
			log.Warn("processChunkResponse verify chunk fail", "error", err)
			failureCount++
			continue
		}

		success, err := sm.TryWrite(chunk.idx, chunk.data)
		if !success || err != nil {
			res.task.indexes[chunk.idx] = 0
			failureCount++
		} else {
			delete(res.task.indexes, chunk.idx)
			successCount++
		}
	}

	// set peer to stateless peer if fail too much
	if req, ok := res.task.req[res.reqId]; successCount == 0 && ok {
		s.statelessPeers[req.peer] = struct{}{}
	}

	s.chunkSynced += synced
	s.chunkBytes += common.StorageSize(syncedBytes)
	log.Debug("Persisted set of chunks", "count", synced, "bytes", syncedBytes)

	// If this delivery completed the last pending task, forward the account task
	// to the next chunk
	if len(res.task.indexes) == 0 {
		res.task.done = true
	}
}

type metadata struct {
	kvIdx      uint64
	kvSize     uint64
	hashInMeta []byte
}

// verifyChunk verify chunk using metadata
func verifyChunk(chunk *Chunk, meta *metadata) error {
	if chunk.idx != meta.kvIdx {
		return fmt.Errorf("verifyChunk fail: kvIdx mismatch", "chunk Idx", chunk.idx, "meta kvIdx", meta.kvIdx)
	}

	if meta.kvSize > uint64(len(chunk.data)) {
		return fmt.Errorf("verifyChunk fail: size error", "data size", len(chunk.data), "meta kvSize", meta.kvSize)
	}

	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hasher.Write(chunk.data[:meta.kvSize])
	hash := common.Hash{}
	hasher.Read(hash[:])

	if bytes.Compare(hash[:24], meta.hashInMeta) != 0 {
		return fmt.Errorf("verifyChunk fail: size error",
			"data hash", hash.Hex(), "meta hash (24)", common.Bytes2Hex(meta.hashInMeta))
	}

	return nil
}

// getSlotHash generate slot hash to fetch data from stateDB
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

func getSstorageMetadata(s *state.StateDB, contract common.Address, index uint64) (*metadata, error) {
	// according to https://github.com/web3q/web3q-contracts/blob/main/contracts/DecentralizedKV.sol,
	// it need to fetch the skey from idxMap (slot 6) using storage index,
	// then get metadata from kvMap (slot 5) using skey. the metadata struct is as following
	// struct PhyAddr {
	// 	uint40 kvIdx;
	// 	uint24 kvSize;
	// 	bytes24 hash;
	// }
	key := getSlotHash(6, uint256.NewInt(index).Bytes32())
	skey := s.GetState(contract, key)
	if skey == emptyHash {
		return nil, fmt.Errorf("Fail to get skey", "index", index)
	}

	key = getSlotHash(5, skey)
	meta := s.GetState(contract, key)
	if skey == emptyHash {
		return nil, fmt.Errorf("Fail to get metadata", "skey", skey)
	}

	return &metadata{binary.BigEndian.Uint64(meta[:5]), binary.BigEndian.Uint64(meta[5:8]), meta[8:]}, nil
}

// OnChunks is a callback method to invoke when a batch of contract
// bytes codes are received from a remote peer.
func (s *Syncer) OnChunks(peer SyncPeer, id uint64, chunks []*Chunk) error {
	var size common.StorageSize
	for _, chunk := range chunks {
		size += common.StorageSize(len(chunk.data))
	}
	logger := peer.Log().New("reqid", id)
	logger.Trace("Delivering set of chunks", "chunks", len(chunks), "bytes", size)

	// Whether or not the response is valid, we can mark the peer as idle and
	// notify the scheduler to assign a new task. If the response is invalid,
	// we'll drop the peer in a bit.
	s.lock.Lock()
	if _, ok := s.peers[peer.ID()]; ok {
		s.chunkIdlers[peer.ID()] = struct{}{}
	}
	select {
	case s.update <- struct{}{}:
	default:
	}
	// Ensure the response is for a valid request
	req, ok := s.chunkReqs[id]
	if !ok {
		// Request stale, perhaps the peer timed out but came through in the end
		logger.Warn("Unexpected chunk packet")
		s.lock.Unlock()
		return nil
	}
	delete(s.chunkReqs, id)
	s.rates.Update(peer.ID(), ChunksMsg, time.Since(req.time), len(chunks))

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
		logger.Debug("Peer rejected chunk request")
		s.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkRequest(req)
		return nil
	}
	startIdx, endIdx := sm.KvEntries()*req.shardId, sm.KvEntries()*(req.shardId+1)-1
	chunkInRange := make([]*Chunk, 0)
	for _, chunk := range chunks {
		if startIdx <= chunk.idx && endIdx >= chunk.idx {
			chunkInRange = append(chunkInRange, chunk)
		}
	}
	if len(chunks) > len(chunkInRange) {
		logger.Warn("Drop unexpected chunks", "count", len(chunks)-len(chunkInRange))
	}

	// Response is valid, but check if peer is signalling that it does not have
	// the requested data. For chunk range queries that means the peer is not
	// yet synced.
	if len(chunkInRange) == 0 {
		logger.Debug("Peer rejected chunk request")
		s.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Response validated, send it to the scheduler for filling
	response := &chunkResponse{
		task:     req.task,
		reqId:    req.id,
		contract: req.contract,
		shardId:  req.shardId,
		chunks:   chunks,
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
	// Don't report all the events, just occasionally
	if !force && time.Since(s.logTime) < 8*time.Second {
		return
	}
	// Don't report anything until we have a meaningful progress
	synced := s.chunkSynced
	if synced == 0 {
		return
	}
	chunksToSync := uint64(0)
	for _, task := range s.tasks {
		chunksToSync = chunksToSync + uint64(len(task.indexes))
	}
	s.logTime = time.Now()

	elapsed := time.Since(s.startTime)
	estTime := elapsed / time.Duration(synced) * time.Duration(chunksToSync+synced)

	// Create a mega progress report
	var (
		progress = fmt.Sprintf("%.2f%%", float64(synced)*100/float64(chunksToSync+synced))
		chunk    = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.chunkSynced), s.chunkBytes.TerminalString())
	)
	log.Info("State sync in progress", "synced", progress, "state", synced,
		"chunk", chunk, "eta", common.PrettyDuration(estTime-elapsed))
}
