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
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/msgrate"
	"github.com/ethereum/go-ethereum/sstorage"
)

const (
	// maxRequestSize is the maximum number of bytes to request from a remote peer.
	// This number is used as the high cap for kv range requests.
	maxRequestSize = uint64(512 * 1024)

	maxConcurrency = 16

	minSubTaskSize = 16
)

// ErrCancelled is returned from sstorage syncing if the operation was prematurely
// terminated.
var ErrCancelled = errors.New("sync cancelled")

var (
	maxEmptyTaskTreads          int
	empty                       = make([]byte, 0)
	requestTimeoutInMillisecond = 1000 * time.Millisecond // Millisecond
)

// kvRangeRequest tracks a pending kv request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: kv requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the Data to
// construct the response without accessing runloop internals (i.e. task). That
// is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type kvRangeRequest struct {
	peer string    // Peer to which this request is assigned
	id   uint64    // Request ID of this request
	time time.Time // Timestamp when the request was sent

	deliver chan *kvRangeResponse // Channel to deliver successful response on
	revert  chan *kvRangeRequest  // Channel to deliver request failure on
	cancel  chan struct{}         // Channel to track sync cancellation
	timeout *time.Timer           // Timer to track delivery timeout
	stale   chan struct{}         // Channel to signal the request was dropped

	contract common.Address
	shardId  uint64
	origin   uint64
	limit    uint64

	task *kvSubTask // kvSubTask which this request is filling (only access fields through the runloop!!)
}

// kvHealResponse is an already verified remote response to a kv request.
type kvRangeResponse struct {
	reqId        uint64         // Request ID of this response
	task         *kvSubTask     // kvHealTask which this request is filling
	contract     common.Address // contract
	shardId      uint64         // shardId
	providerAddr common.Address
	kvs          map[uint64][]byte // kvs to store into the sharded storage
}

// kvHealRequest tracks a pending kv request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: kv requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the Data to
// construct the response without accessing runloop internals (i.e. task). That
// is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type kvHealRequest struct {
	peer string    // Peer to which this request is assigned
	id   uint64    // Request ID of this request
	time time.Time // Timestamp when the request was sent

	deliver chan *kvHealResponse // Channel to deliver successful response on
	revert  chan *kvHealRequest  // Channel to revert request failure on
	cancel  chan struct{}        // Channel to track sync cancellation
	timeout *time.Timer          // Timer to track delivery timeout
	stale   chan struct{}        // Channel to signal the request was dropped

	contract common.Address
	shardId  uint64
	indexes  []uint64

	task *kvHealTask // kvHealTask which this request is filling (only access fields through the runloop!!)
}

// kvHealResponse is an already verified remote response to a kv request.
type kvHealResponse struct {
	reqId        uint64         // Request ID of this response
	task         *kvHealTask    // kvHealTask which this request is filling
	contract     common.Address // contract
	shardId      uint64         // shardId
	providerAddr common.Address
	kvs          map[uint64][]byte // kvs to store into the sharded storage
}

// kvTask represents the sync task for a sstorage shard.
type kvTask struct {
	// These fields get serialized to leveldb on shutdown
	Contract        common.Address // Contract address
	ShardId         uint64         // ShardId
	KvSubTasks      []*kvSubTask
	HealTask        *kvHealTask
	KvSubEmptyTasks []*kvSubEmptyTask

	statelessPeers map[string]struct{} // Peers that failed to deliver kv Data

	done bool // Flag whether the task can be removed
}

// task which is used to write empty to sstorage file, so the files will fill up with encode data
type kvSubEmptyTask struct {
	kvTask *kvTask

	next  uint64
	First uint64
	Last  uint64

	isRunning bool
	done      bool // Flag whether the task can be removed
}

type kvSubTask struct {
	kvTask *kvTask

	next  uint64
	First uint64
	Last  uint64

	req *kvRangeRequest  // Pending request to fill this task
	res *kvRangeResponse // Validate response filling this task

	done bool // Flag whether the task can be removed
}

// kvHealTask represents the sync task for a sstorage shard.
type kvHealTask struct {
	kvTask  *kvTask
	Indexes map[uint64]int64 // Indexes kv index to sync time map

	// These fields are internals used during runtime
	req *kvHealRequest  // Pending request to fill this task
	res *kvHealResponse // Validate response filling this task

	lock sync.RWMutex // Protects fields that can change outside of sync (peers, reqs, root)
}

func (h *kvHealTask) hasIndexInRange(first, last uint64) (bool, uint64) {
	min, exist := last, false
	for idx, _ := range h.Indexes {
		if idx < last && idx >= first {
			exist = true
			if min > idx {
				min = idx
			}
		}
	}
	return exist, min
}

func (t *kvHealTask) getKVIndexesForRequest(batch uint64) []uint64 {
	indexes := make([]uint64, 0)
	l := uint64(0)
	t.lock.Lock()
	defer t.lock.Unlock()
	for idx, tm := range t.Indexes {
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

	// IsShardExist is the peer support this ShardId
	IsShardExist(contract common.Address, shardId uint64) bool

	// RequestKVs fetches a batch of kvs with a kv list
	RequestKVs(id uint64, contract common.Address, shardId uint64, kvList []uint64) error

	// RequestKVRange fetches a batch of kvs with a kv list
	RequestKVRange(id uint64, contract common.Address, shardId uint64, origin uint64, limit uint64) error

	// RequestShardList fetches shard list support by the peer
	RequestShardList(shards map[common.Address][]uint64) error

	// Log retrieves the peer's own contextual logger.
	Log() log.Logger
}

type BlockChain interface {
	// StateAt returns a new mutable state based on a particular point in time.
	StateAt(root common.Hash) (*state.StateDB, error)

	// CurrentBlock retrieves the current head block of the canonical chain. The
	// block is retrieved from the blockchain's internal cache.
	CurrentBlock() *types.Block

	// VerifyAndWriteKV verify a list of encoded KV data using the metadata saved in the local level DB and write successfully verified
	// KVs to the sstorage file. And return the inserted KV index list.
	VerifyAndWriteKV(contract common.Address, data map[uint64][]byte, providerAddress common.Address) (uint64, uint64, []uint64, error)

	// FillSstorWithEmptyKV get the lastKVIndex and if the kv index need to fill is larger than or equal to lastKVIndex
	// fill up the kv with empty ([]byte{}), so the data in the file will be filled with encode empty data
	FillSstorWithEmptyKV(contract common.Address, start, limit uint64) (uint64, error)

	// ReadEncodedKVsByIndexList Read the masked KVs by a list of KV index.
	ReadEncodedKVsByIndexList(contract common.Address, shardId uint64, indexes []uint64) (common.Address, []*core.KV, error)

	// ReadEncodedKVsByIndexRange Read masked KVs sequentially starting from origin until the index exceeds the limit or
	// the amount of data read is greater than the bytes.
	ReadEncodedKVsByIndexRange(contract common.Address, shardId uint64, origin uint64, limit uint64, bytes uint64) (common.Address, []*core.KV, error)

	// GetSstorageLastKvIdx get LastKvIdx from a sstorage contract with latest stateDB.
	GetSstorageLastKvIdx(contract common.Address) (uint64, error)
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
	mux   *event.TypeMux // Event multiplexer to announce sync operation events
	tasks []*kvTask

	sstorageInfo map[common.Address][]uint64 // Map for Contract address to support shardIds
	syncDone     bool                        // Flag to signal that sstorage phase is done
	update       chan struct{}               // Notification channel for possible sync progression

	peers map[string]SyncPeer // Currently active peers to download from

	peerJoin *event.Feed       // Event feed to react to peers joining
	peerDrop *event.Feed       // Event feed to react to peers dropping
	rates    *msgrate.Trackers // Message throughput rates for peers

	// Request tracking during syncing phase
	kvRangeIdlers map[string]struct{}        // Peers that aren't serving kv requests
	kvHealIdlers  map[string]struct{}        // Peers that aren't serving kv heal requests
	kvRangeReqs   map[uint64]*kvRangeRequest // KV requests currently running
	kvHealReqs    map[uint64]*kvHealRequest  // KV heal requests currently running

	runningEmptyTaskTreads int // Number of working threads for processing empty task

	kvSynced  uint64             // Number of kvs downloaded
	kvBytes   common.StorageSize // Number of kv bytes downloaded
	kvSyncing uint64             // Number of kvs downloading

	startTime time.Time // Time instance when sstorage sync started
	logTime   time.Time // Time instance when status was Last reported

	pend sync.WaitGroup // Tracks network request goroutines for graceful shutdown
	lock sync.RWMutex   // Protects fields that can change outside of sync (peers, reqs, root)
	once sync.Once      // make loadSyncStatus run once
}

// NewSyncer creates a new sstorage syncer to download the sharded storage content over the sstorage protocol.
func NewSyncer(db ethdb.KeyValueStore, chain BlockChain, mux *event.TypeMux, sstorageInfo map[common.Address][]uint64) *Syncer {
	maxEmptyTaskTreads = runtime.NumCPU() - 2
	if maxEmptyTaskTreads < 1 {
		maxEmptyTaskTreads = 1
	}
	return &Syncer{
		db:           db,
		mux:          mux,
		tasks:        make([]*kvTask, 0),
		sstorageInfo: sstorageInfo,
		chain:        chain,

		peers:    make(map[string]SyncPeer),
		peerJoin: new(event.Feed),
		peerDrop: new(event.Feed),
		rates:    msgrate.NewTrackers(log.New("proto", "sstorage")),
		update:   make(chan struct{}, 1),

		kvRangeIdlers:          make(map[string]struct{}),
		kvHealIdlers:           make(map[string]struct{}),
		runningEmptyTaskTreads: 0,
		kvRangeReqs:            make(map[uint64]*kvRangeRequest),
		kvHealReqs:             make(map[uint64]*kvHealRequest),
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
	s.kvRangeIdlers[id] = struct{}{}
	s.kvHealIdlers[id] = struct{}{}
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

	delete(s.kvRangeIdlers, id)
	delete(s.kvHealIdlers, id)
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
	if s.syncDone {
		log.Info("Sstorage sync already completed")
		return nil
	}
	defer func() { // Persist any progress, independent of failure
		s.cleanKVTasks()
		s.saveSyncStatus()
	}()

	for addr, ids := range s.sstorageInfo {
		log.Debug("Starting Sstorage sync cycle", "Contract", addr.Hex(), "shards", ids)
	}

	// Whether sync completed or not, disregard any future packets
	defer func() {
		s.lock.Lock()
		s.kvRangeReqs = make(map[uint64]*kvRangeRequest)
		s.kvHealReqs = make(map[uint64]*kvHealRequest)
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
		kvRangeReqFails = make(chan *kvRangeRequest)
		kvRangeResps    = make(chan *kvRangeResponse)
		kvHealReqFails  = make(chan *kvHealRequest)
		kvHealResps     = make(chan *kvHealResponse)
		i               = 0
	)
	for {
		// Remove all completed tasks and terminate sync if everything's done
		s.cleanKVTasks()
		if s.syncDone {
			return nil
		}
		s.assignKVRangeTasks(kvRangeResps, kvRangeReqFails, cancel)
		// Assign all the Data retrieval tasks to any free peers
		s.assignKVHealTasks(kvHealResps, kvHealReqFails, cancel)

		s.assignKVEmptyTasks()

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

		case req := <-kvRangeReqFails:
			s.revertKVRangeRequest(req)
		case req := <-kvHealReqFails:
			s.revertKVHealRequest(req)

		case res := <-kvRangeResps:
			s.processKVRangeResponse(res)
		case res := <-kvHealResps:
			s.processKVHealResponse(res)
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
	var progress SyncProgress

	if status := rawdb.ReadSstorageSyncStatus(s.db); status != nil {
		if err := json.Unmarshal(status, &progress); err != nil {
			log.Error("Failed to decode sstorage sync status", "err", err)
		} else {
			for _, task := range progress.Tasks {
				log.Debug("Scheduled sstorage sync task", "Contract", task.Contract.Hex(),
					"shard", task.ShardId, "count", len(task.KvSubTasks))
				task.HealTask.kvTask = task
				for _, kvSubTask := range task.KvSubTasks {
					kvSubTask.kvTask = task
					kvSubTask.next = kvSubTask.First
				}
				for _, kvSubEmptyTask := range task.KvSubEmptyTasks {
					kvSubEmptyTask.kvTask = task
					kvSubEmptyTask.next = kvSubEmptyTask.First
				}
			}
			s.kvSynced, s.kvBytes = progress.KVSynced, progress.KVBytes
		}
	}

	// create tasks
	for contract, shards := range s.sstorageInfo {
		sm := sstorage.ContractToShardManager[contract]
		lastKvIndex, err := s.chain.GetSstorageLastKvIdx(contract)
		if err != nil {
			log.Info("loadSyncStatus failed: get lastKvIdx")
			lastKvIndex = 0
		}
		for _, sid := range shards {
			exist := false
			for _, task := range progress.Tasks {
				if task.Contract == contract && task.ShardId == sid {
					s.tasks = append(s.tasks, task)
					exist = true
					continue
				}
			}
			if exist {
				continue
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

			first, limit := sm.KvEntries()*sid, sm.KvEntries()*(sid+1)
			firstEmpty, limitForEmpty := uint64(0), uint64(0)
			if first >= lastKvIndex {
				firstEmpty, limitForEmpty = first, limit
				limit = first
			} else if limit >= lastKvIndex {
				firstEmpty, limitForEmpty = lastKvIndex, limit
				limit = lastKvIndex
			}

			subTasks := make([]*kvSubTask, 0)
			// split task for a shard to 16 subtasks and if one batch is too small
			// set to minSubTaskSize
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
				first = last
			}

			subEmptyTasks := make([]*kvSubEmptyTask, 0)
			if limitForEmpty > 0 {
				maxEmptyTaskSize := (limitForEmpty - firstEmpty + uint64(maxEmptyTaskTreads)) / uint64(maxEmptyTaskTreads)
				if maxEmptyTaskSize < minSubTaskSize {
					maxEmptyTaskSize = minSubTaskSize
				}

				for firstEmpty < limitForEmpty {
					last := firstEmpty + maxEmptyTaskSize
					if last > limitForEmpty {
						last = limitForEmpty
					}
					subTask := kvSubEmptyTask{
						kvTask: &task,
						next:   firstEmpty,
						First:  firstEmpty,
						Last:   last,
						done:   false,
					}

					subEmptyTasks = append(subEmptyTasks, &subTask)
					firstEmpty = last
				}
			}

			task.HealTask, task.KvSubTasks, task.KvSubEmptyTasks = &healTask, subTasks, subEmptyTasks
			s.tasks = append(s.tasks, &task)
		}
	}

	allDone := true
	for _, task := range s.tasks {
		if len(task.KvSubTasks) > 0 || len(task.HealTask.Indexes) > 0 || len(task.KvSubEmptyTasks) > 0 {
			allDone = false
			break
		}
	}
	if allDone {
		s.setSyncDone()
	}
}

type SstorSyncDone struct{}

func (s *Syncer) setSyncDone() {
	s.syncDone = true
	s.mux.Post(SstorSyncDone{})
}

// saveSyncStatus marshals the remaining sync tasks into leveldb.
func (s *Syncer) saveSyncStatus() {
	// Store the actual progress markers
	progress := &SyncProgress{
		Tasks:    s.tasks,
		KVSynced: s.kvSynced,
		KVBytes:  s.kvBytes,
	}
	status, err := json.Marshal(progress)
	if err != nil {
		panic(err) // This can only fail during implementation
	}
	rawdb.WriteSstorageSyncStatus(s.db, status)
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
	// Sync wasn't finished previously, check for any task that can be finalized
	allDone := true
	for _, task := range s.tasks {
		for i := 0; i < len(task.KvSubTasks); i++ {
			exist, min := task.HealTask.hasIndexInRange(task.KvSubTasks[i].First, task.KvSubTasks[i].Last)
			if exist {
				task.KvSubTasks[i].First = min
			}
			if task.KvSubTasks[i].done && !exist {
				task.KvSubTasks = append(task.KvSubTasks[:i], task.KvSubTasks[i+1:]...)
				i--
			}
		}
		for i := 0; i < len(task.KvSubEmptyTasks); i++ {
			if task.KvSubEmptyTasks[i].done {
				task.KvSubEmptyTasks = append(task.KvSubEmptyTasks[:i], task.KvSubEmptyTasks[i+1:]...)
				i--
			}
		}
		if len(task.KvSubTasks) > 0 || len(task.KvSubEmptyTasks) > 0 {
			allDone = false
		}
	}

	// If everything was just finalized, generate the account trie and start heal
	if allDone {
		s.lock.Lock()
		s.setSyncDone()
		s.lock.Unlock()
		log.Info("Sstorage sync done", "task count", len(s.tasks))

		// Push the final sync report
		s.report(true)
	}
}

// assignKVHealTasks attempts to match idle peers to pending kv range retrievals.
func (s *Syncer) assignKVRangeTasks(success chan *kvRangeResponse, fail chan *kvRangeRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.kvRangeIdlers) == 0 {
		return
	}
	idlers := make([]string, 0, len(s.kvRangeIdlers))
	for id := range s.kvRangeIdlers {
		idlers = append(idlers, id)
	}

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		for _, subTask := range task.KvSubTasks {
			if subTask.done {
				continue
			}
			// Skip any tasks already filling
			if subTask.req != nil || subTask.res != nil {
				continue
			}
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
				if p.IsShardExist(task.Contract, task.ShardId) {
					peer = p
					if i < len(idlers)-1 {
						idlers = append(idlers[:i], idlers[i+1:]...)
					} else {
						idlers = idlers[:i]
					}
					break
				}
			}
			if peer == nil {
				continue
			}

			// Matched a pending task to an idle peer, allocate a unique request id
			var reqid uint64
			for {
				reqid = uint64(rand.Int63())
				if reqid == 0 {
					continue
				}
				if _, ok := s.kvRangeReqs[reqid]; ok {
					continue
				}
				break
			}

			req := &kvRangeRequest{
				peer:     peer.ID(),
				id:       reqid,
				contract: task.Contract,
				shardId:  task.ShardId,
				origin:   subTask.next,
				limit:    subTask.Last - 1,
				time:     time.Now(),
				deliver:  success,
				revert:   fail,
				cancel:   cancel,
				stale:    make(chan struct{}),
				task:     subTask,
			}
			req.timeout = time.AfterFunc(s.rates.TargetTimeout(), func() {
				peer.Log().Info("KV Range request timed out", "reqid", reqid)
				s.rates.Update(peer.ID(), KVRangeMsg, 0, 0)
				s.scheduleRevertKVRangeRequest(req)
			})
			s.kvRangeReqs[reqid] = req
			delete(s.kvRangeIdlers, peer.ID())

			s.pend.Add(1)
			go func() {
				defer s.pend.Done()

				// Attempt to send the remote request and revert if it fails
				if err := peer.RequestKVRange(reqid, req.task.kvTask.Contract, req.shardId, req.origin, req.limit); err != nil {
					log.Warn("Failed to request kvs", "err", err)
					s.scheduleRevertKVRangeRequest(req)
				}
			}()

			subTask.req = req
		}
	}
}

// assignKVHealTasks attempts to match idle peers to heal kv requests to retrieval missing kv from the kv range request.
func (s *Syncer) assignKVHealTasks(success chan *kvHealResponse, fail chan *kvHealRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.kvHealIdlers) == 0 {
		return
	}
	idlers := make([]string, 0, len(s.kvHealIdlers))
	for id := range s.kvHealIdlers {
		idlers = append(idlers, id)
	}

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		// All the kvs are downloading, wait for request time or success
		batch := maxRequestSize / sstorage.ContractToShardManager[task.Contract].MaxKvSize() * 2

		// kvHealTask pending retrieval, try to find an idle peer. If no such peer
		// exists, we probably assigned tasks for all (or they are stateless).
		// Abort the entire assignment mechanism.
		if len(idlers) == 0 {
			return
		}
		indexes := task.HealTask.getKVIndexesForRequest(batch)
		if len(indexes) == 0 {
			continue
		}
		var (
			peer SyncPeer = nil
		)
		for i, id := range idlers {
			p := s.peers[id]
			if _, ok := task.statelessPeers[id]; ok {
				continue
			}
			if p.IsShardExist(task.Contract, task.ShardId) {
				peer = p
				if i < len(idlers)-1 {
					idlers = append(idlers[:i], idlers[i+1:]...)
				} else { // Last one
					idlers = idlers[:i]
				}
				break
			}
		}
		if peer == nil {
			log.Info("peer for request no found", "Contract", task.Contract.Hex(), "shard id",
				task.ShardId, "index len", len(task.HealTask.Indexes), "peers", len(s.peers), "idlers", len(idlers))
			continue
		}

		// Matched a pending task to an idle peer, allocate a unique request id
		var reqid uint64
		for {
			reqid = uint64(rand.Int63())
			if reqid == 0 {
				continue
			}
			if _, ok := s.kvHealReqs[reqid]; ok {
				continue
			}
			break
		}

		req := &kvHealRequest{
			peer:     peer.ID(),
			id:       reqid,
			contract: task.Contract,
			shardId:  task.ShardId,
			indexes:  indexes,
			time:     time.Now(),
			deliver:  success,
			revert:   fail,
			cancel:   cancel,
			stale:    make(chan struct{}),
			task:     task.HealTask,
		}
		req.timeout = time.AfterFunc(s.rates.TargetTimeout(), func() {
			peer.Log().Info("KV heal request timed out", "reqid", reqid)
			s.rates.Update(peer.ID(), KVsMsg, 0, 0)
			s.scheduleRevertKVHealRequest(req)
		})
		s.kvHealReqs[reqid] = req
		delete(s.kvHealIdlers, peer.ID())

		s.pend.Add(1)
		go func() {
			defer s.pend.Done()

			// Attempt to send the remote request and revert if it fails
			if err := peer.RequestKVs(reqid, req.task.kvTask.Contract, req.shardId, req.indexes); err != nil {
				log.Warn("Failed to request kvs", "err", err)
				s.scheduleRevertKVHealRequest(req)
			}
		}()

		task.HealTask.req = req
		req.task.lock.Lock()
		defer req.task.lock.Unlock()
		for _, idx := range indexes {
			req.task.Indexes[idx] = time.Now().UnixMilli()
		}
	}
}

// assignKVEmptyTasks attempts to match idle peers to heal kv requests to retrieval missing kv from the kv range request.
func (s *Syncer) assignKVEmptyTasks() {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		for _, subEmptyTask := range task.KvSubEmptyTasks {
			if s.runningEmptyTaskTreads >= maxEmptyTaskTreads {
				return
			}
			s.runningEmptyTaskTreads++
			if subEmptyTask.isRunning {
				continue
			}
			subTask := subEmptyTask
			subTask.isRunning = true
			start, last := subTask.next, subTask.Last
			if last > start+minSubTaskSize {
				last = start + minSubTaskSize
			}
			go func(eTask *kvSubEmptyTask, contract common.Address, start, limit uint64) {
				t := time.Now()
				next, err := s.chain.FillSstorWithEmptyKV(contract, start, limit)
				if err != nil {
					log.Warn("fill in empty fail", "err", err.Error())
				}
				log.Warn("FillSstorWithEmptyKV", "time", time.Now().Sub(t).Seconds())
				eTask.next = next
				if eTask.next >= eTask.Last {
					eTask.done = true
				}
				eTask.isRunning = false
				s.runningEmptyTaskTreads--
			}(subTask, task.Contract, start, last-1)
		}
	}
}

// revertRequests locates all the currently pending reuqests from a particular
// peer and reverts them, rescheduling for others to fulfill.
func (s *Syncer) revertRequests(peer string) {
	// Gather the requests first, revertals need the lock too
	s.lock.Lock()
	var kvRangeReqs []*kvRangeRequest
	for _, req := range s.kvRangeReqs {
		if req.peer == peer {
			kvRangeReqs = append(kvRangeReqs, req)
		}
	}
	var kvHealReqs []*kvHealRequest
	for _, req := range s.kvHealReqs {
		if req.peer == peer {
			kvHealReqs = append(kvHealReqs, req)
		}
	}
	s.lock.Unlock()

	// Revert all the requests matching the peer
	for _, req := range kvRangeReqs {
		s.revertKVRangeRequest(req)
	}
	for _, req := range kvHealReqs {
		s.revertKVHealRequest(req)
	}
}

// scheduleRevertKVHealRequest asks the event loop to clean up a kv request
// and return all failed retrieval tasks to the scheduler for reassignment.
func (s *Syncer) scheduleRevertKVRangeRequest(req *kvRangeRequest) {
	select {
	case req.revert <- req:
		// Sync event loop notified
	case <-req.cancel:
		// Sync cycle got cancelled
	case <-req.stale:
		// Request already reverted
	}
}

// scheduleRevertKVHealRequest asks the event loop to clean up a kv request
// and return all failed retrieval tasks to the scheduler for reassignment.
func (s *Syncer) scheduleRevertKVHealRequest(req *kvHealRequest) {
	select {
	case req.revert <- req:
		// Sync event loop notified
	case <-req.cancel:
		// Sync cycle got cancelled
	case <-req.stale:
		// Request already reverted
	}
}

// revertKVRangeRequest cleans up a kv request and returns all failed
// retrieval tasks to the scheduler for reassignment.
//
// Note, this needs to run on the event runloop thread to reschedule to idle peers.
// On peer threads, use scheduleRevertKVHealRequest.
func (s *Syncer) revertKVRangeRequest(req *kvRangeRequest) {
	select {
	case <-req.stale:
		log.Trace("KV request already reverted", "peer", req.peer, "reqid", req.id)
		return
	default:
	}
	close(req.stale)

	// Remove the request from the tracked set
	s.lock.Lock()
	delete(s.kvRangeReqs, req.id)
	s.lock.Unlock()

	// If there's a timeout timer still running, abort it and mark the code
	// retrievals as not-pending, ready for resheduling
	req.timeout.Stop()
	if req.task.req == req {
		req.task.req = nil
	}
}

// revertKVHealRequest cleans up a kv request and returns all failed
// retrieval tasks to the scheduler for reassignment.
//
// Note, this needs to run on the event runloop thread to reschedule to idle peers.
// On peer threads, use scheduleRevertKVHealRequest.
func (s *Syncer) revertKVHealRequest(req *kvHealRequest) {
	select {
	case <-req.stale:
		log.Trace("KV request already reverted", "peer", req.peer, "reqid", req.id)
		return
	default:
	}
	close(req.stale)

	// Remove the request from the tracked set
	s.lock.Lock()
	delete(s.kvHealReqs, req.id)
	s.lock.Unlock()

	// If there's a timeout timer still running, abort it and mark the code
	// retrievals as not-pending, ready for resheduling
	req.timeout.Stop()
	for _, index := range req.indexes {
		req.task.Indexes[index] = 0
	}
}

// processKVRangeResponse integrates an already validated kv response
// into the account tasks.
func (s *Syncer) processKVRangeResponse(res *kvRangeResponse) {
	var (
		synced      uint64
		syncedBytes uint64
		req         = res.task.req
	)
	res.task.req = nil
	res.task.res = res
	defer func() { res.task.res = nil }()

	if res.task.kvTask.Contract != res.contract {
		log.Error("processKVRangeResponse fail: Contract mismatch", "task", res.task.kvTask.Contract.Hex(), "res", res.contract.Hex())
		return
	}

	// TODO: obtain peer provider address
	synced, syncedBytes, inserted, err := s.chain.VerifyAndWriteKV(res.contract, res.kvs, res.providerAddr)
	if err != nil {
		log.Error("processKVRangeResponse fail", "err", err.Error())
		return
	}

	s.kvSynced += synced
	s.kvBytes += common.StorageSize(syncedBytes)
	log.Info("Persisted set of kvs", "count", synced, "bytes", syncedBytes)

	// set peer to stateless peer if fail too much
	if len(inserted) == 0 {
		res.task.kvTask.statelessPeers[req.peer] = struct{}{}
		return
	}

	sort.Slice(inserted, func(i, j int) bool {
		return inserted[i] < inserted[j]
	})
	max := inserted[len(inserted)-1]
	for i, n := 0, res.task.next; n <= max; n++ {
		if inserted[i] == n {
			i++
		} else if inserted[i] > n {
			res.task.kvTask.HealTask.Indexes[n] = 0
		}
	}
	if max == res.task.Last-1 {
		res.task.done = true
	} else {
		res.task.next = max + 1
	}
}

// processKVHealResponse integrates an already validated kv response
// into the account tasks.
func (s *Syncer) processKVHealResponse(res *kvHealResponse) {
	var (
		synced      uint64
		syncedBytes uint64
		req         = res.task.req
	)
	/*res.task.req = nil
	res.task.res = res*/
	defer func() { res.task.res = nil }()

	if res.task.kvTask.Contract != res.contract {
		log.Error("processKVHealResponse fail: Contract mismatch", "task", res.task.kvTask.Contract.Hex(), "res", res.contract.Hex())
		return
	}

	// TODO: obtain peer provider address
	synced, syncedBytes, inserted, err := s.chain.VerifyAndWriteKV(res.contract, res.kvs, res.providerAddr)
	if err != nil {
		log.Error("processKVHealResponse fail", "err", err.Error())
		return
	}

	// set peer to stateless peer if fail too much
	if len(inserted) == 0 {
		res.task.kvTask.statelessPeers[req.peer] = struct{}{}
	}

	s.kvSynced += synced
	s.kvBytes += common.StorageSize(syncedBytes)
	log.Trace("Persisted set of kvs", "count", synced, "bytes", syncedBytes)

	res.task.lock.Lock()
	defer res.task.lock.Unlock()
	for _, idx := range inserted {
		if _, ok := res.kvs[idx]; ok {
			delete(res.task.Indexes, idx)
		} else {
			res.task.Indexes[idx] = 0
		}
	}

	log.Info("remain index for heal sync", "ShardId", res.task.kvTask.ShardId, "len", len(res.task.Indexes))
}

// OnKVs is a callback method to invoke when a batch of Contract
// bytes codes are received from a remote peer.
func (s *Syncer) OnKVs(peer SyncPeer, id uint64, providerAddr common.Address, kvs []*core.KV) error {
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
		s.kvHealIdlers[peer.ID()] = struct{}{}
	}
	select {
	case s.update <- struct{}{}:
	default:
	}
	// Ensure the response is for a valid request
	req, ok := s.kvHealReqs[id]
	if !ok {
		// Request stale, perhaps the peer timed out but came through in the end
		logger.Warn("Unexpected kv heal packet")
		s.lock.Unlock()
		return nil
	}
	delete(s.kvHealReqs, id)
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
		logger.Debug("Peer rejected kv request", "len", len(req.task.kvTask.HealTask.Indexes))
		req.task.kvTask.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVHealRequest(req)
		return nil
	}
	startIdx, endIdx := sm.KvEntries()*req.shardId, sm.KvEntries()*(req.shardId+1)-1
	kvInRange := make(map[uint64][]byte)
	for _, kv := range kvs {
		if startIdx <= kv.Idx && endIdx >= kv.Idx {
			kvInRange[kv.Idx] = kv.Data
		}
	}
	if len(kvs) > len(kvInRange) {
		logger.Trace("Drop unexpected kvs", "count", len(kvs)-len(kvInRange))
	}

	// Response is valid, but check if peer is signalling that it does not have
	// the requested Data. For kv range queries that means the peer is not
	// yet synced.
	if len(kvInRange) == 0 {
		logger.Warn("Peer rejected kv range request")
		req.task.kvTask.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVHealRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Response validated, send it to the scheduler for filling
	response := &kvHealResponse{
		task:         req.task,
		reqId:        req.id,
		contract:     req.contract,
		shardId:      req.shardId,
		providerAddr: providerAddr,
		kvs:          kvInRange,
	}
	select {
	case req.deliver <- response:
	case <-req.cancel:
	case <-req.stale:
	}
	return nil
}

// OnKVRange is a callback method to invoke when a batch of Contract
// bytes codes are received from a remote peer.
func (s *Syncer) OnKVRange(peer SyncPeer, id uint64, providerAddr common.Address, kvs []*core.KV) error {
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
		s.kvRangeIdlers[peer.ID()] = struct{}{}
	}
	select {
	case s.update <- struct{}{}:
	default:
	}
	// Ensure the response is for a valid request
	req, ok := s.kvRangeReqs[id]
	if !ok {
		// Request stale, perhaps the peer timed out but came through in the end
		logger.Warn("Unexpected kv range packet")
		s.lock.Unlock()
		return nil
	}
	delete(s.kvRangeReqs, id)
	s.rates.Update(peer.ID(), KVRangeMsg, time.Since(req.time), len(kvs))

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
		logger.Debug("Peer rejected kv request", "origin", req.origin, "limit", req.limit)
		req.task.kvTask.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVRangeRequest(req)
		return nil
	}
	startIdx, endIdx := sm.KvEntries()*req.shardId, sm.KvEntries()*(req.shardId+1)-1
	kvInRange := make(map[uint64][]byte)
	for _, kv := range kvs {
		if startIdx <= kv.Idx && endIdx >= kv.Idx {
			kvInRange[kv.Idx] = kv.Data
		}
	}
	if len(kvs) > len(kvInRange) {
		logger.Trace("Drop unexpected kvs", "count", len(kvs)-len(kvInRange))
	}

	// Response is valid, but check if peer is signalling that it does not have
	// the requested Data. For kv range queries that means the peer is not
	// yet synced.
	if len(kvInRange) == 0 {
		logger.Warn("Peer rejected kv range request")
		req.task.kvTask.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertKVRangeRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Response validated, send it to the scheduler for filling
	response := &kvRangeResponse{
		task:         req.task,
		reqId:        req.id,
		contract:     req.contract,
		shardId:      req.shardId,
		providerAddr: providerAddr,
		kvs:          kvInRange,
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
	subTaskRemain := 0
	for _, task := range s.tasks {
		for _, subTask := range task.KvSubTasks {
			kvsToSync = kvsToSync + (subTask.Last - subTask.next)
			subTaskRemain++
		}
		kvsToSync = kvsToSync + uint64(len(task.HealTask.Indexes))
	}
	s.logTime = time.Now()

	elapsed := time.Since(s.startTime)
	estTime := elapsed / time.Duration(synced) * time.Duration(kvsToSync+synced)

	// Create a mega progress report
	var (
		progress = fmt.Sprintf("%.2f%%", float64(synced)*100/float64(kvsToSync+synced))
		kv       = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.kvSynced), s.kvBytes.TerminalString())
	)
	log.Info("State sync in progress", "synced", progress, "state", synced, "kvsToSync", kvsToSync,
		"sub task remain", subTaskRemain, "kv", kv, "eta", common.PrettyDuration(estTime-elapsed))
}
