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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/msgrate"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

// todo
const (
	// minRequestSize is the minimum number of bytes to request from a remote peer.
	// This number is used as the low cap for account and storage range requests.
	// Chunk and trienode are limited inherently by item count (1).
	minRequestSize = 64 * 1024

	// maxRequestSize is the maximum number of bytes to request from a remote peer.
	// This number is used as the high cap for account and storage range requests.
	// Chunk and trienode are limited more explicitly by the caps below.
	maxRequestSize = 512 * 1024

	// maxCodeRequestCount is the maximum number of chunk blobs to request in a
	// single query. If this number is too low, we're not filling responses fully
	// and waste round trip times. If it's too high, we're capping responses and
	// waste bandwidth.
	//
	// Depoyed chunks are currently capped at 24KB, so the minimum request
	// size should be maxRequestSize / 24K. Assuming that most contracts do not
	// come close to that, requesting 4x should be a good approximation.
	maxCodeRequestCount = maxRequestSize / (24 * 1024) * 4

	// maxTrieRequestCount is the maximum number of trie node blobs to request in
	// a single query. If this number is too low, we're not filling responses fully
	// and waste round trip times. If it's too high, we're capping responses and
	// waste bandwidth.
	maxTrieRequestCount = maxRequestSize / 512
)

// ErrCancelled is returned from snap syncing if the operation was prematurely
// terminated.
var ErrCancelled = errors.New("sync cancelled")

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

	hashes []common.Hash // Chunk hashes to validate responses
	task   *accountTask  // Task which this request is filling (only access fields through the runloop!!)
}

// chunkResponse is an already verified remote response to a chunk request.
type chunkResponse struct {
	task *accountTask // Task which this request is filling

	hashes []common.Hash // Hashes of the chunk to avoid double hashing
	codes  [][]byte      // Actual chunks to store into the database (nil = missing)
}

// chunkHealRequest tracks a pending chunk request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: chunk requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the data to
// construct the response without accessing runloop internals (i.e. task). That
// is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type chunkHealRequest struct {
	peer string    // Peer to which this request is assigned
	id   uint64    // Request ID of this request
	time time.Time // Timestamp when the request was sent

	deliver chan *chunkHealResponse // Channel to deliver successful response on
	revert  chan *chunkHealRequest  // Channel to deliver request failure on
	cancel  chan struct{}           // Channel to track sync cancellation
	timeout *time.Timer             // Timer to track delivery timeout
	stale   chan struct{}           // Channel to signal the request was dropped

	hashes []common.Hash // Chunk hashes to validate responses
	task   *healTask     // Task which this request is filling (only access fields through the runloop!!)
}

// chunkHealResponse is an already verified remote response to a chunk request.
type chunkHealResponse struct {
	task *healTask // Task which this request is filling

	hashes []common.Hash // Hashes of the chunk to avoid double hashing
	codes  [][]byte      // Actual chunks to store into the database (nil = missing)
}

// healTask represents the sync task for healing the snap-synced chunk boundaries.
type healTask struct {
	scheduler *trie.Sync // State trie sync scheduler defining the tasks

	trieTasks map[common.Hash]trie.SyncPath // Set of trie node tasks currently queued for retrieval
	codeTasks map[common.Hash]struct{}      // Set of byte code tasks currently queued for retrieval
}

// SyncProgress is a database entry to allow suspending and resuming a snapshot state
// sync. Opposed to full and fast sync, there is no way to restart a suspended
// snap sync without prior knowledge of the suspension point.
type SyncProgress struct {
	ChunkSynced uint64             // Number of chunks downloaded
	ChunkBytes  common.StorageSize // Number of chunk bytes downloaded

	ChunkHealSynced uint64             // Number of chunks downloaded
	ChunkHealBytes  common.StorageSize // Number of chunks persisted to disk
}

// SyncPending is analogous to SyncProgress, but it's used to report on pending
// ephemeral sync progress that doesn't get persisted into the database.
type SyncPending struct {
	ChunkHeal uint64 // Number of chunks pending
}

// SyncPeer abstracts out the methods required for a peer to be synced against
// with the goal of allowing the construction of mock peers without the full
// blown networking.
type SyncPeer interface {
	// ID retrieves the peer's unique identifier.
	ID() string

	// RequestTrieNodes fetches a batch of account or storage trie nodes rooted in
	// a specificstate trie.
	RequestChunks(id uint64, shardId, startIdx, endIdx uint64) error

	// Log retrieves the peer's own contextual logger.
	Log() log.Logger
}

// Syncer is an Ethereum account and storage trie syncer based on snapshots and
// the  snap protocol. It's purpose is to download all the accounts and storage
// slots from remote peers and reassemble chunks of the state trie, on top of
// which a state sync can be run to fix any gaps / overlaps.
//
// Every network request has a variety of failure events:
//   - The peer disconnects after task assignment, failing to send the request
//   - The peer disconnects after sending the request, before delivering on it
//   - The peer remains connected, but does not deliver a response in time
//   - The peer delivers a stale response after a previous timeout
//   - The peer delivers a refusal to serve the requested state
type Syncer struct {
	db ethdb.KeyValueStore // Database to store the trie nodes into (and dedup)

	root    common.Hash   // Current state trie root being synced
	snapped bool          // Flag to signal that snap phase is done
	healer  *healTask     // Current state healing task being executed
	update  chan struct{} // Notification channel for possible sync progression

	peers    map[string]SyncPeer // Currently active peers to download from
	peerJoin *event.Feed         // Event feed to react to peers joining
	peerDrop *event.Feed         // Event feed to react to peers dropping
	rates    *msgrate.Trackers   // Message throughput rates for peers

	// Request tracking during syncing phase
	statelessPeers map[string]struct{} // Peers that failed to deliver state data
	chunkIdlers    map[string]struct{} // Peers that aren't serving chunk requests

	chunkReqs map[uint64]*chunkRequest // Chunk requests currently running

	chunkSynced uint64             // Number of chunks downloaded
	chunkBytes  common.StorageSize // Number of chunk bytes downloaded

	// Request tracking during healing phase
	chunkHealIdlers map[string]struct{}          // Peers that aren't serving chunk requests
	chunkHealReqs   map[uint64]*chunkHealRequest // Chunk requests currently running

	chunkHealSynced uint64             // Number of chunks downloaded
	chunkHealBytes  common.StorageSize // Number of chunks persisted to disk
	chunkHealDups   uint64             // Number of chunks already processed
	chunkHealNops   uint64             // Number of chunks not requested

	stateWriter ethdb.Batch // Shared batch writer used for persisting raw states

	startTime time.Time // Time instance when snapshot sync started
	logTime   time.Time // Time instance when status was last reported

	pend sync.WaitGroup // Tracks network request goroutines for graceful shutdown
	lock sync.RWMutex   // Protects fields that can change outside of sync (peers, reqs, root)
}

// NewSyncer creates a new snapshot syncer to download the Ethereum state over the
// snap protocol.
func NewSyncer(db ethdb.KeyValueStore) *Syncer {
	return &Syncer{
		db: db,

		peers:    make(map[string]SyncPeer),
		peerJoin: new(event.Feed),
		peerDrop: new(event.Feed),
		rates:    msgrate.NewTrackers(log.New("proto", "snap")),
		update:   make(chan struct{}, 1),

		chunkIdlers:     make(map[string]struct{}),
		chunkReqs:       make(map[uint64]*chunkRequest),
		chunkHealIdlers: make(map[string]struct{}),
		chunkHealReqs:   make(map[uint64]*chunkHealRequest),
		stateWriter:     db.NewBatch(),
	}
}

// Register injects a new data source into the syncer's peerset.
func (s *Syncer) Register(peer SyncPeer) error {
	// Make sure the peer is not registered yet
	id := peer.ID()

	s.lock.Lock()
	if _, ok := s.peers[id]; ok {
		log.Error("Snap peer already registered", "id", id)

		s.lock.Unlock()
		return errors.New("already registered")
	}
	s.peers[id] = peer
	s.rates.Track(id, msgrate.NewTracker(s.rates.MeanCapacities(), s.rates.MedianRoundTrip()))

	// Mark the peer as idle, even if no sync is running
	s.chunkIdlers[id] = struct{}{}
	s.chunkHealIdlers[id] = struct{}{}
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
		log.Error("Snap peer not registered", "id", id)

		s.lock.Unlock()
		return errors.New("not registered")
	}
	delete(s.peers, id)
	s.rates.Untrack(id)

	// Remove status markers, even if no sync is running
	delete(s.statelessPeers, id)

	delete(s.chunkIdlers, id)
	delete(s.chunkHealIdlers, id)
	s.lock.Unlock()

	// Notify any active syncs that pending requests need to be reverted
	s.peerDrop.Send(id)
	return nil
}

// Sync starts (or resumes a previous) sync cycle to iterate over an state trie
// with the given root and reconstruct the nodes based on the snapshot leaves.
// Previously downloaded segments will not be redownloaded of fixed, rather any
// errors will be healed after the leaves are fully accumulated.
func (s *Syncer) Sync(root common.Hash, cancel chan struct{}) error {
	// Move the trie root from any previous value, revert stateless markers for
	// any peers and initialize the syncer if it was not yet run
	s.lock.Lock()
	s.root = root
	s.healer = &healTask{
		scheduler: state.NewStateSync(root, s.db, s.onHealState),
		trieTasks: make(map[common.Hash]trie.SyncPath),
		codeTasks: make(map[common.Hash]struct{}),
	}
	s.statelessPeers = make(map[string]struct{})
	s.lock.Unlock()

	if s.startTime == (time.Time{}) {
		s.startTime = time.Now()
	}
	// Retrieve the previous sync status from LevelDB and abort if already synced
	s.loadSyncStatus()
	if len(s.tasks) == 0 && s.healer.scheduler.Pending() == 0 {
		log.Debug("Snapshot sync already completed")
		return nil
	}
	defer func() { // Persist any progress, independent of failure
		for _, task := range s.tasks {
			s.forwardAccountTask(task)
		}
		s.cleanAccountTasks()
		s.saveSyncStatus()
	}()

	log.Debug("Starting snapshot sync cycle", "root", root)

	// Flush out the last committed raw states
	defer func() {
		if s.stateWriter.ValueSize() > 0 {
			s.stateWriter.Write()
			s.stateWriter.Reset()
		}
	}()
	defer s.report(true)

	// Whether sync completed or not, disregard any future packets
	defer func() {
		log.Debug("Terminating snapshot sync cycle", "root", root)
		s.lock.Lock()
		s.chunkReqs = make(map[uint64]*chunkRequest)
		s.chunkHealReqs = make(map[uint64]*chunkHealRequest)
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
	// a persistent channel across syncs (yup, this happened)
	var (
		chunkReqFails     = make(chan *chunkRequest)
		chunkResps        = make(chan *chunkResponse)
		chunkHealReqFails = make(chan *chunkHealRequest)
		chunkHealResps    = make(chan *chunkHealResponse)
	)
	for {
		// Remove all completed tasks and terminate sync if everything's done
		s.cleanStorageTasks()
		s.cleanAccountTasks()
		if len(s.tasks) == 0 && s.healer.scheduler.Pending() == 0 {
			return nil
		}
		// Assign all the data retrieval tasks to any free peers
		s.assignChunkTasks(chunkResps, chunkReqFails, cancel)

		if len(s.tasks) == 0 {
			// Sync phase done, run heal phase
			s.assignChunkHealTasks(chunkHealResps, chunkHealReqFails, cancel)
		}
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
		case req := <-chunkHealReqFails:
			s.revertChunkHealRequest(req)

		case res := <-chunkResps:
			s.processChunkResponse(res)
		case res := <-chunkHealResps:
			s.processChunkHealResponse(res)
		}
		// Report stats if something meaningful happened
		s.report(false)
	}
}

// loadSyncStatus retrieves a previously aborted sync status from the database,
// or generates a fresh one if none is available.
func (s *Syncer) loadSyncStatus() {
	var progress SyncProgress

	if status := rawdb.ReadSnapshotSyncStatus(s.db); status != nil {
		if err := json.Unmarshal(status, &progress); err != nil {
			log.Error("Failed to decode snap sync status", "err", err)
		} else {
			for _, task := range progress.Tasks {
				log.Debug("Scheduled account sync task", "from", task.Next, "last", task.Last)
			}
			s.tasks = progress.Tasks
			for _, task := range s.tasks {
				task.genBatch = ethdb.HookedBatch{
					Batch: s.db.NewBatch(),
					OnPut: func(key []byte, value []byte) {
						s.accountBytes += common.StorageSize(len(key) + len(value))
					},
				}
				task.genTrie = trie.NewStackTrie(task.genBatch)

				for _, subtasks := range task.SubTasks {
					for _, subtask := range subtasks {
						subtask.genBatch = ethdb.HookedBatch{
							Batch: s.db.NewBatch(),
							OnPut: func(key []byte, value []byte) {
								s.storageBytes += common.StorageSize(len(key) + len(value))
							},
						}
						subtask.genTrie = trie.NewStackTrie(subtask.genBatch)
					}
				}
			}
			s.snapped = len(s.tasks) == 0

			s.chunkSynced = progress.ChunkSynced
			s.chunkBytes = progress.ChunkBytes
			s.chunkHealSynced = progress.ChunkHealSynced
			s.chunkHealBytes = progress.ChunkHealBytes
			return
		}
	}
	// Either we've failed to decode the previus state, or there was none.
	// Start a fresh sync by chunking up the account range and scheduling
	// them for retrieval.
	s.chunkSynced, s.chunkBytes = 0, 0
	s.chunkHealSynced, s.chunkHealBytes = 0, 0

	var next common.Hash
	step := new(big.Int).Sub(
		new(big.Int).Div(
			new(big.Int).Exp(common.Big2, common.Big256, nil),
			big.NewInt(int64(accountConcurrency)),
		), common.Big1,
	)
	for i := 0; i < accountConcurrency; i++ {
		last := common.BigToHash(new(big.Int).Add(next.Big(), step))
		if i == accountConcurrency-1 {
			// Make sure we don't overflow if the step is not a proper divisor
			last = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		}
		batch := ethdb.HookedBatch{
			Batch: s.db.NewBatch(),
			OnPut: func(key []byte, value []byte) {
				s.accountBytes += common.StorageSize(len(key) + len(value))
			},
		}
		s.tasks = append(s.tasks, &accountTask{
			Next:     next,
			Last:     last,
			SubTasks: make(map[common.Hash][]*storageTask),
			genBatch: batch,
			genTrie:  trie.NewStackTrie(batch),
		})
		log.Debug("Created account sync task", "from", next, "last", last)
		next = common.BigToHash(new(big.Int).Add(last.Big(), common.Big1))
	}
}

// saveSyncStatus marshals the remaining sync tasks into leveldb.
func (s *Syncer) saveSyncStatus() {
	// Serialize any partial progress to disk before spinning down
	for _, task := range s.tasks {
		if err := task.genBatch.Write(); err != nil {
			log.Error("Failed to persist account slots", "err", err)
		}
		for _, subtasks := range task.SubTasks {
			for _, subtask := range subtasks {
				if err := subtask.genBatch.Write(); err != nil {
					log.Error("Failed to persist storage slots", "err", err)
				}
			}
		}
	}
	// Store the actual progress markers
	progress := &SyncProgress{
		Tasks:           s.tasks,
		ChunkSynced:     s.chunkSynced,
		ChunkBytes:      s.chunkBytes,
		ChunkHealSynced: s.chunkHealSynced,
		ChunkHealBytes:  s.chunkHealBytes,
	}
	status, err := json.Marshal(progress)
	if err != nil {
		panic(err) // This can only fail during implementation
	}
	rawdb.WriteSnapshotSyncStatus(s.db, status)
}

// Progress returns the snap sync status statistics.
func (s *Syncer) Progress() (*SyncProgress, *SyncPending) {
	s.lock.Lock()
	defer s.lock.Unlock()

	progress := &SyncProgress{
		ChunkSynced:     s.chunkSynced,
		ChunkBytes:      s.chunkBytes,
		ChunkHealSynced: s.chunkHealSynced,
		ChunkHealBytes:  s.chunkHealBytes,
	}
	pending := new(SyncPending)
	if s.healer != nil {
		pending.ChunkHeal = uint64(len(s.healer.codeTasks))
	}
	return progress, pending
}

// assignChunkTasks attempts to match idle peers to pending code retrievals.
func (s *Syncer) assignChunkTasks(success chan *chunkResponse, fail chan *chunkRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Sort the peers by download capacity to use faster ones if many available
	idlers := &capacitySort{
		ids:  make([]string, 0, len(s.chunkIdlers)),
		caps: make([]int, 0, len(s.chunkIdlers)),
	}
	targetTTL := s.rates.TargetTimeout()
	for id := range s.chunkIdlers {
		if _, ok := s.statelessPeers[id]; ok {
			continue
		}
		idlers.ids = append(idlers.ids, id)
		idlers.caps = append(idlers.caps, s.rates.Capacity(id, ChunksMsg, targetTTL))
	}
	if len(idlers.ids) == 0 {
		return
	}
	sort.Sort(sort.Reverse(idlers))

	// Iterate over all the tasks and try to find a pending one
	for _, task := range s.tasks {
		// Skip any tasks not in the chunk retrieval phase
		if task.res == nil {
			continue
		}
		// Skip tasks that are already retrieving (or done with) all codes
		if len(task.codeTasks) == 0 {
			continue
		}
		// Task pending retrieval, try to find an idle peer. If no such peer
		// exists, we probably assigned tasks for all (or they are stateless).
		// Abort the entire assignment mechanism.
		if len(idlers.ids) == 0 {
			return
		}
		var (
			idle = idlers.ids[0]
			peer = s.peers[idle]
			cap  = idlers.caps[0]
		)
		idlers.ids, idlers.caps = idlers.ids[1:], idlers.caps[1:]

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
		// Generate the network query and send it to the peer
		if cap > maxCodeRequestCount {
			cap = maxCodeRequestCount
		}
		hashes := make([]common.Hash, 0, cap)
		for hash := range task.codeTasks {
			delete(task.codeTasks, hash)
			hashes = append(hashes, hash)
			if len(hashes) >= cap {
				break
			}
		}
		req := &chunkRequest{
			peer:    idle,
			id:      reqid,
			time:    time.Now(),
			deliver: success,
			revert:  fail,
			cancel:  cancel,
			stale:   make(chan struct{}),
			hashes:  hashes,
			task:    task,
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
			if err := peer.RequestChunks(reqid, hashes, maxRequestSize); err != nil {
				log.Debug("Failed to request chunks", "err", err)
				s.scheduleRevertChunkRequest(req)
			}
		}()
	}
}

// assignChunkHealTasks attempts to match idle peers to chunk requests to
// heal any trie errors caused by the snap sync's chunked retrieval model.
func (s *Syncer) assignChunkHealTasks(success chan *chunkHealResponse, fail chan *chunkHealRequest, cancel chan struct{}) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Sort the peers by download capacity to use faster ones if many available
	idlers := &capacitySort{
		ids:  make([]string, 0, len(s.chunkHealIdlers)),
		caps: make([]int, 0, len(s.chunkHealIdlers)),
	}
	targetTTL := s.rates.TargetTimeout()
	for id := range s.chunkHealIdlers {
		if _, ok := s.statelessPeers[id]; ok {
			continue
		}
		idlers.ids = append(idlers.ids, id)
		idlers.caps = append(idlers.caps, s.rates.Capacity(id, ChunksMsg, targetTTL))
	}
	if len(idlers.ids) == 0 {
		return
	}
	sort.Sort(sort.Reverse(idlers))

	// Iterate over pending tasks and try to find a peer to retrieve with
	for len(s.healer.codeTasks) > 0 || s.healer.scheduler.Pending() > 0 {
		// If there are not enough trie tasks queued to fully assign, fill the
		// queue from the state sync scheduler. The trie synced schedules these
		// together with trie nodes, so we need to queue them combined.
		var (
			have = len(s.healer.trieTasks) + len(s.healer.codeTasks)
			want = maxTrieRequestCount + maxCodeRequestCount
		)
		if have < want {
			nodes, paths, codes := s.healer.scheduler.Missing(want - have)
			for i, hash := range nodes {
				s.healer.trieTasks[hash] = paths[i]
			}
			for _, hash := range codes {
				s.healer.codeTasks[hash] = struct{}{}
			}
		}
		// If all the heal tasks are trienodes or already downloading, bail
		if len(s.healer.codeTasks) == 0 {
			return
		}
		// Task pending retrieval, try to find an idle peer. If no such peer
		// exists, we probably assigned tasks for all (or they are stateless).
		// Abort the entire assignment mechanism.
		if len(idlers.ids) == 0 {
			return
		}
		var (
			idle = idlers.ids[0]
			peer = s.peers[idle]
			cap  = idlers.caps[0]
		)
		idlers.ids, idlers.caps = idlers.ids[1:], idlers.caps[1:]

		// Matched a pending task to an idle peer, allocate a unique request id
		var reqid uint64
		for {
			reqid = uint64(rand.Int63())
			if reqid == 0 {
				continue
			}
			if _, ok := s.chunkHealReqs[reqid]; ok {
				continue
			}
			break
		}
		// Generate the network query and send it to the peer
		if cap > maxCodeRequestCount {
			cap = maxCodeRequestCount
		}
		hashes := make([]common.Hash, 0, cap)
		for hash := range s.healer.codeTasks {
			delete(s.healer.codeTasks, hash)

			hashes = append(hashes, hash)
			if len(hashes) >= cap {
				break
			}
		}
		req := &chunkHealRequest{
			peer:    idle,
			id:      reqid,
			time:    time.Now(),
			deliver: success,
			revert:  fail,
			cancel:  cancel,
			stale:   make(chan struct{}),
			hashes:  hashes,
			task:    s.healer,
		}
		req.timeout = time.AfterFunc(s.rates.TargetTimeout(), func() {
			peer.Log().Debug("Chunk heal request timed out", "reqid", reqid)
			s.rates.Update(idle, ChunksMsg, 0, 0)
			s.scheduleRevertChunkHealRequest(req)
		})
		s.chunkHealReqs[reqid] = req
		delete(s.chunkHealIdlers, idle)

		s.pend.Add(1)
		go func() {
			defer s.pend.Done()

			// Attempt to send the remote request and revert if it fails
			if err := peer.RequestChunks(reqid, hashes, maxRequestSize); err != nil {
				log.Debug("Failed to request chunk healers", "err", err)
				s.scheduleRevertChunkHealRequest(req)
			}
		}()
	}
}

// revertRequests locates all the currently pending reuqests from a particular
// peer and reverts them, rescheduling for others to fulfill.
func (s *Syncer) revertRequests(peer string) {
	// Gather the requests first, revertals need the lock too
	s.lock.Lock()
	var accountReqs []*accountRequest
	for _, req := range s.accountReqs {
		if req.peer == peer {
			accountReqs = append(accountReqs, req)
		}
	}
	var chunkReqs []*chunkRequest
	for _, req := range s.chunkReqs {
		if req.peer == peer {
			chunkReqs = append(chunkReqs, req)
		}
	}
	var storageReqs []*storageRequest
	for _, req := range s.storageReqs {
		if req.peer == peer {
			storageReqs = append(storageReqs, req)
		}
	}
	var trienodeHealReqs []*trienodeHealRequest
	for _, req := range s.trienodeHealReqs {
		if req.peer == peer {
			trienodeHealReqs = append(trienodeHealReqs, req)
		}
	}
	var chunkHealReqs []*chunkHealRequest
	for _, req := range s.chunkHealReqs {
		if req.peer == peer {
			chunkHealReqs = append(chunkHealReqs, req)
		}
	}
	s.lock.Unlock()

	// Revert all the requests matching the peer
	for _, req := range accountReqs {
		s.revertAccountRequest(req)
	}
	for _, req := range chunkReqs {
		s.revertChunkRequest(req)
	}
	for _, req := range storageReqs {
		s.revertStorageRequest(req)
	}
	for _, req := range trienodeHealReqs {
		s.revertTrienodeHealRequest(req)
	}
	for _, req := range chunkHealReqs {
		s.revertChunkHealRequest(req)
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
	for _, hash := range req.hashes {
		req.task.codeTasks[hash] = struct{}{}
	}
}

// scheduleRevertChunkHealRequest asks the event loop to clean up a chunk heal
// request and return all failed retrieval tasks to the scheduler for reassignment.
func (s *Syncer) scheduleRevertChunkHealRequest(req *chunkHealRequest) {
	select {
	case req.revert <- req:
		// Sync event loop notified
	case <-req.cancel:
		// Sync cycle got cancelled
	case <-req.stale:
		// Request already reverted
	}
}

// revertChunkHealRequest cleans up a chunk heal request and returns all
// failed retrieval tasks to the scheduler for reassignment.
//
// Note, this needs to run on the event runloop thread to reschedule to idle peers.
// On peer threads, use scheduleRevertChunkHealRequest.
func (s *Syncer) revertChunkHealRequest(req *chunkHealRequest) {
	log.Debug("Reverting chunk heal request", "peer", req.peer)
	select {
	case <-req.stale:
		log.Trace("Chunk heal request already reverted", "peer", req.peer, "reqid", req.id)
		return
	default:
	}
	close(req.stale)

	// Remove the request from the tracked set
	s.lock.Lock()
	delete(s.chunkHealReqs, req.id)
	s.lock.Unlock()

	// If there's a timeout timer still running, abort it and mark the code
	// retrievals as not-pending, ready for resheduling
	req.timeout.Stop()
	for _, hash := range req.hashes {
		req.task.codeTasks[hash] = struct{}{}
	}
}

// processChunkResponse integrates an already validated chunk response
// into the account tasks.
func (s *Syncer) processChunkResponse(res *chunkResponse) {
	batch := s.db.NewBatch()

	var (
		codes uint64
	)
	for i, hash := range res.hashes {
		code := res.codes[i]

		// If the chunk was not delivered, reschedule it
		if code == nil {
			res.task.codeTasks[hash] = struct{}{}
			continue
		}
		// Code was delivered, mark it not needed any more
		for j, account := range res.task.res.accounts {
			if res.task.needCode[j] && hash == common.BytesToHash(account.CodeHash) {
				res.task.needCode[j] = false
				res.task.pend--
			}
		}
		// Push the chunk into a database batch
		codes++
		rawdb.WriteCode(batch, hash, code)
	}
	bytes := common.StorageSize(batch.ValueSize())
	if err := batch.Write(); err != nil {
		log.Crit("Failed to persist chunks", "err", err)
	}
	s.chunkSynced += codes
	s.chunkBytes += bytes

	log.Debug("Persisted set of chunks", "count", codes, "bytes", bytes)

	// If this delivery completed the last pending task, forward the account task
	// to the next chunk
	if res.task.pend == 0 {
		s.forwardAccountTask(res.task)
		return
	}
	// Some accounts are still incomplete, leave as is for the storage and contract
	// task assigners to pick up and fill.
}

// processChunkHealResponse integrates an already validated chunk response
// into the healer tasks.
func (s *Syncer) processChunkHealResponse(res *chunkHealResponse) {
	for i, hash := range res.hashes {
		node := res.codes[i]

		// If the trie node was not delivered, reschedule it
		if node == nil {
			res.task.codeTasks[hash] = struct{}{}
			continue
		}
		// Push the trie node into the state syncer
		s.chunkHealSynced++
		s.chunkHealBytes += common.StorageSize(len(node))

		err := s.healer.scheduler.Process(trie.SyncResult{Hash: hash, Data: node})
		switch err {
		case nil:
		case trie.ErrAlreadyProcessed:
			s.chunkHealDups++
		case trie.ErrNotRequested:
			s.chunkHealNops++
		default:
			log.Error("Invalid chunk processed", "hash", hash, "err", err)
		}
	}
	batch := s.db.NewBatch()
	if err := s.healer.scheduler.Commit(batch); err != nil {
		log.Error("Failed to commit healing data", "err", err)
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to persist healing data", "err", err)
	}
	log.Debug("Persisted set of healing data", "type", "chunk", "bytes", common.StorageSize(batch.ValueSize()))
}

// OnChunks is a callback method to invoke when a batch of contract
// bytes codes are received from a remote peer.
func (s *Syncer) OnChunks(peer SyncPeer, id uint64, chunks []*Chunk) error {
	s.lock.RLock()
	syncing := !s.snapped
	s.lock.RUnlock()

	if syncing {
		return s.onChunks(peer, id, chunks)
	}
	return s.onHealChunks(peer, id, chunks)
}

// onChunks is a callback method to invoke when a batch of contract
// bytes codes are received from a remote peer in the syncing phase.
func (s *Syncer) onChunks(peer SyncPeer, id uint64, chunks []*Chunk) error {
	var size common.StorageSize
	for _, code := range chunks {
		size += common.StorageSize(len(code))
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

	// Response is valid, but check if peer is signalling that it does not have
	// the requested data. For chunk range queries that means the peer is not
	// yet synced.
	if len(chunks) == 0 {
		logger.Debug("Peer rejected chunk request")
		s.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Cross reference the requested chunks with the response to find gaps
	// that the serving node is missing
	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hash := make([]byte, 32)

	codes := make([][]byte, len(req.hashes))
	for i, j := 0, 0; i < len(chunks); i++ {
		// Find the next hash that we've been served, leaving misses with nils
		hasher.Reset()
		hasher.Write(chunks[i])
		hasher.Read(hash)

		for j < len(req.hashes) && !bytes.Equal(hash, req.hashes[j][:]) {
			j++
		}
		if j < len(req.hashes) {
			codes[j] = chunks[i]
			j++
			continue
		}
		// We've either ran out of hashes, or got unrequested data
		logger.Warn("Unexpected chunks", "count", len(chunks)-i)
		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkRequest(req)
		return errors.New("unexpected chunk")
	}
	// Response validated, send it to the scheduler for filling
	response := &chunkResponse{
		task:   req.task,
		hashes: req.hashes,
		codes:  codes,
	}
	select {
	case req.deliver <- response:
	case <-req.cancel:
	case <-req.stale:
	}
	return nil
}

// onHealChunks is a callback method to invoke when a batch of contract
// bytes codes are received from a remote peer in the healing phase.
func (s *Syncer) onHealChunks(peer SyncPeer, id uint64, chunks []*Chunk) error {
	var size common.StorageSize
	for _, code := range chunks {
		size += common.StorageSize(len(code))
	}
	logger := peer.Log().New("reqid", id)
	logger.Trace("Delivering set of healing chunks", "chunks", len(chunks), "bytes", size)

	// Whether or not the response is valid, we can mark the peer as idle and
	// notify the scheduler to assign a new task. If the response is invalid,
	// we'll drop the peer in a bit.
	s.lock.Lock()
	if _, ok := s.peers[peer.ID()]; ok {
		s.chunkHealIdlers[peer.ID()] = struct{}{}
	}
	select {
	case s.update <- struct{}{}:
	default:
	}
	// Ensure the response is for a valid request
	req, ok := s.chunkHealReqs[id]
	if !ok {
		// Request stale, perhaps the peer timed out but came through in the end
		logger.Warn("Unexpected chunk heal packet")
		s.lock.Unlock()
		return nil
	}
	delete(s.chunkHealReqs, id)
	s.rates.Update(peer.ID(), ChunksMsg, time.Since(req.time), len(chunks))

	// Clean up the request timeout timer, we'll see how to proceed further based
	// on the actual delivered content
	if !req.timeout.Stop() {
		// The timeout is already triggered, and this request will be reverted+rescheduled
		s.lock.Unlock()
		return nil
	}

	// Response is valid, but check if peer is signalling that it does not have
	// the requested data. For chunk range queries that means the peer is not
	// yet synced.
	if len(chunks) == 0 {
		logger.Debug("Peer rejected chunk heal request")
		s.statelessPeers[peer.ID()] = struct{}{}
		s.lock.Unlock()

		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkHealRequest(req)
		return nil
	}
	s.lock.Unlock()

	// Cross reference the requested chunks with the response to find gaps
	// that the serving node is missing
	hasher := sha3.NewLegacyKeccak256().(crypto.KeccakState)
	hash := make([]byte, 32)

	codes := make([][]byte, len(req.hashes))
	for i, j := 0, 0; i < len(chunks); i++ {
		// Find the next hash that we've been served, leaving misses with nils
		hasher.Reset()
		hasher.Write(chunks[i])
		hasher.Read(hash)

		for j < len(req.hashes) && !bytes.Equal(hash, req.hashes[j][:]) {
			j++
		}
		if j < len(req.hashes) {
			codes[j] = chunks[i]
			j++
			continue
		}
		// We've either ran out of hashes, or got unrequested data
		logger.Warn("Unexpected healing chunks", "count", len(chunks)-i)
		// Signal this request as failed, and ready for rescheduling
		s.scheduleRevertChunkHealRequest(req)
		return errors.New("unexpected healing chunk")
	}
	// Response validated, send it to the scheduler for filling
	response := &chunkHealResponse{
		task:   req.task,
		hashes: req.hashes,
		codes:  codes,
	}
	select {
	case req.deliver <- response:
	case <-req.cancel:
	case <-req.stale:
	}
	return nil
}

// onHealState is a callback method to invoke when a flat state(account
// or storage slot) is downloded during the healing stage. The flat states
// can be persisted blindly and can be fixed later in the generation stage.
// Note it's not concurrent safe, please handle the concurrent issue outside.
func (s *Syncer) onHealState(paths [][]byte, value []byte) error {
	if len(paths) == 1 {
		var account types.StateAccount
		if err := rlp.DecodeBytes(value, &account); err != nil {
			return nil
		}
		blob := snapshot.SlimAccountRLP(account.Nonce, account.Balance, account.Root, account.CodeHash)
		rawdb.WriteAccountSnapshot(s.stateWriter, common.BytesToHash(paths[0]), blob)
		s.accountHealed += 1
		s.accountHealedBytes += common.StorageSize(1 + common.HashLength + len(blob))
	}
	if len(paths) == 2 {
		rawdb.WriteStorageSnapshot(s.stateWriter, common.BytesToHash(paths[0]), common.BytesToHash(paths[1]), value)
		s.storageHealed += 1
		s.storageHealedBytes += common.StorageSize(1 + 2*common.HashLength + len(value))
	}
	if s.stateWriter.ValueSize() > ethdb.IdealBatchSize {
		s.stateWriter.Write() // It's fine to ignore the error here
		s.stateWriter.Reset()
	}
	return nil
}

// hashSpace is the total size of the 256 bit hash space for accounts.
var hashSpace = new(big.Int).Exp(common.Big2, common.Big256, nil)

// report calculates various status reports and provides it to the user.
func (s *Syncer) report(force bool) {
	if len(s.tasks) > 0 {
		s.reportSyncProgress(force)
		return
	}
	s.reportHealProgress(force)
}

// reportSyncProgress calculates various status reports and provides it to the user.
func (s *Syncer) reportSyncProgress(force bool) {
	// Don't report all the events, just occasionally
	if !force && time.Since(s.logTime) < 8*time.Second {
		return
	}
	// Don't report anything until we have a meaningful progress
	synced := s.chunkBytes
	if synced == 0 {
		return
	}
	accountGaps := new(big.Int)
	for _, task := range s.tasks {
		accountGaps.Add(accountGaps, new(big.Int).Sub(task.Last.Big(), task.Next.Big()))
	}
	accountFills := new(big.Int).Sub(hashSpace, accountGaps)
	if accountFills.BitLen() == 0 {
		return
	}
	s.logTime = time.Now()
	estBytes := float64(new(big.Int).Div(
		new(big.Int).Mul(new(big.Int).SetUint64(uint64(synced)), hashSpace),
		accountFills,
	).Uint64())

	elapsed := time.Since(s.startTime)
	estTime := elapsed / time.Duration(synced) * time.Duration(estBytes)

	// Create a mega progress report
	var (
		progress = fmt.Sprintf("%.2f%%", float64(synced)*100/estBytes)
		accounts = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.accountSynced), s.accountBytes.TerminalString())
		storage  = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.storageSynced), s.storageBytes.TerminalString())
		chunk    = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.chunkSynced), s.chunkBytes.TerminalString())
	)
	log.Info("State sync in progress", "synced", progress, "state", synced,
		"accounts", accounts, "slots", storage, "codes", chunk, "eta", common.PrettyDuration(estTime-elapsed))
}

// reportHealProgress calculates various status reports and provides it to the user.
func (s *Syncer) reportHealProgress(force bool) {
	// Don't report all the events, just occasionally
	if !force && time.Since(s.logTime) < 8*time.Second {
		return
	}
	s.logTime = time.Now()

	// Create a mega progress report
	var (
		chunk = fmt.Sprintf("%v@%v", log.FormatLogfmtUint64(s.chunkHealSynced), s.chunkHealBytes.TerminalString())
	)
	log.Info("State heal in progress", "accounts", accounts, "slots", storage,
		"codes", chunk, "nodes", trienode, "pending", s.healer.scheduler.Pending())
}

// estimateRemainingSlots tries to determine roughly how many slots are left in
// a contract storage, based on the number of keys and the last hash. This method
// assumes that the hashes are lexicographically ordered and evenly distributed.
func estimateRemainingSlots(hashes int, last common.Hash) (uint64, error) {
	if last == (common.Hash{}) {
		return 0, errors.New("last hash empty")
	}
	space := new(big.Int).Mul(math.MaxBig256, big.NewInt(int64(hashes)))
	space.Div(space, last.Big())
	if !space.IsUint64() {
		// Gigantic address space probably due to too few or malicious slots
		return 0, errors.New("too few slots for estimation")
	}
	return space.Uint64() - uint64(hashes), nil
}

// capacitySort implements the Sort interface, allowing sorting by peer message
// throughput. Note, callers should use sort.Reverse to get the desired effect
// of highest capacity being at the front.
type capacitySort struct {
	ids  []string
	caps []int
}

func (s *capacitySort) Len() int {
	return len(s.ids)
}

func (s *capacitySort) Less(i, j int) bool {
	return s.caps[i] < s.caps[j]
}

func (s *capacitySort) Swap(i, j int) {
	s.ids[i], s.ids[j] = s.ids[j], s.ids[i]
	s.caps[i], s.caps[j] = s.caps[j], s.caps[i]
}
