// Copyright 2014 The go-ethereum Authors
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

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

type revision struct {
	id           int
	journalIndex int
}

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

type mergedStatus struct {
	writeCachedStateObjects map[common.Address]*stateObject
	mu                      sync.RWMutex

	originAccountMap map[common.Address]Account
	originStorageMap map[string]common.Hash
	originCode       map[common.Hash]map[common.Hash]Code
}

func NewMerged() *mergedStatus {
	return &mergedStatus{
		writeCachedStateObjects: make(map[common.Address]*stateObject),
		mu:                      sync.RWMutex{},
		originAccountMap:        make(map[common.Address]Account),
		originStorageMap:        make(map[string]common.Hash),
		originCode:              make(map[common.Hash]map[common.Hash]Code),
	}
}

func (m *mergedStatus) getWriteObj(addr common.Address) *stateObject {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.writeCachedStateObjects[addr]
}

func (m *mergedStatus) setWriteObj(addr common.Address, obj *stateObject, txIndex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	obj.lastWriteIndex = txIndex
	m.writeCachedStateObjects[addr] = obj
}

func (m *mergedStatus) getOriginCode(addr common.Hash, codeHash common.Hash) (Code, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, ok := m.originCode[addr]; ok {
		if code, exist := data[codeHash]; exist {
			return code, true
		}
	}
	return nil, false
}

func (m *mergedStatus) setOriginCode(addr common.Hash, codehash common.Hash, code Code) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.originCode[codehash]; !ok {
		m.originCode[addr] = make(map[common.Hash]Code)
	}
	m.originCode[addr][codehash] = code
}

func (m *mergedStatus) MergeWriteObj(newObj *stateObject, txIndex int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pre, exist := m.writeCachedStateObjects[newObj.address]
	if !exist {
		newObj.pendingmu.Lock()
		for k, v := range newObj.dirtyStorage {
			newObj.pendingStorage[k] = v
		}
		newObj.pendingmu.Unlock()
		newObj.lastWriteIndex = txIndex
		m.writeCachedStateObjects[newObj.address] = newObj
		return
	}

	pre.pendingmu.Lock()
	for key, value := range newObj.dirtyStorage {
		pre.pendingStorage[key] = value
	}
	pre.pendingmu.Unlock()

	if bytes.Compare(newObj.CodeHash(), pre.CodeHash()) != 0 {
		pre.code = newObj.code
		pre.dirtyCode = newObj.dirtyCode
	}

	pre.suicided = newObj.suicided
	pre.deleted = newObj.deleted
	pre.data = newObj.data

	pre.lastWriteIndex = txIndex
	m.writeCachedStateObjects[newObj.address] = pre

}

func (m *mergedStatus) setStorage(key []byte, value common.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.originStorageMap[string(key)] = value
}
func (m *mergedStatus) GetStorage(key []byte) (common.Hash, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, exist := m.originStorageMap[string(key)]
	return data, exist
}

func (m *mergedStatus) setOriginAccount(addr common.Address, acc Account) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.originAccountMap[addr] = acc
}

func (m *mergedStatus) GetAccountData(addr common.Address) (*Account, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if r := m.writeCachedStateObjects[addr]; r != nil {
		return &Account{
			Nonce:       r.data.Nonce,
			Balance:     new(big.Int).Set(r.data.Balance),
			CodeHash:    r.data.CodeHash,
			Incarnation: r.data.Incarnation,
			Deleted:     r.data.Deleted,
		}, true
	}

	if r, ok := m.originAccountMap[addr]; ok {
		return &Account{
			Nonce:       r.Nonce,
			Balance:     new(big.Int).Set(r.Balance),
			CodeHash:    r.CodeHash,
			Incarnation: r.Incarnation,
			Deleted:     r.Deleted,
		}, true
	}
	return nil, false
}

func (m *mergedStatus) GetCode(addr common.Address) (Code, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if w := m.writeCachedStateObjects[addr]; w != nil {
		if w.data.Deleted {
			return nil, true
		} else if w.code != nil {
			return w.code, true
		}
	}

	return nil, false

}

func (m *mergedStatus) GetState(addr common.Address, key common.Hash) (common.Hash, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if r := m.writeCachedStateObjects[addr]; r != nil {
		if r.data.Deleted {
			return common.Hash{}, true
		}
		if value, ok := r.pendingStorage[key]; ok {
			return value, ok
		}
	}
	return common.Hash{}, false

}

// StateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
type StateDB struct {
	db   Database
	trie Trie

	snaps         *snapshot.Tree
	snap          snapshot.Snapshot
	snapDestructs map[common.Hash]struct{}
	snapAccounts  map[common.Hash][]byte
	snapStorage   map[common.Hash]map[common.Hash][]byte

	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects        map[common.Address]*stateObject
	stateObjectsPending map[common.Address]struct{} // State objects finalized but not yet written to the trie
	stateObjectsDirty   map[common.Address]struct{} // State objects modified in the current execution

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	thash, bhash common.Hash
	txIndex      int
	logs         map[common.Hash][]*types.Log
	logSize      uint

	preimages map[common.Hash][]byte

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal        *journal
	validRevisions []revision
	nextRevisionId int

	// Measurements gathered during execution for debugging purposes
	AccountReads         time.Duration
	AccountHashes        time.Duration
	AccountUpdates       time.Duration
	AccountCommits       time.Duration
	StorageReads         time.Duration
	StorageHashes        time.Duration
	StorageUpdates       time.Duration
	StorageCommits       time.Duration
	SnapshotAccountReads time.Duration
	SnapshotStorageReads time.Duration
	SnapshotCommits      time.Duration

	MergedSts   *mergedStatus
	MergedIndex int
	RWSet       map[common.Address]bool // true dirty ; false only read
}

// New creates a new state from a given trie.
func New(root common.Hash, db Database, snaps *snapshot.Tree) (*StateDB, error) {
	tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	sdb := &StateDB{
		db:                  db,
		trie:                tr,
		snaps:               snaps,
		stateObjects:        make(map[common.Address]*stateObject),
		stateObjectsPending: make(map[common.Address]struct{}),
		stateObjectsDirty:   make(map[common.Address]struct{}),
		logs:                make(map[common.Hash][]*types.Log),
		preimages:           make(map[common.Hash][]byte),
		journal:             newJournal(),
		MergedSts:           NewMerged(),
		MergedIndex:         -1,
		RWSet:               make(map[common.Address]bool, 0),
	}
	if sdb.snaps != nil {
		if sdb.snap = sdb.snaps.Snapshot(root); sdb.snap != nil {
			sdb.snapDestructs = make(map[common.Hash]struct{})
			sdb.snapAccounts = make(map[common.Hash][]byte)
			sdb.snapStorage = make(map[common.Hash]map[common.Hash][]byte)
		}
	}
	return sdb, nil
}

// setError remembers the first non-nil error it is called with.
func (s *StateDB) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

func (s *StateDB) Error() error {
	return s.dbErr
}

func (s *StateDB) CalReadAndWrite() {
	for addr, _ := range s.stateObjects {
		s.RWSet[addr] = true
	}
}

// Reset clears out all ephemeral state objects from the state db, but keeps
// the underlying state trie to avoid reloading data for the next operations.
func (s *StateDB) Reset(root common.Hash) error {
	tr, err := s.db.OpenTrie(root)
	if err != nil {
		return err
	}
	s.trie = tr
	s.stateObjects = make(map[common.Address]*stateObject)
	s.stateObjectsPending = make(map[common.Address]struct{})
	s.stateObjectsDirty = make(map[common.Address]struct{})
	s.thash = common.Hash{}
	s.bhash = common.Hash{}
	s.txIndex = 0
	s.logs = make(map[common.Hash][]*types.Log)
	s.logSize = 0
	s.preimages = make(map[common.Hash][]byte)
	s.clearJournalAndRefund()

	if s.snaps != nil {
		s.snapAccounts, s.snapDestructs, s.snapStorage = nil, nil, nil
		if s.snap = s.snaps.Snapshot(root); s.snap != nil {
			s.snapDestructs = make(map[common.Hash]struct{})
			s.snapAccounts = make(map[common.Hash][]byte)
			s.snapStorage = make(map[common.Hash]map[common.Hash][]byte)
		}
	}
	return nil
}

func (s *StateDB) AddLog(log *types.Log) {
	s.journal.append(addLogChange{txhash: s.thash})

	log.TxHash = s.thash
	log.BlockHash = s.bhash
	log.TxIndex = uint(s.txIndex)
	log.Index = s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], log)
	s.logSize++
}

func (s *StateDB) GetLogs(hash common.Hash) []*types.Log {
	return s.logs[hash]
}

func (s *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range s.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (s *StateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := s.preimages[hash]; !ok {
		s.journal.append(addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		s.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (s *StateDB) Preimages() map[common.Hash][]byte {
	return s.preimages
}

// AddRefund adds gas to the refund counter
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	s.refund += gas
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
func (s *StateDB) SubRefund(gas uint64) error {
	s.journal.append(refundChange{prev: s.refund})
	if gas > s.refund {
		return fmt.Errorf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund)
	}
	s.refund -= gas
	return nil
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (s *StateDB) Exist(addr common.Address) bool {
	s.RWSet[addr] = false
	return s.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (s *StateDB) Empty(addr common.Address) bool {
	s.RWSet[addr] = false
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

// GetBalance retrieves the balance from the given address or 0 if object not found
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	s.RWSet[addr] = false
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (s *StateDB) GetNonce(addr common.Address) uint64 {
	s.RWSet[addr] = false
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

// TxIndex returns the current transaction index set by Prepare.
func (s *StateDB) TxIndex() int {
	return s.txIndex
}

// BlockHash returns the current block hash set by Prepare.
func (s *StateDB) BlockHash() common.Hash {
	return s.bhash
}

func (s *StateDB) GetCode(addr common.Address) []byte {
	s.RWSet[addr] = false
	if data, exist := s.stateObjects[addr]; exist {
		if bytes.Equal(data.data.CodeHash, emptyCodeHash) {
			return nil
		}
		if data.code != nil && !data.data.Deleted {
			return data.code
		}
	}
	if data, exist := s.MergedSts.GetCode(addr); exist {
		return data
	}

	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(s.db)
	}
	return nil
}

func (s *StateDB) GetCodeSize(addr common.Address) int {
	return len(s.GetCode(addr))
}

func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	s.RWSet[addr] = false
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

// GetState retrieves a value from the given account's storage trie.
func (s *StateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	s.RWSet[addr] = false
	if data, exist := s.stateObjects[addr]; exist {
		if value, dirty := data.dirtyStorage[hash]; dirty {
			return value
		}
	}

	return s.GetCommittedState(addr, hash)
}

// GetProof returns the MerkleProof for a given Account
func (s *StateDB) GetProof(a common.Address) ([][]byte, error) {
	var proof proofList
	err := s.trie.Prove(crypto.Keccak256(a.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetStorageProof returns the StorageProof for given key
func (s *StateDB) GetStorageProof(a common.Address, key common.Hash) ([][]byte, error) {
	var proof proofList
	trie := s.StorageTrie(a)
	if trie == nil {
		return proof, errors.New("storage trie for requested address does not exist")
	}
	err := trie.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (s *StateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	s.RWSet[addr] = false
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		if value, pending := stateObject.pendingStorage[hash]; pending {
			return value
		}
		if data, exist := s.MergedSts.GetState(addr, hash); exist {
			return data
		}
		return stateObject.GetCommittedState(s.db, hash)
	} else {
		if data, exist := s.MergedSts.GetState(addr, hash); exist {
			return data
		}
	}
	return common.Hash{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (s *StateDB) Database() Database {
	return s.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (s *StateDB) StorageTrie(addr common.Address) Trie {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(s)
	cpy.updateTrie(s.db)
	return cpy.getTrie(s.db)
}

func (s *StateDB) HasSuicided(addr common.Address) bool {
	s.RWSet[addr] = false
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (s *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (s *StateDB) SetCode(addr common.Address, code []byte) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code, s.GetCode(addr))
	}
}

func (s *StateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		prevValue := s.GetState(addr, key)
		stateObject.SetState(s.db, key, value, prevValue)
	}
}

// SetStorage replaces the entire storage for the specified account with given
// storage. This function should only be used for debugging.
func (s *StateDB) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetStorage(storage)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (s *StateDB) Suicide(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	s.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (s *StateDB) updateStateObject(obj *stateObject) {
	// Track the amount of time wasted on updating the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Encode the account and update the account trie
	addr := obj.Address()

	data, err := rlp.EncodeToBytes(obj)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	if err = s.trie.TryUpdate(addr[:], data); err != nil {
		s.setError(fmt.Errorf("updateStateObject (%x) error: %v", addr[:], err))
	}

	// If state snapshotting is active, cache the data til commit. Note, this
	// update mechanism is not symmetric to the deletion, because whereas it is
	// enough to track account updates at commit time, deletions need tracking
	// at transaction boundary level to ensure we capture state clearing.
	if s.snap != nil {
		s.snapAccounts[obj.addrHash] = snapshot.SlimAccountRLP(obj.data.Nonce, obj.data.Balance, common.Hash{}, obj.data.CodeHash)
	}
}

// deleteStateObject removes the given object from the state trie.
func (s *StateDB) deleteStateObject(obj *stateObject) {
	// Track the amount of time wasted on deleting the account from the trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountUpdates += time.Since(start) }(time.Now())
	}
	// Delete the account from the trie
	addr := obj.Address()
	if err := s.trie.TryDelete(addr[:]); err != nil {
		s.setError(fmt.Errorf("deleteStateObject (%x) error: %v", addr[:], err))
	}
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context. If you need
// to differentiate between non-existent/just-deleted, use getDeletedStateObject.
func (s *StateDB) getStateObject(addr common.Address) *stateObject {
	if obj := s.getDeletedStateObject(addr); obj != nil && !obj.deleted && !obj.data.Deleted {
		return obj
	}
	return nil
}

// getDeletedStateObject is similar to getStateObject, but instead of returning
// nil for a deleted state object, it returns the actual object with the deleted
// flag set. This is needed by the state journal to revert to the correct s-
// destructed object instead of wiping all knowledge about the state object.
func (s *StateDB) getDeletedStateObject(addr common.Address) *stateObject {
	// Prefer live objects if any is available
	if obj := s.stateObjects[addr]; obj != nil {
		return obj
	}
	// If no live objects are available, attempt to use snapshots
	var (
		data *Account
		err  error
	)
	if s.snap != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.SnapshotAccountReads += time.Since(start) }(time.Now())
		}
		var acc *snapshot.Account
		if acc, err = s.snap.Account(crypto.Keccak256Hash(addr.Bytes())); err == nil {
			if acc == nil {
				return nil
			}
			data = &Account{
				Nonce:    acc.Nonce,
				Balance:  acc.Balance,
				CodeHash: acc.CodeHash,
				//Root:     common.BytesToHash(acc.Root),
			}
			if len(data.CodeHash) == 0 {
				data.CodeHash = emptyCodeHash
			}
			//if data.Root == (common.Hash{}) {
			//	data.Root = emptyRoot
			//}
		}
	}
	// If snapshot unavailable or reading from it failed, load from the database
	if s.snap == nil || err != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.AccountReads += time.Since(start) }(time.Now())
		}

		var exist bool
		data, exist = s.MergedSts.GetAccountData(addr)
		if !exist {
			enc, err := s.trie.TryGet(addr.Bytes())
			if err != nil {
				s.setError(fmt.Errorf("getDeleteStateObject (%x) error: %v", addr.Bytes(), err))
				return nil
			}
			if len(enc) == 0 {
				return nil
			}
			data = new(Account)
			if err := rlp.DecodeBytes(enc, data); err != nil {
				log.Error("Failed to decode state object", "addr", addr, "err", err)
				return nil
			}
			s.MergedSts.setOriginAccount(addr, *data)
		}

	}
	// Insert into the live set
	obj := newObject(s, addr, *data)
	s.setStateObject(obj)
	return obj
}

func (s *StateDB) setStateObject(object *stateObject) {
	s.RWSet[object.address] = true
	s.stateObjects[object.Address()] = object
}

// GetOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *StateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = s.createObject(addr, false)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (s *StateDB) createObject(addr common.Address, contraction bool) (newobj, prev *stateObject) {
	prev = s.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!

	var prevdestruct bool
	if s.snap != nil && prev != nil {
		_, prevdestruct = s.snapDestructs[prev.addrHash]
		if !prevdestruct {
			s.snapDestructs[prev.addrHash] = struct{}{}
		}
	}
	newobj = newObject(s, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		s.journal.append(createObjectChange{account: &addr})
	} else {
		s.journal.append(resetObjectChange{prev: prev, prevdestruct: prevdestruct})
	}

	if contraction {
		if prev != nil {
			newobj.data.Incarnation = prev.data.Incarnation + 1
		} else {
			newobj.data.Incarnation = 0
		}
	}
	s.setStateObject(newobj)
	if prev != nil && !prev.deleted {
		return newobj, prev
	}
	return newobj, nil
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (s *StateDB) CreateAccount(addr common.Address, contract bool) {
	newObj, prev := s.createObject(addr, contract)
	if prev != nil {
		newObj.setBalance(prev.data.Balance)
	}
}

func (db *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) error {
	so := db.getStateObject(addr)
	if so == nil {
		return nil
	}
	it := trie.NewIterator(so.getTrie(db.db).NodeIterator(nil))

	for it.Next() {
		key := common.BytesToHash(db.trie.GetKey(it.Key))
		if value, dirty := so.dirtyStorage[key]; dirty {
			if !cb(key, value) {
				return nil
			}
			continue
		}

		if len(it.Value) > 0 {
			_, content, _, err := rlp.Split(it.Value)
			if err != nil {
				return err
			}
			if !cb(key, common.BytesToHash(content)) {
				return nil
			}
		}
	}
	return nil
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (s *StateDB) Copy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	state := &StateDB{
		db:           s.db,
		trie:         trie.NewFastDB(s.db.TrieDB()),
		stateObjects: make(map[common.Address]*stateObject, len(s.journal.dirties)),
		logs:         make(map[common.Hash][]*types.Log, 0),
		preimages:    make(map[common.Hash][]byte, len(s.preimages)),
		journal:      newJournal(),
		RWSet:        make(map[common.Address]bool),
	}

	for addr := range s.stateObjects {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = s.stateObjects[addr].deepCopy(state)
		}
	}
	return state
}

// Snapshot returns an identifier for the current revision of the state.
func (s *StateDB) Snapshot() int {
	id := s.nextRevisionId
	s.nextRevisionId++
	s.validRevisions = append(s.validRevisions, revision{id, s.journal.length()})
	return id
}

func (s *StateDB) Conflict(base *StateDB, miners common.Address, useFake bool, indexToID map[int]int) bool {
	for k, _ := range s.RWSet {
		if miners == k {
			if useFake || s.MergedIndex+1 != s.txIndex {
				return true
			} else {
				continue
			}
		}

		preWrite := s.MergedSts.getWriteObj(k)
		if preWrite != nil {
			if indexToID[s.txIndex] != indexToID[preWrite.lastWriteIndex] {
				if useFake || s.MergedIndex != base.MergedIndex {
					return true
				}
			} else {
				if preWrite.lastWriteIndex > s.MergedIndex {
					return true
				}
			}

		}

	}

	return false
}

func (s *StateDB) Merge(base *StateDB, miner common.Address, txFee *big.Int) {
	for _, newObj := range s.stateObjects {
		s.MergedSts.MergeWriteObj(newObj, s.txIndex)
	}

	pre := base.MergedSts.getWriteObj(miner)
	if pre == nil {
		base.AddBalance(miner, txFee)
		base.MergedSts.setWriteObj(miner, base.getStateObject(miner), s.txIndex)
		base.stateObjects = make(map[common.Address]*stateObject)
	} else {
		pre.AddBalance(txFee)
	}
}

func (s *StateDB) MergeReward(txIndex int) {
	for _, v := range s.stateObjects {
		s.MergedSts.MergeWriteObj(v, txIndex)
	}
	s.stateObjects = make(map[common.Address]*stateObject)
}

func (s *StateDB) FinalUpdateObjs() {
	for addr, obj := range s.MergedSts.writeCachedStateObjects {
		s.stateObjects[addr] = obj
	}
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (s *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(s.validRevisions), func(i int) bool {
		return s.validRevisions[i].id >= revid
	})
	if idx == len(s.validRevisions) || s.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	snapshot := s.validRevisions[idx].journalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	s.journal.revert(s, snapshot)
	s.validRevisions = s.validRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
func (s *StateDB) GetRefund() uint64 {
	return s.refund
}

// Finalise finalises the state by removing the s destructed objects and clears
// the journal as well as the refunds. Finalise, however, will not push any updates
// into the tries just yet. Only IntermediateRoot or Commit will do that.
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	for _, obj := range s.stateObjects {
		if obj.suicided || (deleteEmptyObjects && obj.empty()) {
			obj.deleted = true
			obj.data.Deleted = true

			// If state snapshotting is active, also mark the destruction there.
			// Note, we can't do this only at the end of a block because multiple
			// transactions within the same block might self destruct and then
			// ressurrect an account; but the snapshotter needs both events.
			if s.snap != nil {
				s.snapDestructs[obj.addrHash] = struct{}{} // We need to maintain account deletions explicitly (will remain set indefinitely)
				delete(s.snapAccounts, obj.addrHash)       // Clear out any previously updated account data (may be recreated via a ressurrect)
				delete(s.snapStorage, obj.addrHash)        // Clear out any previously updated storage data (may be recreated via a ressurrect)
			}
		} else {
			//obj.finalise()
		}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	//s.clearJournalAndRefund()
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	// Finalise all the dirty storage states and write them into the tries
	s.Finalise(deleteEmptyObjects)

	for addr := range s.stateObjects {
		obj := s.stateObjects[addr]
		if obj.deleted {
			obj.data.Deleted = true
		}
		if isCommit {
			obj.updateRoot(s.db)
			s.updateStateObject(obj)
		}
	}

	if !isCommit {
		return common.Hash{}
	}
	// Track the amount of time wasted on hashing the account trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.AccountHashes += time.Since(start) }(time.Now())
	}
	return s.trie.Hash()
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (s *StateDB) Prepare(thash, bhash common.Hash, ti int) {
	s.thash = thash
	s.bhash = bhash
	s.txIndex = ti
}

func (s *StateDB) clearJournalAndRefund() {
	if len(s.journal.entries) > 0 {
		s.journal = newJournal()
		s.refund = 0
	}
	s.validRevisions = s.validRevisions[:0] // Snapshots can be created without journal entires
}

var (
	isCommit = bool(false)
)

// Commit writes the state to the underlying in-memory trie database.
func (s *StateDB) Commit(deleteEmptyObjects bool) (common.Hash, error) {
	isCommit = true
	defer func() {
		isCommit = false
	}()
	if s.dbErr != nil {
		return common.Hash{}, fmt.Errorf("commit aborted due to earlier error: %v", s.dbErr)
	}
	// Finalize any pending changes and merge everything into the tries
	s.IntermediateRoot(deleteEmptyObjects)
	isCommit = false
	// Commit objects to the trie, measuring the elapsed time
	codeWriter := s.db.TrieDB().DiskDB().NewBatch()
	for addr := range s.stateObjects {
		if obj := s.stateObjects[addr]; !obj.deleted {
			// Write any contract code associated with the state object
			if obj.code != nil && obj.dirtyCode {
				rawdb.WriteCode(codeWriter, common.BytesToHash(obj.CodeHash()), obj.code)
				obj.dirtyCode = false
			}

			// Write any storage changes in the state object to its storage trie
			if err := obj.CommitTrie(s.db); err != nil {
				return common.Hash{}, err
			}
		}
	}
	if codeWriter.ValueSize() > 0 {
		if err := codeWriter.Write(); err != nil {
			log.Crit("Failed to commit dirty codes", "error", err)
		}
	}
	// Write the account trie changes, measuing the amount of wasted time
	var start time.Time
	if metrics.EnabledExpensive {
		start = time.Now()
	}
	// The onleaf func is called _serially_, so we can reuse the same account
	// for unmarshalling every time.
	var account Account
	root, err := s.trie.Commit(func(leaf []byte, parent common.Hash) error {
		if err := rlp.DecodeBytes(leaf, &account); err != nil {
			return nil
		}
		//if account.Root != emptyRoot {
		//	s.db.TrieDB().Reference(account.Root, parent)
		//}
		return nil
	})
	if metrics.EnabledExpensive {
		s.AccountCommits += time.Since(start)
	}
	// If snapshotting is enabled, update the snapshot tree with this new version
	if s.snap != nil {
		if metrics.EnabledExpensive {
			defer func(start time.Time) { s.SnapshotCommits += time.Since(start) }(time.Now())
		}
		// Only update if there's a state transition (skip empty Clique blocks)
		if parent := s.snap.Root(); parent != root {
			if err := s.snaps.Update(root, parent, s.snapDestructs, s.snapAccounts, s.snapStorage); err != nil {
				log.Warn("Failed to update snapshot tree", "from", parent, "to", root, "err", err)
			}
			if err := s.snaps.Cap(root, 127); err != nil { // Persistent layer is 128th, the last available trie
				log.Warn("Failed to cap snapshot tree", "root", root, "layers", 127, "err", err)
			}
		}
		s.snap, s.snapDestructs, s.snapAccounts, s.snapStorage = nil, nil, nil, nil
	}
	return root, err
}
