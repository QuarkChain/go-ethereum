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

// Package miner implements Ethereum block creation and mining.
package sstorminer

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/protocols/sstorage"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/trie"
)

type mockBackend struct {
	bc     *core.BlockChain
	txPool *core.TxPool
}

func NewMockBackend(bc *core.BlockChain, txPool *core.TxPool) *mockBackend {
	return &mockBackend{
		bc:     bc,
		txPool: txPool,
	}
}

func (m *mockBackend) BlockChain() *core.BlockChain {
	return m.bc
}

func (m *mockBackend) TxPool() *core.TxPool {
	return m.txPool
}

type testBlockChain struct {
	statedb       *state.StateDB
	gasLimit      uint64
	chainHeadFeed *event.Feed
}

func (bc *testBlockChain) CurrentBlock() *types.Block {
	return types.NewBlock(&types.Header{
		GasLimit: bc.gasLimit,
	}, nil, nil, nil, trie.NewStackTrie(nil))
}

func (bc *testBlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return bc.CurrentBlock()
}

func (bc *testBlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *testBlockChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func TestMiner(t *testing.T) {
	miner, mux, cleanup := createMiner(t)
	defer cleanup(false)
	waitForMiningState(t, miner, false)
	// start miner, but the
	miner.Start()
	waitForMiningState(t, miner, false)
	// Start the downloader
	mux.Post(sstorage.SstorSyncDone{})
	waitForMiningState(t, miner, true)
}

func TestMinerStartStopAfterSyncDoneEvents(t *testing.T) {
	miner, mux, cleanup := createMiner(t)
	defer cleanup(false)
	miner.Start()
	waitForMiningState(t, miner, false)
	// Start the downloader
	mux.Post(sstorage.SstorSyncDone{})
	waitForMiningState(t, miner, true)

	miner.Stop()
	waitForMiningState(t, miner, false)

	miner.Start()
	waitForMiningState(t, miner, true)

	miner.Stop()
	waitForMiningState(t, miner, false)
}

func TestStartAfterDownload(t *testing.T) {
	miner, mux, cleanup := createMiner(t)
	defer cleanup(false)
	waitForMiningState(t, miner, false)
	// Stop the downloader and wait for the update loop to run
	mux.Post(sstorage.SstorSyncDone{})
	waitForMiningState(t, miner, false)
	// Starting the miner after the downloader should not work
	miner.Start()
	waitForMiningState(t, miner, true)
}

func TestStartStopMiner(t *testing.T) {
	miner, mux, cleanup := createMiner(t)
	defer cleanup(false)
	waitForMiningState(t, miner, false)
	mux.Post(sstorage.SstorSyncDone{})
	miner.Start()
	waitForMiningState(t, miner, true)
	miner.Stop()
	waitForMiningState(t, miner, false)
}

func TestCloseMiner(t *testing.T) {
	miner, mux, cleanup := createMiner(t)
	defer cleanup(true)
	waitForMiningState(t, miner, false)
	mux.Post(sstorage.SstorSyncDone{})
	miner.Start()
	waitForMiningState(t, miner, true)
	// Terminate the miner and wait for the update loop to run
	miner.Close()
	waitForMiningState(t, miner, false)
}

// waitForMiningState waits until either
// * the desired mining state was reached
// * a timeout was reached which fails the test
func waitForMiningState(t *testing.T, m *Miner, mining bool) {
	t.Helper()

	var state bool
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if state = m.Mining(); state == mining {
			return
		}
	}
	t.Fatalf("Mining() == %t, want %t", state, mining)
}

func createMiner(t *testing.T) (*Miner, *event.TypeMux, func(skipMiner bool)) {
	// Create Ethash config
	config := Config{}
	// Create chainConfig
	memdb := memorydb.New()
	chainDB := rawdb.NewDatabase(memdb)
	genesis := core.DeveloperGenesisBlock(15, 11_500_000, common.HexToAddress("12345"))
	chainConfig, _, err := core.SetupGenesisBlock(chainDB, genesis)
	if err != nil {
		t.Fatalf("can't create new chain config: %v", err)
	}
	// Create consensus engine
	engine := clique.New(chainConfig.Clique, chainDB)
	// Create Ethereum backend
	bc, err := core.NewBlockChain(chainDB, nil, chainConfig, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("can't create new chain %v", err)
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(chainDB), nil)
	blockchain := &testBlockChain{statedb, 10000000, new(event.Feed)}

	pool := core.NewTxPool(testTxPoolConfig, chainConfig, blockchain)
	backend := NewMockBackend(bc, pool)
	// Create event Mux
	mux := new(event.TypeMux)
	// Create Miner
	miner := New(backend, nil, &config, chainConfig, mux, nil, common.Address{})
	cleanup := func(skipMiner bool) {
		bc.Stop()
		engine.Close()
		pool.Stop()
		if !skipMiner {
			miner.Close()
		}
	}
	return miner, mux, cleanup
}
