// Copyright 2022 The go-ethereum Authors
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

// This file contains a miner stress test based on the Tendermint consensus engine.
package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/fdlimit"
	"github.com/ethereum/go-ethereum/consensus/tendermint"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func main() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	fdlimit.Raise(2048)

	tendermint.EnableTestMode()
	// Generate a batch of accounts to seal and fund with
	faucets := make([]*ecdsa.PrivateKey, 128)
	for i := 0; i < len(faucets); i++ {
		faucets[i], _ = crypto.GenerateKey()
	}
	sealers := make([]*ecdsa.PrivateKey, 4)
	for i := 0; i < len(sealers); i++ {
		sealers[i], _ = crypto.GenerateKey()
	}

	// Create a Clique network based off of the Rinkeby config
	genesis := makeGenesis(faucets, sealers)

	log.Warn("genesis", "NextValidators", genesis.NextValidators)

	// Handle interrupts.
	interruptCh := make(chan os.Signal, 5)
	signal.Notify(interruptCh, os.Interrupt)

	var (
		stacks []*node.Node
		nodes  []*eth.Ethereum
		enodes []*enode.Node
	)
	for _, sealer := range sealers {
		// Start the node and wait until it's up
		stack, ethBackend, err := makeSealer(genesis)
		if err != nil {
			panic(err)
		}
		defer stack.Close()

		for stack.Server().NodeInfo().Ports.Listener == 0 {
			time.Sleep(250 * time.Millisecond)
		}
		// Connect the node to all the previous ones
		for _, n := range enodes {
			stack.Server().AddPeer(n)
		}

		// Start tracking the node and its enode
		stacks = append(stacks, stack)
		nodes = append(nodes, ethBackend)
		enodes = append(enodes, stack.Server().Self())

		// Inject the signer key and start sealing with it
		ks := keystore.NewKeyStore(stack.KeyStoreDir(), keystore.LightScryptN, keystore.LightScryptP)
		signer, err := ks.ImportECDSA(sealer, "")
		if err != nil {
			panic(err)
		}
		if err := ks.Unlock(signer, ""); err != nil {
			panic(err)
		}
		stack.AccountManager().AddBackend(ks)
	}

	// Iterate over all the nodes and start signing on them
	time.Sleep(3 * time.Second)

	var maddrs []ma.Multiaddr
	for _, node := range nodes {
		if err := node.StartMining(1); err != nil {
			panic(err)
		}

		// Connect libp2p
		tm := node.Engine().(*tendermint.Tendermint)
		for {
			select {
			case <-interruptCh:
				for _, node := range stacks {
					node.Close()
				}
				return
			default:
			}

			if tm.P2pServer() == nil {
				log.Info("P2pServer nil")
				time.Sleep(250 * time.Millisecond)
				continue
			}
			host := tm.P2pServer().Host
			if host == nil {
				log.Info("host nil")
				time.Sleep(250 * time.Millisecond)
				continue
			}
			network := host.Network()
			if network == nil {
				log.Info("network nil")
				time.Sleep(250 * time.Millisecond)
				continue
			}
			if len(network.ListenAddresses()) == 0 {
				log.Info("network #listen addr = 0")
				time.Sleep(250 * time.Millisecond)
				continue
			}
			break
		}
		for _, maddr := range maddrs {

			pi, err := peer.AddrInfoFromP2pAddr(maddr)
			if err != nil {
				log.Warn("AddrInfoFromP2pAddr failed", "err", err, "ma", maddr)
				continue
			}
			err = tm.P2pServer().Host.Connect(context.Background(), *pi)
			if err != nil {
				log.Warn("Host.Connect failed", "err", err)
			} else {
				log.Info("Host.Connect success")
			}
		}
		listenAddr, err := tm.P2pServer().Host.Network().InterfaceListenAddresses()
		if err != nil {
			panic(fmt.Sprintf("InterfaceListenAddresses failed:%v", err))
		}

		addr, err := ma.NewMultiaddr(fmt.Sprintf("/p2p/%s", tm.P2pServer().Host.ID()))
		var p2pAddr []ma.Multiaddr
		for _, ma := range listenAddr {
			p2pAddr = append(p2pAddr, ma.Encapsulate(addr))
		}
		maddrs = append(maddrs, p2pAddr...)
	}
	time.Sleep(3 * time.Second)

	// Start injecting transactions from the faucet like crazy
	nonces := make([]uint64, len(faucets))
	for {
		// Stop when interrupted.
		select {
		case <-interruptCh:
			for _, node := range stacks {
				node.Close()
			}
			return
		default:
			// after the block halting issue is fixed, should comment out this code block
			// {
			// 	for i, node := range nodes {
			// 		tm := node.Engine().(*tendermint.Tendermint)
			// 		ps := tm.P2pServer().Host.Network().Peers()
			// 		log.Info("node peers", "#peers", len(ps), "i", i)
			// 	}
			// 	time.Sleep(time.Second)
			// 	continue
			// }
		}

		// Pick a random signer node
		index := rand.Intn(len(faucets))
		backend := nodes[index%len(nodes)]

		// Create a self transaction and inject into the pool
		tx, err := types.SignTx(types.NewTransaction(nonces[index], crypto.PubkeyToAddress(faucets[index].PublicKey), new(big.Int), 21000, big.NewInt(100000000000), nil), types.HomesteadSigner{}, faucets[index])
		if err != nil {
			panic(err)
		}
		if err := backend.TxPool().AddLocal(tx); err != nil {
			panic(err)
		}
		nonces[index]++

		// Wait if we're too saturated
		if pend, _ := backend.TxPool().Stats(); pend > 2048 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// makeGenesis creates a custom Clique genesis block based on some pre-defined
// signer and faucet accounts.
func makeGenesis(faucets []*ecdsa.PrivateKey, sealers []*ecdsa.PrivateKey) *core.Genesis {
	// Create a Clique network based off of the Rinkeby config
	genesis := core.DefaultWeb3QGalileoGenesisBlock()
	genesis.GasLimit = 25000000
	genesis.Config.Tendermint.P2pPort = 0
	genesis.Config.Tendermint.P2pBootstrap = ""
	genesis.Config.Tendermint.MaxPeerCount = 50

	genesis.Alloc = core.GenesisAlloc{}
	for _, faucet := range faucets {
		genesis.Alloc[crypto.PubkeyToAddress(faucet.PublicKey)] = core.GenesisAccount{
			Balance: new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil),
		}
	}
	// Sort the signers and embed into the extra-data section
	signers := make([]common.Address, len(sealers))
	powers := make([]uint64, len(sealers))
	for i, sealer := range sealers {
		signers[i] = crypto.PubkeyToAddress(sealer.PublicKey)
		powers[i] = 1
	}

	genesis.NextValidators = signers
	genesis.NextValidatorPowers = powers
	// Return the genesis block for initialization
	return genesis
}

func makeSealer(genesis *core.Genesis) (*node.Node, *eth.Ethereum, error) {
	// Define the basic configurations for the Ethereum node
	datadir, _ := ioutil.TempDir("", "")

	config := &node.Config{
		Name:    "geth",
		Version: params.Version,
		DataDir: datadir,
		P2P: p2p.Config{
			ListenAddr:  "0.0.0.0:0",
			NoDiscovery: true,
			MaxPeers:    25,
		},
	}
	// Start the node and configure a full Ethereum node on it
	stack, err := node.New(config)
	if err != nil {
		return nil, nil, err
	}
	// Create and register the backend
	ethBackend, err := eth.New(stack, &ethconfig.Config{
		Genesis:         genesis,
		NetworkId:       genesis.Config.ChainID.Uint64(),
		SyncMode:        downloader.FullSync,
		DatabaseCache:   256,
		DatabaseHandles: 256,
		TxPool:          core.DefaultTxPoolConfig,
		GPO:             ethconfig.Defaults.GPO,
		Miner: miner.Config{
			GasCeil:  genesis.GasLimit * 11 / 10,
			GasPrice: big.NewInt(1),
			Recommit: time.Second,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	err = stack.Start()
	return stack, ethBackend, err
}
