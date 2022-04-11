package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/consensus/tendermint/p2p"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
)

var (
	p2pNetworkID  *string
	p2pPort       *uint
	p2pBootstrap  *string
	nodeKeyPath   *string
	valKeyPath    *string
	nodeName      *string
	verbosity     *int
	datadir       *string
	validatorSet  *[]string
	genesisTimeMs *uint64
	skipBlockSync *bool
	powerStr      *string

	timeoutCommitMs    *uint64
	consensusSyncMs    *uint64
	proposerRepetition *uint64
	maxPeerCount       *int
)

var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Run the bridge server",
	Run:   runNode,
}

func init() {
	p2pNetworkID = NodeCmd.Flags().String("network", "/mpbft/dev", "P2P network identifier")
	p2pPort = NodeCmd.Flags().Uint("port", 8999, "P2P UDP listener port")
	p2pBootstrap = NodeCmd.Flags().String("bootstrap", "", "P2P bootstrap peers (comma-separated)")

	nodeName = NodeCmd.Flags().String("nodeName", "", "Node name to announce in gossip heartbeats")
	nodeKeyPath = NodeCmd.Flags().String("nodeKey", "", "Path to node key (will be generated if it doesn't exist)")

	verbosity = NodeCmd.Flags().Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail")

	valKeyPath = NodeCmd.Flags().String("valKey", "", "Path to validator key (empty if not a validator)")

	datadir = NodeCmd.Flags().String("datadir", "./datadir", "Path to database")

	validatorSet = NodeCmd.Flags().StringArray("validatorSet", []string{}, "List of validators")
	genesisTimeMs = NodeCmd.Flags().Uint64("genesisTimeMs", 0, "Genesis block timestamp")
	skipBlockSync = NodeCmd.Flags().Bool("skipBlockSync", false, "Skip block sync")
	powerStr = NodeCmd.Flags().String("valPowers", "", "comma seperated voting powers")

	timeoutCommitMs = NodeCmd.Flags().Uint64("timeoutCommitMs", 5000, "Timeout commit in ms")
	consensusSyncMs = NodeCmd.Flags().Uint64("consensusSyncMs", 500, "Consensus sync in ms")
	proposerRepetition = NodeCmd.Flags().Uint64("proposerRepetition", 8, "proposer repetition")

	maxPeerCount = NodeCmd.Flags().Int("maxPeerCount", 10, "proposer repetition")
}

func runNode(cmd *cobra.Command, args []string) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	log.Root().SetHandler(glogger)

	// setup logger
	var ostream log.Handler
	output := io.Writer(os.Stderr)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))

	glogger.SetHandler(ostream)

	// Node's main lifecycle context.
	rootCtx, rootCtxCancel := context.WithCancel(context.Background())
	defer rootCtxCancel()

	// Outbound gossip message queue
	sendC := make(chan consensus.Message, 1000)

	// Inbound observations
	obsvC := make(chan consensus.MsgInfo, 1000)

	// Load p2p private key
	var p2pPriv p2pcrypto.PrivKey
	p2pPriv, err := getOrCreateNodeKey(*nodeKeyPath)
	if err != nil {
		log.Error("Failed to load node key", "err", err)
		return
	}

	if *nodeKeyPath == "" {
		log.Error("Please specify --nodeKey")
		return
	}

	// Check genesis timestamp
	if *genesisTimeMs == 0 {
		log.Error("Please specify --genesisTimeMs")
		return
	}

	// Read private key if the node is a validator
	var privVal consensus.PrivValidator
	var pubVal consensus.PubKey

	if *valKeyPath != "" {
		valKey, err := loadValidatorKey(*valKeyPath)
		if err != nil {
			log.Error("Failed to load validator key", "err", err)
			return
		}
		privVal = consensus.NewPrivValidatorLocal(valKey)
		pubVal, err = privVal.GetPubKey(rootCtx)
		if err != nil {
			log.Error("Failed to load valiator pub key", "err", err)
			return
		}
		log.Info("Running validator", "addr", pubVal.Address())
	}

	// Update validators
	vals := make([]common.Address, len(*validatorSet))
	found := false
	for i, addrStr := range *validatorSet {
		addr := common.HexToAddress(addrStr)
		if pubVal != nil && addr == pubVal.Address() {
			found = true
		}
		vals[i] = addr
	}

	powers := make([]int64, len(vals))
	if *powerStr == "" {
		log.Info("Set all validator power = 1")
		for i := 0; i < len(powers); i++ {
			powers[i] = 1
		}
	} else {
		ss := strings.Split(*powerStr, ",")
		if len(ss) != len(powers) {
			log.Error("Invalid power string", "str", *powerStr)
			return
		}
		for i, s := range ss {
			p, err := strconv.Atoi(s)
			powers[i] = int64(p)
			if err != nil {
				log.Error("Invalid power string", "err", err)
				return
			}
		}
	}

	if pubVal != nil && !found {
		log.Error("Current validator is not in validator set")
		return
	} else {
		log.Info("Validators", "vals", vals, "powers", powers)
	}

	gcs := consensus.MakeGenesisChainState("test", *genesisTimeMs, vals, powers, 128, int64(*proposerRepetition))

	db, err := leveldb.OpenFile(*datadir, &opt.Options{ErrorIfExist: true})
	if err != nil {
		log.Error("Failed to create db", "err", err)
		return
	}

	bs := NewDefaultBlockStore(db)
	executor := consensus.NewDefaultBlockExecutor(db)

	p2pserver, err := p2p.NewP2PServer(rootCtx, bs, obsvC, sendC, p2pPriv, *p2pPort, *p2pNetworkID, *p2pBootstrap, *nodeName, rootCtxCancel, *maxPeerCount)

	go func() {
		p2pserver.Run(rootCtx)
	}()

	// TODO: make sure we have sufficient peer node to sync
	time.Sleep(time.Second)

	if len(vals) == 1 && pubVal != nil && vals[0] == pubVal.Address() {
		log.Info("Running in self validator mode, skipping block sync")
	} else if *skipBlockSync {
		log.Info("Skipping block sync by config")
	} else {
		bs := p2p.NewBlockSync(p2pserver.Host, *gcs, bs, executor, obsvC)
		bs.Start(rootCtx)
		err := bs.WaitDone()
		if err != nil {
			log.Error("Failed in block sync", "err", err)
			return
		}

		*gcs = bs.LastChainState()
	}

	p := params.NewDefaultConsesusConfig()
	p.TimeoutCommit = time.Duration(*timeoutCommitMs) * time.Millisecond
	p.ConsensusSyncRequestDuration = time.Duration(*consensusSyncMs) * time.Millisecond

	// Block sync is done, now entering consensus stage
	consensusState := consensus.NewConsensusState(
		rootCtx,
		p,
		*gcs,
		executor,
		bs,
		obsvC,
		sendC,
	)

	consensusState.SetPrivValidator(privVal)

	p2pserver.SetConsensusState(consensusState)

	consensusState.Start(rootCtx)

	// Running the node
	log.Info("Running the node")

	<-rootCtx.Done()
}

func getOrCreateNodeKey(path string) (p2pcrypto.PrivKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("No node key found, generating a new one...", "path", path)

			priv, _, err := p2pcrypto.GenerateKeyPair(p2pcrypto.Ed25519, -1)
			if err != nil {
				panic(err)
			}

			s, err := p2pcrypto.MarshalPrivateKey(priv)
			if err != nil {
				panic(err)
			}

			err = ioutil.WriteFile(path, s, 0600)
			if err != nil {
				return nil, fmt.Errorf("failed to write node key: %w", err)
			}

			return priv, nil
		} else {
			return nil, fmt.Errorf("failed to read node key: %w", err)
		}
	}

	priv, err := p2pcrypto.UnmarshalPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal node key: %w", err)
	}

	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		panic(err)
	}

	log.Info("Found existing node key",
		"path", path,
		"peerID", peerID)

	return priv, nil
}
