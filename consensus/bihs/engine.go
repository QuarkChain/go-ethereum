package bihs

import (
	"context"
	"fmt"
	"math/big"
	"path"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/bihs/adapter"
	"github.com/ethereum/go-ethereum/consensus/bihs/gov"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	ethcore "github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	ocommon "github.com/ontio/ontology/common"
	"github.com/zhiqiangxu/bihs"
	"github.com/zhiqiangxu/util"
)

type BiHS struct {
	sync.Once
	wg         sync.WaitGroup
	nodeConfig *node.Config
	bihsConfig *params.BiHSConfig
	signer     *adapter.Signer
	db         ethdb.Database
	core       *bihs.HotStuff
	gov        *gov.Governance
	p2p        *adapter.P2P

	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	commitCh     chan *types.Block
}

func New(bihsConfig *params.BiHSConfig, nodeConfig *node.Config, db ethdb.Database) *BiHS {
	privateKey := nodeConfig.NodeKey()
	log.Info("node", crypto.PubkeyToAddress(privateKey.PublicKey).Hex())
	signer := adapter.NewSigner(privateKey)

	return &BiHS{
		nodeConfig:  nodeConfig,
		bihsConfig:  bihsConfig,
		signer:      signer,
		db:          db,
		chainHeadCh: make(chan core.ChainHeadEvent, 1),
		commitCh:    make(chan *types.Block, 1),
	}
}

func (bh *BiHS) Init(chain *ethcore.BlockChain, bc adapter.Broadcaster, consensusMsgCode int, prepareEmptyHeaderFunc func() *types.Header, saveBlockFunc func(block *types.Block)) {

	adapter.ConsensusMsgCode = uint64(consensusMsgCode)

	dir := path.Join(bh.nodeConfig.DataDir, "bihs")
	proposer := bh.signer.Address()
	bihsConfig := bh.bihsConfig

	conf := bihs.Config{
		BlockInterval:    time.Duration(bihsConfig.Period) * time.Second,
		DataDir:          dir,
		ProposerID:       proposer[:],
		EcSigner:         bh.signer,
		Logger:           &adapter.Logger{},
		DefaultBlockFunc: adapter.DefaultBlock,
	}

	governance := gov.New(chain)

	store := adapter.NewStateDB(chain, governance, prepareEmptyHeaderFunc, saveBlockFunc, bh.VerifyHeader)
	p2p := adapter.NewP2P(bc, chain, governance)

	core := bihs.New(store, p2p, conf)
	bh.core = core
	bh.gov = governance
	bh.p2p = p2p

	bh.chainHeadSub = chain.SubscribeChainHeadEvent(bh.chainHeadCh)
	util.GoFunc(&bh.wg, func() {
		for {
			select {
			case <-bh.chainHeadCh:
				store.HeightChanged()
			case <-bh.chainHeadSub.Err():
				return
			}
		}
	})
}

func (bh *BiHS) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (bh *BiHS) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return bh.verifyHeader(chain, header, nil, seal)
}

func (bh *BiHS) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := bh.verifyHeader(chain, header, headers[:i], seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (bh *BiHS) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errUnclesNotAllowed
	}
	return nil
}

func (bh *BiHS) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header, seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if header.Time <= parent.Time {
		return errInvalidTime
	}

	if header.Time > uint64(time.Now().Unix()+deltaSeconds) {
		log.Info("bihs.verifyHeader", "header.Time", header.Time, "now", time.Now().Unix(), "deltaSeconds", deltaSeconds, "coinbase", header.Coinbase, "parent.Time", parent.Time)
		return consensus.ErrFutureBlock
	}

	if header.Coinbase == (common.Address{}) {
		// empty block
		if header.GasLimit != parent.GasLimit {
			return errInvalidGasLimitForEmptyBlock
		}
		if header.Time != parent.Time+1 {
			return errInvalidTimeForEmptyBlock
		}
		if header.Root != parent.Root {
			return errInvalidRootForEmptyBlock
		}
		if header.TxHash != types.EmptyRootHash {
			return errInvalidTxHashForEmptyBlock
		}
		if header.ReceiptHash != types.EmptyRootHash {
			return errInvalidReceiptHashForEmptyBlock
		}
	}

	if header.Nonce.Uint64() != 0 {
		return errInvalidNonce
	}

	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}

	if header.MixDigest != types.BiHSDigest {
		return errInvalidDigest
	}

	if header.Difficulty.Cmp(defaultDifficulty) != 0 {
		return errInvalidDifficulty
	}

	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}

	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}

	if !seal {
		if len(header.Extra) != 0 {
			return fmt.Errorf("extra should be empty for non-seal header, #len %d", len(header.Extra))
		}
	} else {
		var qc bihs.QC
		hash := header.Hash()
		err := qc.DeserializeFromHeader(header.Number.Uint64(), hash[:], ocommon.NewZeroCopySource(header.Extra))
		if err != nil {
			return err
		}

		ids := bh.gov.ValidatorIDs(header.Number.Uint64())
		if !qc.VerifyEC(bh.signer, ids) {
			return fmt.Errorf("qc.VerifyEC failed")
		}
	}
	return nil
}

func (bh *BiHS) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	header.Coinbase = bh.signer.Address()
	header.Nonce = defaultNonce
	header.MixDigest = types.BiHSDigest
	header.Extra = nil

	parent, err := bh.getParentHeader(chain, header)
	if err != nil {
		return err
	}

	header.Difficulty = defaultDifficulty
	header.Time = parent.Time + bh.bihsConfig.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}

	maxAllowedTime := uint64(time.Now().Unix() + deltaSeconds)
	if header.Time >= maxAllowedTime {
		time.Sleep(time.Second * time.Duration(header.Time-maxAllowedTime))
	}
	return nil
}

func (bh *BiHS) getParentHeader(chain consensus.ChainHeaderReader, header *types.Header) (*types.Header, error) {
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return nil, consensus.ErrUnknownAncestor
	}
	return parent, nil
}

func (bh *BiHS) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.EmptyUncleHash
}

func (bh *BiHS) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.EmptyUncleHash

	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

func (bh *BiHS) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) (err error) {

	bh.Do(func() {
		err := bh.core.Start()
		if err != nil {
			log.Crit("core.Start", "err", err)
		}
	})

	bh.core.Propose(context.Background(), (*adapter.Block)(block))

	go func() {
		for {
			select {
			case blk := <-bh.commitCh:
				if blk != nil && blk.Hash() == block.Hash() {
					results <- blk
					return
				}
			case <-stop:
				log.Trace("Stop seal, triggered by miner", "hash", block.Hash(), "number", block.Number())
				return
			}
		}
	}()

	return
}

func (bh *BiHS) SealHash(header *types.Header) common.Hash {
	return header.Hash()
}

func (bh *BiHS) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return defaultDifficulty
}

func (bh *BiHS) OnBlockCommit(block *types.Block) {
	select {
	case bh.commitCh <- block:
	default:
	}
}

func (bh *BiHS) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "bihs",
		Version:   "1.0",
		Service:   &API{chain: chain, bihs: bh},
		Public:    true,
	}}
}

func (bh *BiHS) Close() error {
	if bh.chainHeadSub != nil {
		bh.chainHeadSub.Unsubscribe()
	}

	return bh.core.Stop()
}

func (bh *BiHS) HandleP2pMsg(msg p2p.Msg) error {
	return bh.p2p.HandleP2pMsg(msg)
}
