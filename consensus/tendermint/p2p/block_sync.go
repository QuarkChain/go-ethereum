package p2p

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/log"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
)

type BlockSync struct {
	h          host.Host
	wg         sync.WaitGroup
	executor   consensus.BlockExecutor
	blockStore consensus.BlockStore
	chainState consensus.ChainState
	err        error
	obsvC      chan consensus.MsgInfo
}

func NewBlockSync(h host.Host, chainState consensus.ChainState, blockStore consensus.BlockStore, executor consensus.BlockExecutor, obsvC chan consensus.MsgInfo) *BlockSync {
	return &BlockSync{h: h, executor: executor, blockStore: blockStore, chainState: chainState, obsvC: obsvC}
}

func (bs *BlockSync) Start(ctx context.Context) {
	bs.wg.Add(1)

	go bs.runRoutine(ctx)
}

func (bs *BlockSync) runRoutine(ctx context.Context) {
	bs.err = bs.sync(ctx)
	bs.wg.Done()
}

func (bs *BlockSync) sync(ctx context.Context) error {
	ps := bs.h.Network().Peers()

	var maxPeer peer.ID
	var maxHeight uint64

	for {
		for _, p := range ps {
			req := &HelloRequest{}
			resp := &HelloResponse{}
			err := SendRPC(context.Background(), bs.h, p, TopicHello, req, resp)
			if err != nil {
				continue
			}

			log.Info("Find peer", "peer", p, "last_height", resp.LastHeight)
			if resp.LastHeight > maxHeight {
				maxHeight = resp.LastHeight
				maxPeer = p
			} else if maxHeight == 0 {
				// random pick up one to sync latest message
				maxPeer = p
			}
		}

		localLastHeight := bs.blockStore.Height()

		if maxHeight < localLastHeight {
			// TODO: may return error
			return nil
		} else if maxHeight == localLastHeight {
			break
		}

		log.Info("Sycning block", "from", localLastHeight, "to", maxHeight)

		for height := localLastHeight + 1; height <= maxHeight; height++ {
			req := &GetFullBlockRequest{Height: height}
			var vb consensus.FullBlock
			if err := SendRPC(ctx, bs.h, maxPeer, TopicFullBlock, req, &vb); err != nil {
				return err
			}

			if err := bs.executor.ValidateBlock(bs.chainState, &vb, true); err != nil {
				return err
			}

			if err := bs.chainState.Validators.VerifyCommit(
				bs.chainState.ChainID, vb.Hash(), vb.NumberU64(), vb.Header().Commit); err != nil {
				return err
			}

			newChainState, err := bs.executor.ApplyBlock(ctx, bs.chainState, &vb)
			if err != nil {
				return err
			}

			bs.blockStore.SaveBlock(&vb, vb.Header().Commit)
			bs.chainState = newChainState
		}
		log.Info("Sycned block", "from", localLastHeight, "to", maxHeight)

	}
	log.Info("Finished syncing")

	return nil
}

func (bs *BlockSync) LastChainState() consensus.ChainState {
	return bs.chainState
}

func (bs *BlockSync) WaitDone() error {
	bs.wg.Wait()
	return bs.err
}
