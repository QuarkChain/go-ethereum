package p2p

import (
	"math/rand"

	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/log"
)

func (s *Server) consensSyncRoutine() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case localSyncReq := <-s.consensusSyncChan:
			// randomly pick one peer to send
			// TODO: may find the multiple peers with better information
			ps := s.Host.Network().Peers()

			if len(ps) == 0 {
				continue
			}

			p := ps[rand.Intn(len(ps))]

			resp := &consensus.ConsensusSyncResponse{}

			// Do not block the goroutine
			go func() {
				log.Debug("sending consensus sync", "req", localSyncReq, "peer", p)
				if err := SendRPC(s.ctx, s.Host, p, TopicConsensusSync, localSyncReq, resp); err != nil {
					log.Warn("failed to send consensus sync", "err", err)
					// Mark as bad peer and disconnect from peer?
					return
				}

				if resp.IsCommited == 1 {
					if len(resp.MessageData) != 1 {
						// Mark as bad peer and disconnect from peer?
						log.Warn("failed to decode committed block", "err", "unexpected data received")
						return
					}

					block := &consensus.FullBlock{}
					err := block.DecodeFromRLPBytes(resp.MessageData[0])
					if err != nil {
						log.Warn("failed to decode committed block", "err", err)
						// Mark as bad peer and disconnect from peer?
						return
					}
					s.consensusState.ProcessCommittedBlock(block)
					return
				}

				for _, msgData := range resp.MessageData {
					msg, err := decode(msgData)
					if err != nil {
						log.Debug("cannot decode", "msgData", msgData)
						// Mark as bad peer and disconnect from peer?
						continue
					}

					log.Debug("add consensus sync message", "msg", msg)

					// TODO: add in goroutine if full
					switch m := msg.(type) {
					case *consensus.Proposal:
						s.obsvC <- consensus.MsgInfo{Msg: &consensus.ProposalMessage{Proposal: m}, PeerID: string(p)}
					case *consensus.Vote:
						s.obsvC <- consensus.MsgInfo{Msg: &consensus.VoteMessage{Vote: m}, PeerID: string(p)}
					default:
						// Mark as bad peer and disconnect from peer?
						continue
					}
				}
			}()
		}
	}
}
