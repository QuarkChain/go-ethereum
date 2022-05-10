package p2p

import (
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"github.com/libp2p/go-libp2p-core/control"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"sync"
)

type connGater struct {
	sync.RWMutex
	h            host.Host
	MaxPeerCount int
}

func (cg *connGater) getConnectedPeerCount() int {
	c := 0
	if cg.h != nil {
		for index, p := range cg.h.Network().Peers() {
			if cg.h.Network().Connectedness(p) == network.Connected {
				log.Debug("Connected Peer List", "index", index, "peer id", p.String())
				c++
			}
		}
	}
	return c
}

func (cg *connGater) isPeerAtLimit() bool {
	cg.RLock()
	defer cg.RUnlock()
	if cg.getConnectedPeerCount() >= cg.MaxPeerCount {
		log.Info(fmt.Sprintf("PeerCount %d exceeds the MaxPeerCount %d.\r\n", len(cg.h.Network().Peers()), cg.MaxPeerCount))
		return true
	}
	return false
}

func (cg *connGater) InterceptPeerDial(p peer.ID) (allow bool) {
	log.Debug("InterceptPeerDial", "peer id", p)
	return cg.h.Network().Connectedness(p) == network.Connected || !cg.isPeerAtLimit()
}

func (cg *connGater) InterceptAddrDial(p peer.ID, a ma.Multiaddr) (allow bool) {
	log.Debug("InterceptAddrDial", "peer id", p)
	return cg.h.Network().Connectedness(p) == network.Connected || !cg.isPeerAtLimit()
}

func (cg *connGater) InterceptAccept(cma network.ConnMultiaddrs) (allow bool) {
	return true
}

func (cg *connGater) InterceptSecured(dir network.Direction, p peer.ID, cma network.ConnMultiaddrs) (allow bool) {
	log.Debug("InterceptSecured", "peer id", p)
	return cg.h.Network().Connectedness(p) == network.Connected || !cg.isPeerAtLimit()
}

func (cg *connGater) InterceptUpgraded(network.Conn) (allow bool, reason control.DisconnectReason) {
	return true, 0
}
