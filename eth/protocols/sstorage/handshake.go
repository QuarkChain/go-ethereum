package sstorage

import (
	"fmt"
	"github.com/ethereum/go-ethereum/sstorage"
	"time"

	"github.com/ethereum/go-ethereum/p2p"
)

const (
	// handshakeTimeout is the maximum allowed time for the `sstorage` handshake to
	// complete before dropping the connection.= as malicious.
	handshakeTimeout = 5 * time.Second
)

// Handshake executes the sstorage protocol handshake
func (p *Peer) Handshake() error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)

	go func() {
		errc <- p.RequestShardList(sstorage.Shards())
	}()
	go func() {
		errc <- p.readStatus()
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return p2p.DiscReadTimeout
		}
	}

	return nil
}

// readStatus reads the remote handshake message.
func (p *Peer) readStatus() error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != ShardsMsg {
		return fmt.Errorf("no status message: first msg has code %x (!= %x)", msg.Code, ShardsMsg)
	}
	res := new(ShardListPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	return p.SetShards(convertShardList(res))
}
