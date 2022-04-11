package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-quic-transport/integrationtests/stream"
	"github.com/multiformats/go-multiaddr"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-core/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	"go.uber.org/zap"
)

var (
	p2pHeartbeatsSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "p2p_heartbeats_sent_total",
			Help: "Total number of p2p heartbeats sent",
		})
	p2pMessagesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "p2p_broadcast_messages_sent_total",
			Help: "Total number of p2p pubsub broadcast messages sent",
		})
	p2pMessagesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "p2p_broadcast_messages_received_total",
			Help: "Total number of p2p pubsub broadcast messages received",
		}, []string{"type"})
	decoder = make(map[byte]func([]byte) (interface{}, error))
)

const (
	MsgProposal        = 0x01
	MsgVote            = 0x02
	MsgVerifiedBlock   = 0x03
	MsgHelloRequest    = 0x04
	MsgHelloResponse   = 0x05
	TopicHello         = "/mpbft/dev/hello/1.0.0"
	TopicFullBlock     = "/mpbft/dev/fullblock/1.0.0"
	TopicConsensusSync = "/mpbft/dev/consensus_sync/1.0.0"
)

func init() {
	prometheus.MustRegister(p2pHeartbeatsSent)
	prometheus.MustRegister(p2pMessagesSent)
	prometheus.MustRegister(p2pMessagesReceived)
	decoder[1] = decodeProposal
	decoder[2] = decodeVote
	decoder[3] = decodeFullBlock
	decoder[4] = decodeHelloRequest
	decoder[5] = decodeHelloResponse
	decoder[6] = decodeGetFullBlockRequest
}

type HelloRequest struct {
	LastHeight uint64
}

type HelloResponse struct {
	LastHeight uint64
}

type GetLatestMessagesRequest struct {
}

type GetLatestMessagesResponse struct {
	MessageData [][]byte
}

type GetFullBlockRequest struct {
	Height uint64
}

func decodeHelloRequest(data []byte) (interface{}, error) {
	var h HelloRequest
	err := rlp.DecodeBytes(data, &h)
	return h, err
}

func decodeHelloResponse(data []byte) (interface{}, error) {
	var h HelloResponse
	err := rlp.DecodeBytes(data, &h)
	return h, err
}

func (req *HelloRequest) ValidateBasic() error {
	return nil
}

func (req *HelloResponse) ValidateBasic() error {
	return nil
}

func decodeGetFullBlockRequest(data []byte) (interface{}, error) {
	var req GetFullBlockRequest
	err := rlp.DecodeBytes(data, &req)
	return req, err
}

func decodeVote(data []byte) (interface{}, error) {
	v := &consensus.Vote{}
	err := v.DecodeRLP(rlp.NewStream(bytes.NewReader(data), 0))
	if err != nil {
		return nil, err
	}
	return v, v.ValidateBasic()
}

func encodeVote(v *consensus.Vote) ([]byte, error) {
	var buf bytes.Buffer
	if err := v.EncodeRLP(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeProposal(data []byte) (interface{}, error) {
	p := &consensus.Proposal{}
	err := p.DecodeRLP(rlp.NewStream(bytes.NewReader(data), 0))
	if err != nil {
		return nil, err
	}
	return p, p.ValidateBasic()
}

func encodeProposal(p *consensus.Proposal) ([]byte, error) {
	var buf bytes.Buffer
	if err := p.EncodeRLP(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeFullBlock(data []byte) (interface{}, error) {
	var b consensus.FullBlock
	err := b.DecodeFromRLPBytes(data)
	return b, err
}

func decode(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("incorrect msg")
	}

	if decoder[data[0]] == nil {
		return nil, fmt.Errorf("deocder not found")
	}

	return decoder[data[0]](data[1:])
}

func encodeRaw(msg interface{}) ([]byte, error) {
	var data []byte
	var err error
	switch m := msg.(type) {
	case *consensus.Proposal:
		data, err = encodeProposal(m)
	case *consensus.Vote:
		data, err = encodeVote(m)
	case *consensus.FullBlock:
		data, err = rlp.EncodeToBytes(m)
	case *HelloRequest:
		data, err = rlp.EncodeToBytes(m)
	case *HelloResponse:
		data, err = rlp.EncodeToBytes(m)
	}
	return data, err
}

func encode(msg interface{}) ([]byte, error) {
	var data []byte
	var err error
	var typeData []byte
	switch msg.(type) {
	case *consensus.Proposal:
		typeData = []byte{1}
	case *consensus.Vote:
		typeData = []byte{2}
	case *consensus.FullBlock:
		typeData = []byte{3}
	case *HelloRequest:
		typeData = []byte{4}
	case *HelloResponse:
		typeData = []byte{5}
	case *GetFullBlockRequest:
		typeData = []byte{6}
	}

	data, err = encodeRaw(msg)

	if err != nil {
		return nil, err
	}
	return append(typeData, data...), nil
}

func WriteMsgWithPrependedSize(stream network.Stream, msg []byte) error {
	sizeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBytes, uint32(len(msg)))
	n, err := stream.Write(sizeBytes)
	if err != nil {
		return err
	}
	if n != len(sizeBytes) {
		return fmt.Errorf("not fully write")
	}

	n, err = stream.Write(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return fmt.Errorf("not fully write")
	}
	return nil
}

func ReadMsgWithPrependedSize(stream stream.Stream) ([]byte, error) {
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(stream, sizeBytes)
	if err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(sizeBytes)

	msg := make([]byte, size)
	_, err = io.ReadFull(stream, msg)
	return msg, err
}

func Send(ctx context.Context, h host.Host, peer peer.ID, topic string, msg interface{}) (stream.Stream, error) {
	data, err := rlp.EncodeToBytes(msg)
	if err != nil {
		return nil, err
	}

	stream, err := h.NewStream(ctx, peer, protocol.ID(topic))
	if err != nil {
		return nil, err
	}

	err = WriteMsgWithPrependedSize(stream, data)
	if err != nil {
		stream.Close()
		return nil, err
	}

	if err := stream.CloseWrite(); err != nil {
		stream.Reset()
		return nil, err
	}
	return stream, err
}

func SendRPC(ctx context.Context, h host.Host, peer peer.ID, topic string, req interface{}, resp interface{}) error {
	s, err := Send(ctx, h, peer, topic, req)
	if err != nil {
		return err
	}

	// TODO: timeout?
	data, err := ReadMsgWithPrependedSize(s)
	if err != nil {
		return err
	}

	return rlp.DecodeBytes(data, resp)
}

type Server struct {
	Host              host.Host
	ctx               context.Context
	consensusState    *consensus.ConsensusState
	consensusSyncChan chan *consensus.ConsensusSyncRequest
	blockStore        consensus.BlockStore
	obsvC             chan consensus.MsgInfo
	sendC             chan consensus.Message
	priv              crypto.PrivKey
	port              uint
	networkID         string
	nodeName          string
	rootCtxCancel     context.CancelFunc
}

var TestMode bool

func NewP2PServer(
	ctx context.Context,
	blockStore consensus.BlockStore,
	obsvC chan consensus.MsgInfo,
	sendC chan consensus.Message,
	priv crypto.PrivKey,
	port uint,
	networkID string,
	bootstrapPeers string,
	nodeName string,
	rootCtxCancel context.CancelFunc,
	maxPeerCount int,
) (*Server, error) {
	cg := &connGater{h: nil, MaxPeerCount: maxPeerCount}
	h, err := libp2p.New(ctx,
		// Use the keypair we generated
		libp2p.Identity(priv),

		// Multiple listen addresses
		libp2p.ListenAddrStrings(
			// Listen on QUIC only.
			// https://github.com/libp2p/go-libp2p/issues/688
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", port),
			fmt.Sprintf("/ip6/::/udp/%d/quic", port),
		),

		libp2p.ConnectionGater(cg),

		// Enable TLS security as the only security protocol.
		libp2p.Security(libp2ptls.ID, libp2ptls.New),

		// Enable QUIC transport as the only transport.
		libp2p.Transport(libp2pquic.NewTransport),

		// Let's prevent our peer from having too many
		// connections by attaching a connection manager.
		libp2p.ConnectionManager(connmgr.NewConnManager(
			100,         // Lowwater
			400,         // HighWater,
			time.Minute, // GracePeriod
		)),

		// Let this host use the DHT to find other hosts
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			// TODO(leo): Persistent data store (i.e. address book)
			idht, err := dht.New(ctx, h, dht.Mode(dht.ModeServer),
				// TODO(leo): This intentionally makes us incompatible with the global IPFS DHT
				dht.ProtocolPrefix(protocol.ID("/"+networkID)),
			)
			return idht, err
		}),
	)

	if err != nil {
		return nil, err
	}

	log.Info("Connecting to bootstrap peers", "bootstrap_peers", bootstrapPeers)

	cg.h = h
	// Add our own bootstrap nodes

	// Count number of successful connection attempts. If we fail to connect to any bootstrap peer, kill
	// the service and have supervisor retry it.
	successes := 0
	// Are we a bootstrap node? If so, it's okay to not have any peers.
	bootstrapNode := false

	for _, addr := range strings.Split(bootstrapPeers, ",") {
		if addr == "" {
			continue
		}
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			log.Error("Invalid bootstrap address", "peer", addr, "err", err)
			continue
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Error("Invalid bootstrap address", "peer", addr, "err", err)
			continue
		}

		if pi.ID == h.ID() {
			log.Info("We're a bootstrap node")
			bootstrapNode = true
			continue
		}

		if err = h.Connect(ctx, *pi); err != nil {
			log.Error("Failed to connect to bootstrap peer", "peer", addr, "err", err)
		} else {
			successes += 1
		}
	}

	h.SetStreamHandler(TopicHello, func(stream network.Stream) {
		defer stream.Close()

		data, err := ReadMsgWithPrependedSize(stream)
		if err != nil {
			return
		}

		var msg HelloRequest

		err = rlp.DecodeBytes(data, &msg)
		if err != nil {
			return
		}

		log.Debug("received hello",
			"payload", data,
			"raw", data)

		resp, err := rlp.EncodeToBytes(&HelloResponse{blockStore.Height()})
		if err != nil {
			return
		}

		err = WriteMsgWithPrependedSize(stream, resp)
		if err != nil {
			return
		}
	})

	h.SetStreamHandler(TopicFullBlock, func(stream network.Stream) {
		defer stream.Close()

		data, err := ReadMsgWithPrependedSize(stream)
		if err != nil {
			return
		}

		var msg GetFullBlockRequest

		err = rlp.DecodeBytes(data, &msg)
		if err != nil {
			return
		}

		log.Debug("received fullblock_req",
			"payload", data,
			"raw", data)

		// TODO: check height correctness
		vb := blockStore.LoadBlock(msg.Height)
		commit := blockStore.LoadBlockCommit(msg.Height)
		vb = vb.WithCommit(commit)

		resp, err := vb.EncodeToRLPBytes()
		if err != nil {
			return
		}

		err = WriteMsgWithPrependedSize(stream, resp)
		if err != nil {
			return
		}
	})

	// TODO: continually reconnect to bootstrap nodes?
	if !TestMode && successes == 0 && !bootstrapNode {
		return nil, fmt.Errorf("failed to connect to any bootstrap peer")
	} else {
		log.Info("Connected to bootstrap peers", "num", successes)
	}

	log.Info("Node has been started", "peer_id", h.ID().String(),
		"addrs", fmt.Sprintf("%v", h.Addrs()))

	return &Server{
		Host:              h,
		ctx:               ctx,
		consensusSyncChan: make(chan *consensus.ConsensusSyncRequest),
		blockStore:        blockStore,
		obsvC:             obsvC,
		sendC:             sendC,
		priv:              priv,
		port:              port,
		networkID:         networkID,
		nodeName:          nodeName,
		rootCtxCancel:     rootCtxCancel,
	}, nil
}

func (server *Server) Run(ctx context.Context) error {

	var err error

	defer func() {
		// TODO: libp2p cannot be cleanly restarted (https://github.com/libp2p/go-libp2p/issues/992)
		log.Error("p2p routine has exited, cancelling root context...", "err", err)
		server.rootCtxCancel()
	}()

	topic := fmt.Sprintf("%s/%s", server.networkID, "broadcast")

	log.Info("Subscribing pubsub topic", "topic", topic)
	ps, err := pubsub.NewGossipSub(ctx, server.Host)
	if err != nil {
		panic(err)
	}

	th, err := ps.Join(topic)
	if err != nil {
		return fmt.Errorf("failed to join topic: %w", err)
	}

	sub, err := th.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe topic: %w", err)
	}

	// TODO: create a thread to send heartbeat?

	// h.Network().Notify(&network.NotifyBundle{ConnectedF: func(net network.Network, conn network.Conn) {
	// 	// Must be in goroutine to prevent blocking the callback
	// 	go func() {
	// 		s, err := h.NewStream(context.Background(), conn.RemotePeer(), "/go-minimal-pbft/steam/1.0.0")
	// 		if err != nil {
	// 			log.Error("Cannot create stream", "peer", conn.RemotePeer(), "err", err)
	// 		}

	// 		req, err := encode(&HelloRequest{})
	// 		if err != nil {
	// 			log.Error("Cannot create stream", "peer", conn.RemotePeer(), "err", err)
	// 		}

	// 		WriteMsgWithPrependedSize(s, req)

	// 		defer s.Close()
	// 	}()
	// }})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-server.sendC:
				var err error
				var data []byte
				switch m := (msg).(type) {
				case *consensus.ProposalMessage:
					data, err = encode(m.Proposal)
					if err == nil {
						err = th.Publish(ctx, data)
						p2pMessagesSent.Inc()
					}
				case *consensus.VoteMessage:
					data, err = encode(m.Vote)
					if err == nil {
						err = th.Publish(ctx, data)
						p2pMessagesSent.Inc()
					}
				case *consensus.ConsensusSyncRequest:
					server.consensusSyncChan <- m
				default:
					log.Error("unrecognized data to sent")
				}

				if err != nil {
					log.Error("failed to publish message from queue", zap.Error(err))
				}
			}
		}
	}()

	for {
		envelope, err := sub.Next(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive pubsub message: %w", err)
		}

		if envelope.GetFrom() == server.Host.ID() {
			log.Trace("received message from ourselves, ignoring",
				"payload", envelope.Data)
			p2pMessagesReceived.WithLabelValues("loopback").Inc()
			continue
		}

		msg, err := decode(envelope.Data)

		if err != nil {
			log.Info("received invalid message",
				"err", err,
				"data", envelope.Data,
				"from", envelope.GetFrom().String())
			p2pMessagesReceived.WithLabelValues("invalid").Inc()
			continue
		}

		log.Debug("received message",
			"payload", msg,
			"raw", envelope.Data,
			"from", envelope.GetFrom().String())

		switch m := msg.(type) {
		case *consensus.Proposal:
			server.obsvC <- consensus.MsgInfo{Msg: &consensus.ProposalMessage{Proposal: m}, PeerID: string(envelope.GetFrom())}
			p2pMessagesReceived.WithLabelValues("observation").Inc()
		case *consensus.Vote:
			server.obsvC <- consensus.MsgInfo{Msg: &consensus.VoteMessage{Vote: m}, PeerID: string(envelope.GetFrom())}
			p2pMessagesReceived.WithLabelValues("observation").Inc()
		case *HelloRequest:
		case *HelloResponse:
		case *GetFullBlockRequest:
		default:
			p2pMessagesReceived.WithLabelValues("unknown").Inc()
			log.Warn("received unknown message type (running outdated software?)",
				"payload", msg,
				"raw", envelope.Data,
				"from", envelope.GetFrom().String())
		}
	}
}

func (server *Server) SetConsensusState(cs *consensus.ConsensusState) {
	server.consensusState = cs

	server.Host.SetStreamHandler(TopicConsensusSync, func(stream network.Stream) {
		defer stream.Close()

		data, err := ReadMsgWithPrependedSize(stream)
		if err != nil {
			return
		}

		var req consensus.ConsensusSyncRequest

		err = rlp.DecodeBytes(data, &req)
		if err != nil {
			return
		}

		log.Debug("received consensus_sync_req",
			"req", &req,
			"payload", data)

		msgs, err := cs.ProcessSyncRequest(&req)

		if err != nil {
			return
		}

		resp := consensus.ConsensusSyncResponse{}

		if len(msgs) == 1 {
			fb, ok0 := msgs[0].(*consensus.FullBlock)
			if ok0 {
				resp.IsCommited = 1
				bs0, err := fb.EncodeToRLPBytes()
				if err != nil {
					return
				}
				resp.MessageData = append(resp.MessageData, bs0)
			}
		}

		if resp.IsCommited == 0 {
			for _, lmsg := range msgs {
				var data []byte
				var err error

				switch m := (lmsg).(type) {
				case *consensus.ProposalMessage:
					data, err = encode(m.Proposal)
				case *consensus.VoteMessage:
					data, err = encode(m.Vote)
				}
				if err != nil {
					return
				}
				resp.MessageData = append(resp.MessageData, data)
			}
		}

		respData, err := rlp.EncodeToBytes(&resp)
		if err != nil {
			return
		}

		err = WriteMsgWithPrependedSize(stream, respData)
		if err != nil {
			return
		}
	})

	go server.consensSyncRoutine()
}
