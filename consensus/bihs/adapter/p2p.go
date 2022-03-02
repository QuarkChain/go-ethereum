package adapter

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/bihs/gov"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	ocommon "github.com/ontio/ontology/common"
	"github.com/zhiqiangxu/bihs"
)

type P2P struct {
	bc    Broadcaster
	chain *core.BlockChain
	gov   *gov.Governance
	ch    chan *bihs.Msg
}

type Broadcaster interface {
	Unicast(target common.Address, msgcode uint64, data interface{})
	Multicast(targets []common.Address, msgcode uint64, data interface{})
}

const chanSize = 20

func NewP2P(bc Broadcaster, chain *core.BlockChain, gov *gov.Governance) *P2P {
	return &P2P{bc: bc, chain: chain, gov: gov, ch: make(chan *bihs.Msg, chanSize)}
}

func (p *P2P) Broadcast(msg *bihs.Msg) {

	sink := ocommon.NewZeroCopySink(nil)
	msg.Serialize(sink)
	payload := sink.Bytes()
	validators := p.gov.ValidatorP2PAddrs(msg.Height)
	log.Info("Broadcast", "#payload", len(payload), "type", msg.Type, "height", msg.Height, "view", msg.View, "msg hash", msg.Hash())
	p.bc.Multicast(validators, ConsensusMsgCode, payload)

	// {
	// 	var decodeMsg bihs.Msg
	// 	err := decodeMsg.Deserialize(ocommon.NewZeroCopySource(payload))
	// 	if err != nil {
	// 		panic(fmt.Sprintf("decodeMsg.Deserialize failed:%v", err))
	// 	}
	// }
}

var ConsensusMsgCode uint64

func (p *P2P) Send(id bihs.ID, msg *bihs.Msg) {
	target := p.gov.ValidatorP2PAddr(common.BytesToAddress(id))
	sink := ocommon.NewZeroCopySink(nil)
	msg.Serialize(sink)
	payload := sink.Bytes()
	p.bc.Unicast(target, ConsensusMsgCode, payload)
}

func (p *P2P) MsgCh() <-chan *bihs.Msg {
	return p.ch
}

func (p *P2P) HandleP2pMsg(msg p2p.Msg) (err error) {

	var payload []byte
	if err = msg.Decode(&payload); err != nil {
		return
	}

	var bihsMsg bihs.Msg
	if err = bihsMsg.Deserialize(ocommon.NewZeroCopySource(payload)); err != nil {
		log.Info("bihs.Msg", "#payload", len(payload), "type", bihsMsg.Type, "height", bihsMsg.Height, "view", bihsMsg.View, "qc", bihsMsg.Justify)
		return
	}

	log.Info("HandleP2pMsg", "#payload", len(payload), "msg hash", bihsMsg.Hash())

	select {
	case p.ch <- &bihsMsg:
	default:
		log.Warn("p2p msg dropped because channel is ful")
	}

	// TODO help propagation?
	return nil
}
