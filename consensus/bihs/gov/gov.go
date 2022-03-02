package gov

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/zhiqiangxu/bihs"
)

// this package is for test purpose only

type Governance struct {
	chain *core.BlockChain
}

func New(chain *core.BlockChain) *Governance {
	return &Governance{chain: chain}
}

var validators = []common.Address{
	common.HexToAddress("0xb81aB4520565601a6904682b3c139Fc82ff22fa8"),
	common.HexToAddress("0x49666faD0530f3A50A48Ed473104647ca2af777D"),
}

func (g *Governance) ValidatorP2PAddrs(height uint64) []common.Address {
	return validators
}

func (g *Governance) ValidatorP2PAddr(account common.Address) common.Address {
	return account
}

func (g *Governance) ValidatorIndex(height uint64, peer bihs.ID) int {

	peerAddr := common.BytesToAddress(peer)
	log.Info("ValidatorIndex", "peerAddr", peerAddr)
	for i, addr := range validators {
		if peerAddr == addr {
			return i
		}
	}

	log.Info("ValidatorIndex", "peerAddr", peerAddr, "idx", -1)
	return -1
}

func (g *Governance) SelectLeader(height, view uint64) bihs.ID {
	return validators[(height+view)%uint64(len(validators))][:]
}

func (g *Governance) ValidatorCount(height uint64) int32 {
	return int32(len(validators))
}
func (g *Governance) ValidatorIDs(height uint64) (result []bihs.ID) {

	for _, val := range validators {
		val := val
		result = append(result, val[:])
	}
	return
}
