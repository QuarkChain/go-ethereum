package gov

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
)

type Governance struct {
	epoch uint64
	chain *core.BlockChain
}

func New(epoch uint64, chain *core.BlockChain) *Governance {
	return &Governance{epoch: epoch, chain: chain}
}

// EpochValidators returns the current epoch validators that height belongs to
func (g *Governance) EpochValidators(height uint64) []common.Address {
	// TODO get real validators by calling contract
	header := g.chain.GetHeaderByNumber(0)
	return header.NextValidators
}

func (g *Governance) NextValidators(height uint64) []common.Address {
	if height%g.epoch != 0 {
		return nil
	}

	switch {
	case height == 0:
		header := g.chain.GetHeaderByNumber(0)
		return header.NextValidators
	default:
		// TODO get real validators by calling contract
		header := g.chain.GetHeaderByNumber(height - g.epoch)
		return header.NextValidators
	}
}
