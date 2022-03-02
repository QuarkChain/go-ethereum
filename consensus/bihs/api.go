package bihs

import "github.com/ethereum/go-ethereum/consensus"

type API struct {
	chain consensus.ChainHeaderReader
	bihs  *BiHS
}

func (api *API) Version() string {
	return "1.0"
}
