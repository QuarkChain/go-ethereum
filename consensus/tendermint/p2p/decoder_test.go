package p2p

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
)

func TestSerdeProposal(t *testing.T) {
	c := consensus.CommitSig{
		BlockIDFlag:      consensus.BlockIDFlagCommit,
		ValidatorAddress: common.Address{},
		TimestampMs:      1133423,
		Signature:        []byte{},
	}
	cm := consensus.NewCommit(5, 6, common.Hash{}, []consensus.CommitSig{c})

	p := &consensus.Proposal{
		Height:      4,
		Round:       3,
		POLRound:    -1,
		TimestampMs: time.Now().UnixMilli(),
		Signature:   []byte{'1'},
		Block: &consensus.FullBlock{Block: types.NewBlock(
			&consensus.Header{
				ParentHash:     common.Hash{},
				Number:         big.NewInt(6),
				TimeMs:         34534,
				Coinbase:       common.Address{},
				LastCommitHash: common.Hash{},
				Difficulty:     big.NewInt(2),
				Extra:          []byte{},
				BaseFee:        big.NewInt(7),
				NextValidators: []common.Address{},
			},
			[]*types.Transaction{},
			[]*types.Header{},
			[]*types.Receipt{},
			trie.NewStackTrie(nil),
		),
			LastCommit: cm,
		}}

	data, err := encodeProposal(p)
	assert.NoError(t, err)
	np, err := decodeProposal(data)
	assert.NoError(t, err)
	assert.Equal(t, p.Block.Hash(), np.(*consensus.Proposal).Block.Hash())
}

func TestSerdeVote(t *testing.T) {
	v := &consensus.Vote{
		Type:             consensus.PrevoteType,
		Height:           4,
		Round:            3,
		TimestampMs:      uint64(time.Now().UnixMilli()),
		BlockID:          common.BytesToHash([]byte{1, 2}),
		ValidatorAddress: common.BigToAddress(big.NewInt(12345)),
		ValidatorIndex:   5,
		Signature:        []byte{'2'},
	}

	data, err := encodeVote(v)
	assert.NoError(t, err)
	nv, err := decodeVote(data)
	assert.NoError(t, err)
	assert.Equal(t, v, nv)
}
