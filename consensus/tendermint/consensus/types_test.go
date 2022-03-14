package consensus

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
)

func TestSerdeCommitSig(t *testing.T) {
	c := CommitSig{
		BlockIDFlag:      BlockIDFlagCommit,
		ValidatorAddress: common.Address{},
		TimestampMs:      1133423,
		Signature:        []byte{},
	}

	data, err := rlp.EncodeToBytes(c)
	assert.NoError(t, err)
	nc := CommitSig{}
	err = rlp.DecodeBytes(data, &nc)
	assert.NoError(t, err)
	assert.Equal(t, c, nc)
}

func TestSerdeCommit(t *testing.T) {
	c := CommitSig{
		BlockIDFlag:      BlockIDFlagCommit,
		ValidatorAddress: common.Address{},
		TimestampMs:      1133423,
		Signature:        []byte{},
	}
	cm := NewCommit(5, 6, common.Hash{}, []CommitSig{c})

	data, err := rlp.EncodeToBytes(cm)
	assert.NoError(t, err)
	ncm := Commit{}
	err = rlp.DecodeBytes(data, &ncm)
	assert.NoError(t, err)
	assert.Equal(t, *cm, ncm)
}

func TestSerdeBlock(t *testing.T) {
	c := CommitSig{
		BlockIDFlag:      BlockIDFlagCommit,
		ValidatorAddress: common.Address{},
		TimestampMs:      1133423,
		Signature:        []byte{},
	}
	cm := NewCommit(5, 6, common.Hash{}, []CommitSig{c})

	b := &FullBlock{Block: types.NewBlock(
		&Header{
			ParentHash:     common.Hash{},
			Number:         big.NewInt(6),
			TimeMs:         34534,
			Coinbase:       common.Address{},
			LastCommitHash: common.Hash{},
			Difficulty:     big.NewInt(1),
			Extra:          []byte{},
			BaseFee:        big.NewInt(2), // TODO
			NextValidators: []common.Address{},
		},
		[]*types.Transaction{},
		[]*types.Header{},
		[]*types.Receipt{},
		trie.NewStackTrie(nil)),
		LastCommit: cm,
	}

	var buf bytes.Buffer
	err := b.EncodeRLP(&buf)
	assert.NoError(t, err)
	nb := FullBlock{}
	bs := buf.Bytes()
	err = nb.DecodeRLP(rlp.NewStream(bytes.NewReader(bs), 0))
	assert.NoError(t, err)
	assert.Equal(t, b.Hash(), nb.Hash())
	// assert.Equal(t, b.Body(), nb.Body())
	assert.Equal(t, b.LastCommit, nb.LastCommit)
}

func TestSerdeConsensusSyncRequest(t *testing.T) {
	req := &ConsensusSyncRequest{
		Height:           152,
		Round:            1356,
		HasProposal:      1,
		PrevotesBitmap:   []uint64{3},
		PrecommitsBitmap: []uint64{2},
	}

	bs, _ := rlp.EncodeToBytes(req)
	nreq := &ConsensusSyncRequest{}
	rlp.DecodeBytes(bs, nreq)
	assert.Equal(t, req, nreq)
}

func TestVoteSignBytes(t *testing.T) {
	v := Vote{
		Type:             PrecommitType,
		Height:           20,
		Round:            2,
		BlockID:          common.Hash{},
		TimestampMs:      352353,
		ValidatorAddress: common.Address{},
		ValidatorIndex:   3,
		Signature:        []byte{},
	}

	bs0 := v.VoteSignBytes("aaa")
	bs1 := v.VoteSignBytes("bbb")
	assert.NotEqual(t, bs0, bs1)

	v.Height = 21
	bs2 := v.VoteSignBytes("aaa")
	assert.NotEqual(t, bs0, bs2)
}

func TestSignVote(t *testing.T) {
	pv := GeneratePrivValidatorLocal()
	pubKey, err := pv.GetPubKey(context.Background())
	assert.NoError(t, err)

	v := Vote{
		Type:             PrecommitType,
		Height:           20,
		Round:            2,
		BlockID:          common.Hash{},
		TimestampMs:      352353,
		ValidatorAddress: pubKey.Address(),
		ValidatorIndex:   3,
		Signature:        []byte{},
	}

	pv.SignVote(context.Background(), "aaa", &v)
	assert.NoError(t, v.Verify("aaa", pubKey))
}

func TestSignProposal(t *testing.T) {
	pv := GeneratePrivValidatorLocal()
	pubKey, err := pv.GetPubKey(context.Background())
	assert.NoError(t, err)

	c := CommitSig{
		BlockIDFlag:      BlockIDFlagCommit,
		ValidatorAddress: common.Address{},
		TimestampMs:      1133423,
		Signature:        []byte{},
	}

	cm := NewCommit(5, 6, common.Hash{}, []CommitSig{c})

	proposal := Proposal{
		Height:      20,
		Round:       2,
		POLRound:    -1,
		TimestampMs: 352353,
		Signature:   []byte{},
		Block: &FullBlock{Block: types.NewBlock(
			&Header{
				ParentHash:     common.Hash{},
				Number:         big.NewInt(6),
				TimeMs:         34534,
				Coinbase:       common.Address{},
				LastCommitHash: common.Hash{},
				Difficulty:     big.NewInt(1),
				Extra:          []byte{},
				BaseFee:        big.NewInt(2), // TODO
				NextValidators: []common.Address{},
			},
			[]*types.Transaction{},
			[]*types.Header{},
			[]*types.Receipt{},
			trie.NewStackTrie(nil)),
			LastCommit: cm,
		},
	}

	pv.SignProposal(context.Background(), "aaa", &proposal)
	assert.True(t, pubKey.VerifySignature(proposal.ProposalSignBytes("aaa"), proposal.Signature))
}

func TestSignNilVote(t *testing.T) {
	pv := GeneratePrivValidatorLocal()
	pubKey, err := pv.GetPubKey(context.Background())
	assert.NoError(t, err)

	vote := &Vote{
		ValidatorAddress: pubKey.Address(),
		ValidatorIndex:   0,
		Height:           6,
		Round:            1,
		TimestampMs:      1234,
		Type:             PrecommitType,
		BlockID:          common.Hash{},
	}

	assert.NoError(t, pv.SignVote(context.Background(), "test", vote))

	commitSig := vote.CommitSig()
	assert.False(t, commitSig.ForBlock())

	assert.True(t, pubKey.VerifySignature(vote.VoteSignBytes("test"), commitSig.Signature))
}

func TestSignCommitWithNil(t *testing.T) {
	n := 4
	pv := make([]PrivValidator, n)
	pk := make([]PubKey, n)
	addrs := make([]common.Address, n)
	powers := make([]int64, n)

	for i := 0; i < n; i++ {
		pv[i] = GeneratePrivValidatorLocal()
		p, err := pv[i].GetPubKey(context.Background())
		assert.NoError(t, err)
		pk[i] = p

		powers[i] = 1
		addrs[i] = p.Address()
	}

	vals := NewValidatorSet(addrs, powers, 4)
	vs := NewVoteSet("test", 1, 2, PrecommitType, vals)
	blockHash := common.BytesToHash([]byte{1, 2, 3})
	for i := 0; i < n; i++ {
		var blockId common.Hash
		if i != 0 {
			blockId = blockHash
		}
		vote := &Vote{
			ValidatorAddress: pk[i].Address(),
			ValidatorIndex:   int32(i),
			Height:           1,
			Round:            2,
			TimestampMs:      1234,
			Type:             PrecommitType,
			BlockID:          blockId,
		}

		assert.NoError(t, pv[i].SignVote(context.Background(), "test", vote))

		if i == 0 {
			fmt.Println(hex.EncodeToString(vote.VoteSignBytes("test")))
		}

		added, err := vs.AddVote(vote)
		assert.NoError(t, err)
		assert.True(t, added)
	}

	commit := vs.MakeCommit()

	assert.NoError(t, vals.VerifyCommit(
		"test", blockHash, 1, commit))
}
