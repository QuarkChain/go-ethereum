package consensus

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// PrivValidator defines the functionality of a local Tendermint validator
// that signs votes and proposals, and never double signs.
type PrivValidator interface {
	Address() common.Address
	GetPubKey(context.Context) (PubKey, error)

	SignVote(ctx context.Context, chainID string, vote *Vote) error
	SignProposal(ctx context.Context, chainID string, proposal *Proposal) error
	SignTX(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// PrivValidatorType defines the implemtation types.
type PrivValidatorType uint8

const (
	MockSignerClient      = PrivValidatorType(0x00) // mock signer
	FileSignerClient      = PrivValidatorType(0x01) // signer client via file
	RetrySignerClient     = PrivValidatorType(0x02) // signer client with retry via socket
	SignerSocketClient    = PrivValidatorType(0x03) // signer client via socket
	ErrorMockSignerClient = PrivValidatorType(0x04) // error mock signer
	SignerGRPCClient      = PrivValidatorType(0x05) // signer client via gRPC
)

type PrivValidatorLocal struct {
	PrivKey *ecdsa.PrivateKey
}

// generate a local priv validator with random key.
func GeneratePrivValidatorLocal() PrivValidator {
	pk, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		panic("failed to generate key")
	}

	return &PrivValidatorLocal{
		PrivKey: pk,
	}
}

func NewPrivValidatorLocal(privKey *ecdsa.PrivateKey) *PrivValidatorLocal {
	return &PrivValidatorLocal{PrivKey: privKey}
}

func pubKeyToAddress(pub []byte) common.Address {
	var addr common.Address
	// the first byte of pubkey is bitcoin heritage
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr
}

func (pv *PrivValidatorLocal) Address() common.Address {
	return crypto.PubkeyToAddress(pv.PrivKey.PublicKey)
}

func (pv *PrivValidatorLocal) GetPubKey(context.Context) (PubKey, error) {
	return &EcdsaPubKey{address: pv.Address()}, nil
}

func (pv *PrivValidatorLocal) SignVote(ctx context.Context, chainId string, vote *Vote) error {
	vote.TimestampMs = uint64(CanonicalNowMs())
	b := vote.VoteSignBytes(chainId)

	h := crypto.Keccak256Hash(b)
	sign, err := crypto.Sign(h[:], pv.PrivKey)
	vote.Signature = sign

	return err
}

func (pv *PrivValidatorLocal) SignProposal(ctx context.Context, chainID string, proposal *Proposal) error {
	// TODO: sanity check
	b := proposal.ProposalSignBytes(chainID)

	h := crypto.Keccak256Hash(b)

	sign, err := crypto.Sign(h[:], pv.PrivKey)
	proposal.Signature = sign
	return err
}

func (pv *PrivValidatorLocal) SignTX(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), pv.PrivKey)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(signer, signature)
}
