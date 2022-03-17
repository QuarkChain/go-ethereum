package consensus

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type PubKey interface {
	Address() common.Address
	// Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
	// Equals(PubKey) bool
	Type() string
}

type EcdsaPubKey struct {
	address common.Address
}

func NewEcdsaPubKey(addr common.Address) PubKey {
	return &EcdsaPubKey{address: addr}
}

func (pubkey *EcdsaPubKey) Type() string {
	return "ECDSA_PUBKEY"
}

func (pubkey *EcdsaPubKey) Address() common.Address {
	return pubkey.address
}

func (pubkey *EcdsaPubKey) VerifySignature(msg []byte, sig []byte) bool {
	h := crypto.Keccak256Hash(msg)

	pub, err := crypto.Ecrecover(h[:], sig)
	if err != nil {
		return false
	}

	if len(pub) == 0 || pub[0] != 4 {
		return false
	}

	addr := pubKeyToAddress(pub)
	return addr == pubkey.address
}
