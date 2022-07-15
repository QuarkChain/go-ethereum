package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

func GetSlot() common.Hash {

	slot := uint256.NewInt(0).Bytes32()
	key := uint256.NewInt(1).Bytes32()

	keydata := key[:]
	slotdata := slot[:]
	data := append(keydata, slotdata...)

	hasher := sha3.NewLegacyKeccak256().(keccakState)
	hasher.Write(data)

	hashRes := common.Hash{}
	hasher.Read(hashRes[:])

	return hashRes
}
