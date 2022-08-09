package utils

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"io/ioutil"
)

// LoadPriKey loads a serialized guardian key from disk.
func LoadPriKey(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	gk, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize raw key data: %w", err)
	}

	return gk, nil
}

func SavePrivateKey(inPath, outPath, passwd string) {
	keyjson, e := ioutil.ReadFile(inPath)
	if e != nil {
		panic(e)
	}
	key, e := keystore.DecryptKey(keyjson, passwd)
	if e != nil {
		panic(e)
	}
	e = crypto.SaveECDSA(outPath, key.PrivateKey)
	if e != nil {
		panic(e)
	}
	fmt.Println("Key saved to:", outPath)

}
