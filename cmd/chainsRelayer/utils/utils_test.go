package utils

import "testing"

const (
	inPath  = "/Users/chenyanlong/Work/go-ethereum/cmd/geth/data_val_0/keystore/UTC--2022-06-07T04-15-42.696295000Z--96f22a48dcd4dfb99a11560b24bee02f374ca77d"
	outPath = "/Users/chenyanlong/Work/go-ethereum/cmd/chainsRelayer/key/metamask.key"
	passwd  = "123"
)

func TestSavePrivateKey(t *testing.T) {
	SavePrivateKey(inPath, outPath, passwd)
}
