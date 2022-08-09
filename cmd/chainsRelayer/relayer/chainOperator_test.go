package relayer

import "testing"

func TestNewRealayerByKeyStore(t *testing.T) {
	filepath := "/Users/chenyanlong/Work/go-ethereum/cmd/geth/data_val_0/keystore/UTC--2022-06-07T04-15-42.696295000Z--96f22a48dcd4dfb99a11560b24bee02f374ca77d"
	r, err := NewRelayerByKeyStore(filepath, "123")
	if err != nil {
		t.Error(err)
	}

	t.Log(r.prikey)
}
