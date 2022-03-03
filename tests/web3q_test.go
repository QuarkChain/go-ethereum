package tests

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"path/filepath"
	"testing"
)

var web3QTestDir = filepath.Join(baseDir, "Web3QTest")
var StakeTestDir = filepath.Join(web3QTestDir, "Stake")

func TestWeb3QStakeForCode(t *testing.T) {

	t.Parallel()
	st := new(testMatcher)

	for _, dir := range []string{
		StakeTestDir,
	} {
		st.walk(t, dir, func(t *testing.T, name string, test *StateTest) {
			for _, subtest := range test.Subtests() {
				subtest := subtest
				key := fmt.Sprintf("%s%d", subtest.Fork, subtest.Index)

				t.Run(key+"/trie", func(t *testing.T) {
					withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {

						_, db, err := test.Run(subtest, vmconfig, false)

						caller := common.HexToAddress("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
						err1 := checkState(subtest, caller, test, db)
						if err1 != nil {
							t.Fatal(err)
						}

						if err != nil {
							t.Fatal(err)
						}
						contract := getCreateContractAddr(caller, 0)
						balance := db.GetBalance(contract)
						code := db.GetCode(contract)
						t.Log("balance:", balance)
						t.Log("code:", code)

						callerBalance := db.GetBalance(caller)
						t.Log("caller balance:", callerBalance)

						if err != nil && len(test.json.Post[subtest.Fork][subtest.Index].ExpectException) > 0 {
							// Ignore expected errors (TODO MariusVanDerWijden check error string)

							return nil
						}
						return st.checkFailure(t, err)
					})
				})
			}
		})
	}
}

func checkState(subtest StateSubtest, caller common.Address, test *StateTest, db *state.StateDB) error {
	post := test.json.Post[subtest.Fork][subtest.Index]
	nonce := test.json.Tx.Nonce
	contract := getCreateContractAddr(caller, nonce)

	// check value
	valuestr := test.json.Tx.Value[post.Indexes.Value]
	// notify: need cut "0x"
	valueBytes := common.Hex2Bytes(valuestr[2:])
	value := new(big.Int).SetBytes(valueBytes)
	contractValue := db.GetBalance(contract)
	if value.Cmp(contractValue) != 0 {
		return fmt.Errorf("value in contract err")
	}

	// check runtime code
	datastr := test.json.Tx.Data[post.Indexes.Data]
	dataBytes := common.Hex2Bytes(datastr[2:])

	code := db.GetCode(contract)

	inputData := dataBytes[len(dataBytes)-len(code):]
	if len(inputData) != len(code) {
		return fmt.Errorf("code err")
	}
	//common.Hex2Bytes(value)

	return nil

}
