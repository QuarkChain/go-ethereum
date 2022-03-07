package tests

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"
)

var web3QTestDir = filepath.Join(baseDir, "Web3QTest")
var StakeTestDir = filepath.Join(web3QTestDir, "Stake")
var CallTestDir = filepath.Join(web3QTestDir, "Call")

func TestWeb3QExtraGasForCall(t *testing.T) {
	t.Parallel()
	st := new(testMatcher)
	for _, dir := range []string{
		CallTestDir,
	} {
		// st.walk会进入到每个json文件中 然后执行func
		st.walk(t, dir, func(t *testing.T, name string, test *StateTest) {
			for _, subtest := range test.Subtests() {
				subtest := subtest
				key := fmt.Sprintf("%s%d", subtest.Fork, subtest.Index)

				t.Run(key+"/trie", func(t *testing.T) {
					withTrace1(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {

						_, _, err := test.Run(subtest, vmconfig, false)

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
					withTrace1(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {

						_, db, err := test.Run(subtest, vmconfig, false)
						if err == nil {
							caller := common.HexToAddress("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
							err = checkState(t, subtest, caller, test, db)
						}

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

const CHUNK_SIZE = 1024 * 24
const CODE_STATKING_PER_CHUNK = 1000000000000000000
const CodeOffset = 570

func checkState(t *testing.T, subtest StateSubtest, caller common.Address, test *StateTest, db *state.StateDB) error {
	post := test.json.Post[subtest.Fork][subtest.Index]
	nonce := test.json.Tx.Nonce
	contract := getCreateContractAddr(caller, nonce)

	datastr := test.json.Tx.Data[post.Indexes.Data]
	dataBytes := common.Hex2Bytes(datastr[2:])
	inputCode := dataBytes[CodeOffset:]
	code := db.GetCode(contract)

	// notify: need cut "0x"
	valuestr := test.json.Tx.Value[post.Indexes.Value]
	valueBytes := common.Hex2Bytes(valuestr[2:])
	value := new(big.Int).SetBytes(valueBytes)
	contractBalance := db.GetBalance(contract)

	t.Log("inputcode len:", len(inputCode))
	if len(inputCode) > CHUNK_SIZE {
		t.Log("case: pay web3q for staking")
		// check if  transaction have enough value to pay for staking
		needValue := (len(inputCode) - 1) / CHUNK_SIZE
		needValue = needValue * CODE_STATKING_PER_CHUNK
		t.Log("need value:", needValue, "  value:", value.Int64())
		if value.Cmp(big.NewInt(int64(needValue))) < 0 {
			t.Log("case: no enough value for staking")
			// evm execute fail,so the balance of contract is zero
			if contractBalance.Cmp(big.NewInt(0)) != 0 {
				return fmt.Errorf("evm should execute fail, need value:%d , tx value:%d", needValue, value.Int64())
			}
			// evm execute fail,so the code of contract is empty
			if len(code) != 0 {
				return fmt.Errorf("evm should execute fail，test fail!")
			}
			t.Log("evm execute failed to execute, test succeed!")
			// evm execute failed to execute, test succeed!
			return nil
		}
	}

	//check value
	if value.Cmp(contractBalance) != 0 {
		return fmt.Errorf("value in contract err: contract value in statedb:%d , transfer value: %d", contractBalance.Int64(), value.Int64())
	}

	// check runtime code
	if len(inputCode) != len(code) {
		return fmt.Errorf("code err")
	}

	return nil

}

const traceErrorLimit1 = 400000000

func withTrace1(t *testing.T, gasLimit uint64, test func(vm.Config) error) {
	// Use config from command line arguments.
	config := vm.Config{}
	err := test(config)
	if err == nil {
		return
	}

	// Test failed, re-run with tracing enabled.
	t.Error(err)
	if gasLimit > traceErrorLimit1 {
		t.Log("gas limit too high for EVM trace")
		return
	}
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	tracer := logger.NewJSONLogger(&logger.Config{}, w)
	config.Debug, config.Tracer = true, tracer
	err2 := test(config)
	if !reflect.DeepEqual(err, err2) {
		t.Errorf("different error for second run: %v", err2)
	}
	w.Flush()
	if buf.Len() == 0 {
		t.Log("no EVM operation logs generated")
	} else {
		t.Log("EVM operation log:\n" + buf.String())
	}
	// t.Logf("EVM output: 0x%x", tracer.Output())
	// t.Logf("EVM error: %v", tracer.Error())
}

func getCreateContractAddr(caller common.Address, nonce uint64) common.Address {
	return crypto.CreateAddress(caller, nonce)
}
