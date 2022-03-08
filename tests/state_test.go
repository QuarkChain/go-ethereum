// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
)

func TestState(t *testing.T) {
	t.Parallel()

	st := new(testMatcher)
	// Long tests:
	st.slow(`^stAttackTest/ContractCreationSpam`)
	st.slow(`^stBadOpcode/badOpcodes`)
	st.slow(`^stPreCompiledContracts/modexp`)
	st.slow(`^stQuadraticComplexityTest/`)
	st.slow(`^stStaticCall/static_Call50000`)
	st.slow(`^stStaticCall/static_Return50000`)
	st.slow(`^stSystemOperationsTest/CallRecursiveBomb`)
	st.slow(`^stTransactionTest/Opcodes_TransactionInit`)

	// Very time consuming
	st.skipLoad(`^stTimeConsuming/`)
	st.skipLoad(`.*vmPerformance/loop.*`)

	// Uses 1GB RAM per tested fork
	st.skipLoad(`^stStaticCall/static_Call1MB`)

	// Broken tests:
	// Expected failures:
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/Byzantium/0`, "bug in test")
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/Byzantium/3`, "bug in test")
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/Constantinople/0`, "bug in test")
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/Constantinople/3`, "bug in test")
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/ConstantinopleFix/0`, "bug in test")
	//st.fails(`^stRevertTest/RevertPrecompiledTouch(_storage)?\.json/ConstantinopleFix/3`, "bug in test")

	// For Istanbul, older tests were moved into LegacyTests
	for _, dir := range []string{
		stateTestDir,
		legacyStateTestDir,
	} {
		st.walk(t, dir, func(t *testing.T, name string, test *StateTest) {
			for _, subtest := range test.Subtests() {
				subtest := subtest
				key := fmt.Sprintf("%s/%d", subtest.Fork, subtest.Index)

				t.Run(key+"/trie", func(t *testing.T) {
					withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
						_, _, err := test.Run(subtest, vmconfig, false)
						if err != nil && len(test.json.Post[subtest.Fork][subtest.Index].ExpectException) > 0 {
							// Ignore expected errors (TODO MariusVanDerWijden check error string)
							return nil
						}
						return st.checkFailure(t, err)
					})
				})
				t.Run(key+"/snap", func(t *testing.T) {
					withTrace(t, test.gasLimit(subtest), func(vmconfig vm.Config) error {
						snaps, statedb, err := test.Run(subtest, vmconfig, true)
						if snaps != nil && statedb != nil {
							if _, err := snaps.Journal(statedb.IntermediateRoot(false)); err != nil {
								return err
							}
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

// Transactions with gasLimit above this value will not get a VM trace on failure.
const traceErrorLimit = 400000

func withTrace(t *testing.T, gasLimit uint64, test func(vm.Config) error) {
	// Use config from command line arguments.
	config := vm.Config{}
	err := test(config)
	if err == nil {
		return
	}

	// Test failed, re-run with tracing enabled.
	t.Error(err)
	if gasLimit > traceErrorLimit {
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

						if err != nil {
							StateTrie(db, test, t)
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

func StateTrie(db *state.StateDB, test *StateTest, t *testing.T) {
	noContractCreation := test.json.Tx.To != ""

	fmt.Println("--------------------state info-------------------")
	for addr, _ := range test.json.Pre {
		//object := db.GetOrNewStateObject(addr)
		fmt.Println("address:", addr)
		fmt.Println("balance:", db.GetBalance(addr))
		fmt.Println("code:", db.GetCode(addr))
		fmt.Println("nonce:", db.GetNonce(addr))
		fmt.Println("--------------------------------------------")
	}

	if !noContractCreation {
		caller := common.HexToAddress("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
		contract := getCreateContractAddr(caller, test.json.Tx.Nonce)
		fmt.Println("address:", contract)
		fmt.Println("balance:", db.GetBalance(contract))
		fmt.Println("code:", db.GetCode(contract))
		fmt.Println("nonce:", db.GetNonce(contract))
		fmt.Println("--------------------------------------------")
	}
}
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
