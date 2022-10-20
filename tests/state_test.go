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
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
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
		benchmarksDir,
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

func BenchmarkEVM(b *testing.B) {
	// Walk the directory.
	dir := benchmarksDir
	dirinfo, err := os.Stat(dir)
	if os.IsNotExist(err) || !dirinfo.IsDir() {
		fmt.Fprintf(os.Stderr, "can't find test files in %s, did you clone the evm-benchmarks submodule?\n", dir)
		b.Skip("missing test files")
	}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext == ".json" {
			name := filepath.ToSlash(strings.TrimPrefix(strings.TrimSuffix(path, ext), dir+string(filepath.Separator)))
			b.Run(name, func(b *testing.B) { runBenchmarkFile(b, path) })
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
}

func runBenchmarkFile(b *testing.B, path string) {
	m := make(map[string]StateTest)
	if err := readJSONFile(path, &m); err != nil {
		b.Fatal(err)
		return
	}
	if len(m) != 1 {
		b.Fatal("expected single benchmark in a file")
		return
	}
	for _, t := range m {
		runBenchmark(b, &t)
	}
}

func runBenchmark(b *testing.B, t *StateTest) {
	for _, subtest := range t.Subtests() {
		subtest := subtest
		key := fmt.Sprintf("%s/%d", subtest.Fork, subtest.Index)

		b.Run(key, func(b *testing.B) {
			vmconfig := vm.Config{}

			config, eips, err := GetChainConfig(subtest.Fork)
			if err != nil {
				b.Error(err)
				return
			}
			vmconfig.ExtraEips = eips
			block := t.genesis(config).ToBlock(nil)
			_, statedb := MakePreState(rawdb.NewMemoryDatabase(), t.json.Pre, false)

			var baseFee *big.Int
			if config.IsLondon(new(big.Int)) {
				baseFee = t.json.Env.BaseFee
				if baseFee == nil {
					// Retesteth uses `0x10` for genesis baseFee. Therefore, it defaults to
					// parent - 2 : 0xa as the basefee for 'this' context.
					baseFee = big.NewInt(0x0a)
				}
			}
			post := t.json.Post[subtest.Fork][subtest.Index]
			msg, err := t.json.Tx.toMessage(post, baseFee)
			if err != nil {
				b.Error(err)
				return
			}

			// Try to recover tx with current signer
			if len(post.TxBytes) != 0 {
				var ttx types.Transaction
				err := ttx.UnmarshalBinary(post.TxBytes)
				if err != nil {
					b.Error(err)
					return
				}

				if _, err := types.Sender(types.LatestSigner(config), &ttx); err != nil {
					b.Error(err)
					return
				}
			}

			// Prepare the EVM.
			txContext := core.NewEVMTxContext(msg)
			context := core.NewEVMBlockContext(block.Header(), nil, &t.json.Env.Coinbase)
			context.GetHash = vmTestBlockHash
			context.BaseFee = baseFee
			evm := vm.NewEVM(context, txContext, statedb, config, vmconfig)

			// Create "contract" for sender to cache code analysis.
			sender := vm.NewContract(vm.AccountRef(msg.From()), vm.AccountRef(msg.From()),
				nil, 0)

			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				// Execute the message.
				snapshot := statedb.Snapshot()
				_, _, err = evm.Call(sender, *msg.To(), msg.Data(), msg.Gas(), msg.Value())
				if err != nil {
					b.Error(err)
					return
				}
				statedb.RevertToSnapshot(snapshot)
			}

		})
	}
}

var web3QStateTestDir = filepath.Join(baseDir, "Web3QTest")

func TestWeb3QState(t *testing.T) {
	t.Parallel()
	st := new(testMatcher)

	//st.fails("TestWeb3QState/Stake/StakeFor25kCode.json/London0/trie", "insufficient staking for code")
	for _, dir := range []string{
		web3QStateTestDir,
	} {
		st.walk(t, dir, func(t *testing.T, name string, test *StateTest) {
			for _, subtest := range test.Subtests() {
				subtest := subtest
				key := fmt.Sprintf("%s%d", subtest.Fork, subtest.Index)
				t.Run(key+"/trie", func(t *testing.T) {
					config := vm.Config{}
					_, db, err := test.Run(subtest, config, false)
					err = st.checkFailure(t, err)
					if err != nil {
						printStateTrie(db, test, t)
						t.Error(err)
					}
				})
			}
		})
	}
}

func printStateTrie(db *state.StateDB, test *StateTest, t *testing.T) {
	noContractCreation := test.json.Tx.To != ""

	t.Log("--------------------StateInfo---------------------")

	coinbase := test.json.Env.Coinbase
	t.Logf("--------------------CoinBase---------------------- \naddress: %s \nbalance: %d \nnonce: %d \n", coinbase.Hex(), db.GetBalance(coinbase).Int64(), db.GetNonce(coinbase))
	for addr, acc := range test.json.Pre {
		t.Logf("--------------------Account---------------------- \naddress: %s \npre balance: %d \n    balance: %d \nnonce: %d \ncode len: %d \n", addr.Hex(), acc.Balance.Int64(), db.GetBalance(addr).Int64(), db.GetNonce(addr), len(db.GetCode(addr)))
	}

	if !noContractCreation {
		caller := common.HexToAddress("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
		contract := getCreateContractAddr(caller, test.json.Tx.Nonce)
		t.Logf("--------------------Account---------------------- \naddress: %s \nbalance: %d \nnonce: %d \ncode len: %d \n", contract.Hex(), db.GetBalance(contract).Int64(), db.GetNonce(contract), len(db.GetCode(contract)))
	}
	t.Log("-------------------END-------------------------")
}

func getCreateContractAddr(caller common.Address, nonce uint64) common.Address {
	return crypto.CreateAddress(caller, nonce)
}

type WrapClient struct {
	*backends.SimulatedBackend
	latestBlock uint64
}

func NewWrapClient(simulatedBackend *backends.SimulatedBackend) *WrapClient {
	return &WrapClient{SimulatedBackend: simulatedBackend, latestBlock: 0}
}

func (c *WrapClient) MintNewBlock(num uint64) {
	c.latestBlock += num
}

func (c *WrapClient) BlockNumber(ctx context.Context) (uint64, error) {
	return c.latestBlock, nil
}

func (c *WrapClient) ChainID(ctx context.Context) (*big.Int, error) {
	return c.Blockchain().Config().ChainID, nil
}

func newMuskBlockChain() (*types.Receipt, *WrapClient, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	chainId := big.NewInt(1337)
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainId)

	balance := new(big.Int)
	balance.SetString("100000000000000000000", 10) // 100 eth in wei

	triggerEventContract := common.HexToAddress("0000000000000000000000000000000000000aaa")
	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
		triggerEventContract: {
			Balance: balance,
			Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100575760003560e01c8063209652551461005c578063552410771461007a57806381045ead146100965780638ff2dc7e146100b4578063a1611e0e146100be575b600080fd5b6100646100da565b604051610071919061037b565b60405180910390f35b610094600480360381019061008f9190610288565b6100e3565b005b61009e61011a565b6040516100ab919061037b565b60405180910390f35b6100bc610123565b005b6100d860048036038101906100d391906102b5565b610151565b005b60008054905090565b807f44166b8e7efa954701ff28cba73852e3bbb791ac94a02de05fba64d11492fe9f60405160405180910390a28060008190555050565b60008054905090565b7f8e397a038a34466ac8069165f69d2f28bde665accf96372b7e665ee069dd00d260405160405180910390a1565b6002600081819054906101000a900467ffffffffffffffff1680929190610177906104d7565b91906101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555050827fdce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca983600260009054906101000a900467ffffffffffffffff16846040516101e893929190610396565b60405180910390a28160008190555082600181905550505050565b6000610216610211846103f9565b6103d4565b9050828152602081018484840111156102325761023161056b565b5b61023d848285610464565b509392505050565b600082601f83011261025a57610259610566565b5b813561026a848260208601610203565b91505092915050565b6000813590506102828161058b565b92915050565b60006020828403121561029e5761029d610575565b5b60006102ac84828501610273565b91505092915050565b6000806000606084860312156102ce576102cd610575565b5b60006102dc86828701610273565b93505060206102ed86828701610273565b925050604084013567ffffffffffffffff81111561030e5761030d610570565b5b61031a86828701610245565b9150509250925092565b600061032f8261042a565b6103398185610435565b9350610349818560208601610473565b6103528161057a565b840191505092915050565b61036681610446565b82525050565b61037581610450565b82525050565b6000602082019050610390600083018461035d565b92915050565b60006060820190506103ab600083018661035d565b6103b8602083018561036c565b81810360408301526103ca8184610324565b9050949350505050565b60006103de6103ef565b90506103ea82826104a6565b919050565b6000604051905090565b600067ffffffffffffffff82111561041457610413610537565b5b61041d8261057a565b9050602081019050919050565b600081519050919050565b600082825260208201905092915050565b6000819050919050565b600067ffffffffffffffff82169050919050565b82818337600083830152505050565b60005b83811015610491578082015181840152602081019050610476565b838111156104a0576000848401525b50505050565b6104af8261057a565b810181811067ffffffffffffffff821117156104ce576104cd610537565b5b80604052505050565b60006104e282610450565b915067ffffffffffffffff8214156104fd576104fc610508565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b61059481610446565b811461059f57600080fd5b5056fea26469706673582212205a08eea3634f7d27082237722f79299192f3e5c5cd229afea0339c3943dfa0bf64736f6c63430008070033"),
		},
	}

	blockGasLimit := uint64(50000000)
	client := backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)

	actualChainId := client.Blockchain().Config().ChainID
	if actualChainId.Cmp(chainId) != 0 {
		panic("chainId no match")
	}

	// 1. Deploy a contract with events that can be triggered by calling methods
	ctx := context.Background()
	nonce, err := client.PendingNonceAt(ctx, auth.From)
	if err != nil {
		panic(err)
	}

	// 2. Call method by sendTransaction to trigger event
	triggerEventTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   actualChainId,
		To:        &triggerEventContract,
		Nonce:     nonce,
		Data:      common.FromHex("0xa1611e0e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000"),
		GasFeeCap: big.NewInt(7000000000),
		GasTipCap: big.NewInt(1000000000),
		Gas:       800000,
	})

	triggerEventTxSigned, err := types.SignTx(triggerEventTx, types.MakeSigner(client.Blockchain().Config(), big.NewInt(0)), privateKey)
	if err != nil {
		panic(err)
	}

	err = client.SendTransaction(ctx, triggerEventTxSigned)
	if err != nil {
		panic(err)
	}

	client.Commit()
	receipt, err := client.TransactionReceipt(ctx, triggerEventTxSigned.Hash())
	if err != nil {
		panic(err)
	}

	return receipt, NewWrapClient(client), nil

}

func generateExternalCallInput(chainId uint64, dstTxHash common.Hash, logIdx uint64, maxDataLen uint64, confirm uint64) string {
	method := "99e20070"
	chainIdStr := addPrefix0(strconv.FormatUint(chainId, 16))
	txHash := dstTxHash.String()[2:]
	logIdxStr := addPrefix0(strconv.FormatUint(logIdx, 16))
	maxDataLenStr := addPrefix0(strconv.FormatUint(maxDataLen, 16))
	confirmStr := addPrefix0(strconv.FormatUint(confirm, 16))

	return method + chainIdStr + txHash + logIdxStr + maxDataLenStr + confirmStr
}

func addPrefix0(str string) string {
	spliceStr := "0000000000000000000000000000000000000000000000000000000000000000"
	endIndex := len(spliceStr) - len(str)
	spliceStr = spliceStr[:endIndex]
	return (spliceStr + str)
}

func TestCrossChainCallPrecompile(t *testing.T) {

	// Successful external call transaction
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 160, confirm)

		result, err := vm.VerifyCrossChainCall(client, input)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(result, common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000aaa000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000")) {
			t.Errorf("incorrect external call result,actual result :%s", common.Bytes2Hex(result))
		}

	}

	// Failed external call transaction:Expect Error:CrossChainCall:confirms no enough
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64() - 1)

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 160, confirm)

		_, err = vm.VerifyCrossChainCall(client, input)
		if err != nil {
			if err.Error() != "Expect Error:CrossChainCall:confirms no enough" {
				t.Error("The resulting error does not match the expected error")
			}
		} else {
			t.Error("expect an error")
		}

	}

	// Failed external call transaction: Expect Error:CrossChainCall:logIdx out-of-bound
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		var logIdx_out_range uint64 = 2
		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, logIdx_out_range, 160, confirm)

		_, err = vm.VerifyCrossChainCall(client, input)
		if err != nil {
			if err.Error() != "Expect Error:CrossChainCall:logIdx out-of-bound" {
				t.Errorf("The resulting error does not match the expected error; actual err:%s", err.Error())
			}
		} else {
			t.Error("expect an error")
		}

	}

	// Failed external call transaction: Expect Error:CrossChainCall:chainId 2 no support
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		var chainId_nosupport uint64 = 2
		input := generateExternalCallInput(chainId_nosupport, rec.TxHash, 0, 160, confirm)

		_, err = vm.VerifyCrossChainCall(client, input)
		if err != nil {
			if err.Error() != "Expect Error:CrossChainCall:chainId 2 no support" {
				t.Errorf("The resulting error does not match the expected error; actual err:%s", err.Error())
			}
		} else {
			t.Error("expect an error")
		}
	}

	// Failed external call transaction: Expect Error:not found
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		var txHash_noFound string = "0x0000000000000000000000000000000000000000000000000000000000000004"
		input := generateExternalCallInput(chainId.Uint64(), common.HexToHash(txHash_noFound), 0, 160, confirm)

		_, err = vm.VerifyCrossChainCall(client, input)
		if err != nil {
			if err.Error() != "Expect Error:not found" {
				t.Errorf("The resulting error does not match the expected error; actual err:%s", err.Error())
			}
		} else {
			t.Error("expect an error")
		}
	}

}
