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
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"log"
	"math"
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
	chainIdStr := addPrefix0(strconv.FormatUint(chainId, 16))
	txHash := dstTxHash.String()[2:]
	logIdxStr := addPrefix0(strconv.FormatUint(logIdx, 16))
	maxDataLenStr := addPrefix0(strconv.FormatUint(maxDataLen, 16))
	confirmStr := addPrefix0(strconv.FormatUint(confirm, 16))

	return chainIdStr + txHash + logIdxStr + maxDataLenStr + confirmStr
}

func addPrefix0(str string) string {
	spliceStr := "0000000000000000000000000000000000000000000000000000000000000000"
	endIndex := len(spliceStr) - len(str)
	spliceStr = spliceStr[:endIndex]
	return (spliceStr + str)
}

func TestCrossChainCallPrecompile(t *testing.T) {

	/*
		The Trigger Event
		Addr
		0000000000000000000000000000000000000000000000000000000000000aaa
		Topics
		0000000000000000000000000000000000000000000000000000000000000060
		00000000000000000000000000000000000000000000000000000000000000c0
		0000000000000000000000000000000000000000000000000000000000000002
		dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9
		0000000000000000000000000000000000000000000000000000000000000001
		Data (length = 160)
		00000000000000000000000000000000000000000000000000000000000000a0
		0000000000000000000000000000000000000000000000000000000000000002
		0000000000000000000000000000000000000000000000000000000000000001
		0000000000000000000000000000000000000000000000000000000000000060
		0000000000000000000000000000000000000000000000000000000000000010
		aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000
	*/

	// test crossChainCall when maxDataLen is 160(the actual data length is equal to 160)
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 300, confirm)

		result, err := vm.VerifyCrossChainCall(client, input)
		if err != nil {
			t.Fatal(err)
		}

		expectOutput := common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000aaa000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000")
		if !bytes.Equal(result, expectOutput) {
			t.Errorf("incorrect external call result \n%s  \n ,actual result :\n%s", common.Bytes2Hex(expectOutput), common.Bytes2Hex(result))
		}

	}

	// test crossChainCall when maxDataLen is 160(the actual data length is equal to 160)
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 160, confirm)

		result, err := vm.VerifyCrossChainCall(client, input)
		if err != nil {
			t.Fatal(err)
		}

		expectOutput := common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000aaa000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000")
		if !bytes.Equal(result, expectOutput) {
			t.Errorf("incorrect external call result \n%s  \n ,actual result :\n%s", common.Bytes2Hex(expectOutput), common.Bytes2Hex(result))
		}

	}

	//test crossChainCall when maxDataLen is 120
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 120, confirm)

		result, err := vm.VerifyCrossChainCall(client, input)
		if err != nil {
			t.Fatal(err)
		}

		expectOutput := common.FromHex("0000000000000000000000000000000000000000000000000000000000000aaa000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000780000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000")
		if !bytes.Equal(result, expectOutput) {
			t.Errorf("incorrect external call result \n%s  \n ,actual result :\n%s", common.Bytes2Hex(expectOutput), common.Bytes2Hex(result))
		}

	}

	// test crossChainCall when maxDataLen is 0
	{
		rec, client, err := newMuskBlockChain()
		if err != nil {
			t.Fatal(err)
		}

		chainId, err := client.ChainID(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		var confirm uint64 = 10
		client.MintNewBlock(confirm + rec.BlockNumber.Uint64())

		input := generateExternalCallInput(chainId.Uint64(), rec.TxHash, 0, 0, confirm)

		result, err := vm.VerifyCrossChainCall(client, input)
		if err != nil {
			t.Fatal(err)
		}

		expectOutput := common.FromHex("0000000000000000000000000000000000000000000000000000000000000aaa000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca900000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000")
		if !bytes.Equal(result, expectOutput) {
			t.Errorf("incorrect external call result \n%s  \n ,actual result :\n%s", common.Bytes2Hex(expectOutput), common.Bytes2Hex(result))
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
			if err.Error() != "CrossChainCall: confirms no enough" {
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
			if err.Error() != "Expect Error:CrossChainCall: logIdx out-of-bound" {
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
			if err.Error() != "Expect Error:CrossChainCall: chainId 2 no support" {
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
			if err.Error() != "not found" {
				t.Errorf("The resulting error does not match the expected error; actual err:%s", err.Error())
			}
		} else {
			t.Error("expect an error")
		}
	}

}

type WrapTendermint struct {
	*clique.Clique
	Client *ethclient.Client
}

func NewWrapTendermint(cli *clique.Clique, client *ethclient.Client) *WrapTendermint {
	return &WrapTendermint{Clique: cli, Client: client}
}

type TestChainContext struct {
	tm consensus.Engine
}

func NewTestChainContext(tm consensus.Engine) *TestChainContext {
	return &TestChainContext{tm: tm}
}

func (ctx *TestChainContext) Engine() consensus.Engine {
	return ctx.tm
}

func (ctx *TestChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

type WrapTx struct {
	Tx             *types.Transaction
	GasUsed        uint64
	Args           *CrossChainCallArgument
	ExpectTxData   func() ([]byte, error)
	ExpectTraces   []*ExpectTrace
	ExpectCCRBytes []byte
	happenError    error
	Index          int
}

func (wt *WrapTx) SetExternalCallRes(crossChainCallRes []byte) {
	wt.ExpectCCRBytes = crossChainCallRes
}

func (wt *WrapTx) SetUnexpectErr(err error) {
	wt.happenError = err
}

func (wt *WrapTx) MarkTransitionIndex() string {
	return fmt.Sprintf("[Transaction Index %d]", wt.Index)
}

func NewWrapTx(tx *types.Transaction, args *CrossChainCallArgument) *WrapTx {
	return &WrapTx{Tx: tx, Args: args}
}

func (wt *WrapTx) VerifyCallResult(crossCallResult []byte, happenedError error, txIndex int, t *testing.T) {
	if happenedError != nil {
		if wt.happenError == nil {
			t.Fatalf("[txIndex %d] happened err: %s", txIndex, happenedError.Error())
			return
		}

		if happenedError.Error() != wt.happenError.Error() {
			t.Fatalf("[txIndex %d] \nexpect happen err:%s\nactual happen err:%s", txIndex, wt.happenError, happenedError)
		} else {
			t.Logf("[txIndex %d] expect happen err match: %s", txIndex, happenedError.Error())
		}
		happenedError = nil
		return
	}

	tracesWithVersion := &vm.CrossChainCallOutputsWithVersion{}
	err := rlp.DecodeBytes(crossCallResult, tracesWithVersion)
	if err != nil {
		t.Fatal(err)
	}

	actualTraces := tracesWithVersion.Outputs

	if len(wt.ExpectTraces) != len(actualTraces) {
		t.Fatalf("[txIndex %d] wrapTx.ExpectTraces length [%d] no match actualTraces length [%d]", txIndex, len(wt.ExpectTraces), len(actualTraces))
	}

	for i, v := range actualTraces {
		cs := v.Output
		wt.ExpectTraces[i].verifyRes(cs, t, txIndex, i, v.Success)
	}

}

type ExpectTrace struct {
	CallResultBytes []byte // call result
	ExpectErrBytes  error
	success         bool
	UnExpectErr     error
}

func NewExpectTrace(callResultBytes []byte, expectErrBytes error, unExpectErr error) *ExpectTrace {
	return &ExpectTrace{CallResultBytes: callResultBytes, ExpectErrBytes: expectErrBytes, UnExpectErr: unExpectErr}
}

func (et *ExpectTrace) compareRes(cs []byte) bool {
	return bytes.Equal(et.CallResultBytes, cs)
}

func (et *ExpectTrace) verifyRes(cs []byte, t *testing.T, txIndex, outputIndex int, success bool) {

	if success != true {
		t.Error("the trace.Success should be true when execute succeed")
	}
	if bytes.Equal(et.CallResultBytes, cs) {
		t.Logf("[txIndex %d][outputIndex %d] crossChainCall output match", txIndex, outputIndex)
	} else {
		t.Errorf("[txIndex %d][outputIndex %d] res no match ,expect : %s, actual: %s", txIndex, outputIndex, common.Bytes2Hex(et.CallResultBytes), common.Bytes2Hex(cs))
	}

}

type CrossChainCallArgument struct {
	ChainId     uint64
	TxHash      common.Hash
	LogIdx      uint64
	MaxDataLen  uint64
	Confirms    uint64
	contractAbi abi.ABI
	env         *vm.PrecompiledContractCallEnv
}

const CrossChainCallContract = `[
	{
		"inputs": [],
		"name": "ErrMsg",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "callTimes",
				"type": "uint256"
			}
		],
		"name": "batchCall",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callAndDealRes",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callAndDealResWithBytes",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callOnce",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callTwice",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			},
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "context",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "count",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "crossChainCallContract",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "originContract",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "topics",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "value",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]`

func NewCrossChainCallArgument(chainconfig *params.ChainConfig, client *WrapClient, chainId uint64, txHash common.Hash, logIdx uint64, maxDataLen uint64, confirms uint64) *CrossChainCallArgument {
	evmConfig := vm.Config{}
	mrctx := &vm.MindReadingContext{MREnable: true, MRClient: client, ChainId: chainconfig.MindReading.SupportChainId, MinimumConfirms: chainconfig.MindReading.MinimumConfirms}
	evm := vm.NewEVMWithMRC(vm.BlockContext{}, vm.TxContext{}, mrctx, nil, chainconfig, evmConfig)
	env := vm.NewPrecompiledContractCallEnv(evm, nil)
	abi, err := abi.JSON(strings.NewReader(CrossChainCallContract))
	if err != nil {
		panic(err)
	}
	return &CrossChainCallArgument{ChainId: chainId, TxHash: txHash, LogIdx: logIdx, MaxDataLen: maxDataLen, Confirms: confirms, contractAbi: abi, env: env}
}

func (c *CrossChainCallArgument) CallOncePack() ([]byte, error) {
	return c.contractAbi.Pack("callOnce", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
}

func (c *CrossChainCallArgument) CallOncePackWithoutErr() []byte {
	data, _ := c.contractAbi.Pack("callOnce", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
	return data
}

func (c *CrossChainCallArgument) BatchCallPackWithoutErr(times int64) []byte {
	data, _ := c.contractAbi.Pack("batchCall", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)), big.NewInt(times))
	return data
}

func (c *CrossChainCallArgument) BatchCallPack(times int64) ([]byte, error) {
	return c.contractAbi.Pack("batchCall", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)), big.NewInt(times))
}

func (c *CrossChainCallArgument) CrossChainCallResult() (*vm.GetLogByTxHash, *vm.ExpectCallErr, error) {
	return vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
}

func (c *CrossChainCallArgument) CrossChainCallResultToExpectCallResult() *ExpectTrace {
	cs, expErr, unExpErr := vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
	if unExpErr != nil {
		return NewExpectTrace(nil, nil, unExpErr)
	} else if expErr != nil {
		return NewExpectTrace(nil, expErr, nil)
	} else {
		pack, err := cs.ABIPack()
		if err != nil {
			panic(err)
		}
		return NewExpectTrace(pack, nil, nil)
	}
}

func TestApplyTransaction(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:             big.NewInt(3334),
			HomesteadBlock:      big.NewInt(0),
			DAOForkBlock:        nil,
			DAOForkSupport:      true,
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			MuirGlacierBlock:    nil,
			BerlinBlock:         big.NewInt(0),
			LondonBlock:         big.NewInt(0),
			PisaBlock:           big.NewInt(0),
			ArrowGlacierBlock:   nil,
			MindReading: &params.MindReadingConfig{
				EnableBlockNumber: big.NewInt(0),
				Version:           1,
				SupportChainId:    1337,
				MinimumConfirms:   0,
			},
		}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
	)

	var (
		db           = rawdb.NewMemoryDatabase()
		contractAddr = common.HexToAddress("0xa000000000000000000000000000000000000aaa")
		gspec        = &core.Genesis{
			Config: config,
			Alloc: core.GenesisAlloc{
				addr1: core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   0,
				},
				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
				},
				contractAddr: core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
					Code:    common.FromHex("0x608060405234801561001057600080fd5b50600436106100b45760003560e01c80638c95e054116100715780638c95e054146101a45780639afb416c146101c2578063a25a92aa146101e0578063bb36008d146101fc578063d0496d6a14610218578063f9f8a58814610236576100b4565b806306661abd146100b957806318d9adab146100d757806320615362146101075780632fbc69e2146101385780633fa4f24514610156578063518a351014610174575b600080fd5b6100c1610252565b6040516100ce9190610b38565b60405180910390f35b6100f160048036038101906100ec9190610b93565b610258565b6040516100fe9190610bd9565b60405180910390f35b610121600480360381019061011c9190610c20565b61027c565b60405161012f929190610d2b565b60405180910390f35b61014061045d565b60405161014d9190610db7565b60405180910390f35b61015e6104eb565b60405161016b9190610b38565b60405180910390f35b61018e60048036038101906101899190610c20565b6104f1565b60405161019b9190610dd9565b60405180910390f35b6101ac6105e0565b6040516101b99190610e3c565b60405180910390f35b6101ca6105e7565b6040516101d79190610e3c565b60405180910390f35b6101fa60048036038101906101f59190610c20565b61060b565b005b61021660048036038101906102119190610e57565b61079d565b005b6102206108a5565b60405161022d9190610dd9565b60405180910390f35b610250600480360381019061024b9190610c20565b610933565b005b60035481565b6001818154811061026857600080fd5b906000526020600020016000915090505481565b6060806000878787878760405160200161029a959493929190610f26565b60405160208183030381529060405290506000806203332173ffffffffffffffffffffffffffffffffffffffff16836040516102d69190610fc1565b6000604051808303816000865af19150503d8060008114610313576040519150601f19603f3d011682016040523d82523d6000602084013e610318565b606091505b50915091508161035d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103549061104a565b60405180910390fd5b60008a8a60018b61036e9190611099565b8a8a604051602001610384959493929190610f26565b60405160208183030381529060405290506000806203332173ffffffffffffffffffffffffffffffffffffffff16836040516103c09190610fc1565b6000604051808303816000865af19150503d80600081146103fd576040519150601f19603f3d011682016040523d82523d6000602084013e610402565b606091505b509150915081610447576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161043e9061113f565b60405180910390fd5b8381975097505050505050509550959350505050565b6005805461046a9061118e565b80601f01602080910402602001604051908101604052809291908181526020018280546104969061118e565b80156104e35780601f106104b8576101008083540402835291602001916104e3565b820191906000526020600020905b8154815290600101906020018083116104c657829003601f168201915b505050505081565b60025481565b60606000868686868660405160200161050e959493929190610f26565b60405160208183030381529060405290506000806203332173ffffffffffffffffffffffffffffffffffffffff168360405161054a9190610fc1565b6000604051808303816000865af19150503d8060008114610587576040519150601f19603f3d011682016040523d82523d6000602084013e61058c565b606091505b5091509150816105d1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105c89061120b565b60405180910390fd5b80935050505095945050505050565b6203332181565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008585858585604051602001610626959493929190610f26565b60405160208183030381529060405290506000806203332173ffffffffffffffffffffffffffffffffffffffff16836040516106629190610fc1565b6000604051808303816000865af19150503d806000811461069f576040519150601f19603f3d011682016040523d82523d6000602084013e6106a4565b606091505b5091509150816106d957808060200190518101906106c29190611351565b600590816106d09190611546565b50505050610796565b6000806000838060200190518101906106f291906117d4565b925092509250826000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550816001908051906020019061074e929190610ab5565b506000806000838060200190518101906107689190611874565b9250925092508260028190555081600381905550806004908161078b919061193e565b505050505050505050505b5050505050565b600086868686866040516020016107b8959493929190610f26565b604051602081830303815290604052905060005b8281101561089b576000806203332173ffffffffffffffffffffffffffffffffffffffff16846040516107ff9190610fc1565b6000604051808303816000865af19150503d806000811461083c576040519150601f19603f3d011682016040523d82523d6000602084013e610841565b606091505b509150915081610886576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161087d9061120b565b60405180910390fd5b5050808061089390611a10565b9150506107cc565b5050505050505050565b600480546108b29061118e565b80601f01602080910402602001604051908101604052809291908181526020018280546108de9061118e565b801561092b5780601f106109005761010080835404028352916020019161092b565b820191906000526020600020905b81548152906001019060200180831161090e57829003601f168201915b505050505081565b6000858585858560405160200161094e959493929190610f26565b60405160208183030381529060405290506000806203332173ffffffffffffffffffffffffffffffffffffffff168360405161098a9190610fc1565b6000604051808303816000865af19150503d80600081146109c7576040519150601f19603f3d011682016040523d82523d6000602084013e6109cc565b606091505b509150915081610a0157808060200190518101906109ea9190611351565b600590816109f89190611546565b50505050610aae565b600080600083806020019051810190610a1a91906117d4565b925092509250826000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508160019080519060200190610a76929190610ab5565b50600080600083806020019051810190610a909190611874565b92509250925082600281905550816003819055505050505050505050505b5050505050565b828054828255906000526020600020908101928215610af1579160200282015b82811115610af0578251825591602001919060010190610ad5565b5b509050610afe9190610b02565b5090565b5b80821115610b1b576000816000905550600101610b03565b5090565b6000819050919050565b610b3281610b1f565b82525050565b6000602082019050610b4d6000830184610b29565b92915050565b6000604051905090565b600080fd5b600080fd5b610b7081610b1f565b8114610b7b57600080fd5b50565b600081359050610b8d81610b67565b92915050565b600060208284031215610ba957610ba8610b5d565b5b6000610bb784828501610b7e565b91505092915050565b6000819050919050565b610bd381610bc0565b82525050565b6000602082019050610bee6000830184610bca565b92915050565b610bfd81610bc0565b8114610c0857600080fd5b50565b600081359050610c1a81610bf4565b92915050565b600080600080600060a08688031215610c3c57610c3b610b5d565b5b6000610c4a88828901610b7e565b9550506020610c5b88828901610c0b565b9450506040610c6c88828901610b7e565b9350506060610c7d88828901610b7e565b9250506080610c8e88828901610b7e565b9150509295509295909350565b600081519050919050565b600082825260208201905092915050565b60005b83811015610cd5578082015181840152602081019050610cba565b60008484015250505050565b6000601f19601f8301169050919050565b6000610cfd82610c9b565b610d078185610ca6565b9350610d17818560208601610cb7565b610d2081610ce1565b840191505092915050565b60006040820190508181036000830152610d458185610cf2565b90508181036020830152610d598184610cf2565b90509392505050565b600081519050919050565b600082825260208201905092915050565b6000610d8982610d62565b610d938185610d6d565b9350610da3818560208601610cb7565b610dac81610ce1565b840191505092915050565b60006020820190508181036000830152610dd18184610d7e565b905092915050565b60006020820190508181036000830152610df38184610cf2565b905092915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610e2682610dfb565b9050919050565b610e3681610e1b565b82525050565b6000602082019050610e516000830184610e2d565b92915050565b60008060008060008060c08789031215610e7457610e73610b5d565b5b6000610e8289828a01610b7e565b9650506020610e9389828a01610c0b565b9550506040610ea489828a01610b7e565b9450506060610eb589828a01610b7e565b9350506080610ec689828a01610b7e565b92505060a0610ed789828a01610b7e565b9150509295509295509295565b6000819050919050565b610eff610efa82610b1f565b610ee4565b82525050565b6000819050919050565b610f20610f1b82610bc0565b610f05565b82525050565b6000610f328288610eee565b602082019150610f428287610f0f565b602082019150610f528286610eee565b602082019150610f628285610eee565b602082019150610f728284610eee565b6020820191508190509695505050505050565b600081905092915050565b6000610f9b82610c9b565b610fa58185610f85565b9350610fb5818560208601610cb7565b80840191505092915050565b6000610fcd8284610f90565b915081905092915050565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6000611034602583610d6d565b915061103f82610fd8565b604082019050919050565b6000602082019050818103600083015261106381611027565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006110a482610b1f565b91506110af83610b1f565b92508282019050808211156110c7576110c661106a565b5b92915050565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6000611129602583610d6d565b9150611134826110cd565b604082019050919050565b600060208201905081810360008301526111588161111c565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806111a657607f821691505b6020821081036111b9576111b861115f565b5b50919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b60006111f5601883610d6d565b9150611200826111bf565b602082019050919050565b60006020820190508181036000830152611224816111e8565b9050919050565b600080fd5b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61126d82610ce1565b810181811067ffffffffffffffff8211171561128c5761128b611235565b5b80604052505050565b600061129f610b53565b90506112ab8282611264565b919050565b600067ffffffffffffffff8211156112cb576112ca611235565b5b6112d482610ce1565b9050602081019050919050565b60006112f46112ef846112b0565b611295565b9050828152602081018484840111156113105761130f611230565b5b61131b848285610cb7565b509392505050565b600082601f8301126113385761133761122b565b5b81516113488482602086016112e1565b91505092915050565b60006020828403121561136757611366610b5d565b5b600082015167ffffffffffffffff81111561138557611384610b62565b5b61139184828501611323565b91505092915050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b6000600883026113fc7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff826113bf565b61140686836113bf565b95508019841693508086168417925050509392505050565b6000819050919050565b600061144361143e61143984610b1f565b61141e565b610b1f565b9050919050565b6000819050919050565b61145d83611428565b6114716114698261144a565b8484546113cc565b825550505050565b600090565b611486611479565b611491818484611454565b505050565b5b818110156114b5576114aa60008261147e565b600181019050611497565b5050565b601f8211156114fa576114cb8161139a565b6114d4846113af565b810160208510156114e3578190505b6114f76114ef856113af565b830182611496565b50505b505050565b600082821c905092915050565b600061151d600019846008026114ff565b1980831691505092915050565b6000611536838361150c565b9150826002028217905092915050565b61154f82610d62565b67ffffffffffffffff81111561156857611567611235565b5b611572825461118e565b61157d8282856114b9565b600060209050601f8311600181146115b0576000841561159e578287015190505b6115a8858261152a565b865550611610565b601f1984166115be8661139a565b60005b828110156115e6578489015182556001820191506020850194506020810190506115c1565b8683101561160357848901516115ff601f89168261150c565b8355505b6001600288020188555050505b505050505050565b600061162382610dfb565b9050919050565b61163381611618565b811461163e57600080fd5b50565b6000815190506116508161162a565b92915050565b600067ffffffffffffffff82111561167157611670611235565b5b602082029050602081019050919050565b600080fd5b60008151905061169681610bf4565b92915050565b60006116af6116aa84611656565b611295565b905080838252602082019050602084028301858111156116d2576116d1611682565b5b835b818110156116fb57806116e78882611687565b8452602084019350506020810190506116d4565b5050509392505050565b600082601f83011261171a5761171961122b565b5b815161172a84826020860161169c565b91505092915050565b600067ffffffffffffffff82111561174e5761174d611235565b5b61175782610ce1565b9050602081019050919050565b600061177761177284611733565b611295565b90508281526020810184848401111561179357611792611230565b5b61179e848285610cb7565b509392505050565b600082601f8301126117bb576117ba61122b565b5b81516117cb848260208601611764565b91505092915050565b6000806000606084860312156117ed576117ec610b5d565b5b60006117fb86828701611641565b935050602084015167ffffffffffffffff81111561181c5761181b610b62565b5b61182886828701611705565b925050604084015167ffffffffffffffff81111561184957611848610b62565b5b611855868287016117a6565b9150509250925092565b60008151905061186e81610b67565b92915050565b60008060006060848603121561188d5761188c610b5d565b5b600061189b8682870161185f565b93505060206118ac8682870161185f565b925050604084015167ffffffffffffffff8111156118cd576118cc610b62565b5b6118d9868287016117a6565b9150509250925092565b60008190508160005260206000209050919050565b601f8211156119395761190a816118e3565b611913846113af565b81016020851015611922578190505b61193661192e856113af565b830182611496565b50505b505050565b61194782610c9b565b67ffffffffffffffff8111156119605761195f611235565b5b61196a825461118e565b6119758282856118f8565b600060209050601f8311600181146119a85760008415611996578287015190505b6119a0858261152a565b865550611a08565b601f1984166119b6866118e3565b60005b828110156119de578489015182556001820191506020850194506020810190506119b9565b868310156119fb57848901516119f7601f89168261150c565b8355505b6001600288020188555050505b505050505050565b6000611a1b82610b1f565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611a4d57611a4c61106a565b5b60018201905091905056fea2646970667358221220ddc5debade2a5e1f483d23041b151810ff4f029d45752397287386c2fe71fa6164736f6c63430008110033"),
				},
			},
		}

		globalchainId = config.ChainID
		genesis       = gspec.MustCommit(db)
	)

	rec, externalClient, err := newMuskBlockChain()
	if err != nil {
		t.Fatal(err)
	}

	targetTxHash := rec.TxHash
	const txHashNotFound = "0x0000000000000000000000000000000000000000000000000000000000000001"

	ctx := context.Background()
	chainID, err := externalClient.ChainID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	CallOnceArgs := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 0, 300, 10)
	//CallOnceArgsWithExpectErrAsLogIdxExceed := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 2, 300, 10)
	CallOnceArgsWithExpectErrAsNotFound := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), common.HexToHash(txHashNotFound), 2, 300, 10)

	BatchCallTrace0 := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 0, 300, 10)
	BatchCallTrace1 := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 0, 300, 10)
	BatchCallTrace2 := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 0, 300, 10)
	BatchCallArgs := NewCrossChainCallArgument(config, externalClient, chainID.Uint64(), targetTxHash, 0, 300, 10)

	//ExpectErrChainIdNoSupportArgs := NewCrossChainCallArgument(config, externalClient, 5, targetTxHash, 0, 300, 10)

	wrapTxs := []*WrapTx{
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      CallOnceArgs.CallOncePackWithoutErr(),
			}),
			Args:         CallOnceArgs,
			ExpectTxData: CallOnceArgs.CallOncePack,
			ExpectTraces: []*ExpectTrace{
				CallOnceArgs.CrossChainCallResultToExpectCallResult(),
			},
		},
		// expect err match:CrossChainCall:logIdx out-of-bound
		//&WrapTx{
		//	Tx: types.NewTx(&types.DynamicFeeTx{
		//		ChainID:   globalchainId,
		//		Nonce:     0,
		//		To:        &contractAddr,
		//		Value:     big.NewInt(0),
		//		Gas:       5000000,
		//		GasTipCap: big.NewInt(1000000000),
		//		GasFeeCap: big.NewInt(6000000000),
		//		Data:      CallOnceArgsWithExpectErrAsLogIdxExceed.CallOncePackWithoutErr(),
		//	}),
		//	Args:         CallOnceArgsWithExpectErrAsLogIdxExceed,
		//	ExpectTxData: CallOnceArgsWithExpectErrAsLogIdxExceed.CallOncePack,
		//	ExpectTraces: []*ExpectTrace{
		//		CallOnceArgsWithExpectErrAsLogIdxExceed.CrossChainCallResultToExpectCallResult(),
		//	},
		//	happenError: vm.NewExpectCallErr("CrossChainCall: logIdx out-of-bound"),
		//},
		// unexpect err txHash not found
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      CallOnceArgsWithExpectErrAsNotFound.CallOncePackWithoutErr(),
			}),
			Args:         CallOnceArgsWithExpectErrAsNotFound,
			ExpectTxData: CallOnceArgsWithExpectErrAsNotFound.CallOncePack,
			happenError:  ethereum.NotFound,
		},
		//// expect err chainId no support
		//&WrapTx{
		//	Tx: types.NewTx(&types.DynamicFeeTx{
		//		ChainID:   globalchainId,
		//		Nonce:     0,
		//		To:        &contractAddr,
		//		Value:     big.NewInt(0),
		//		Gas:       5000000,
		//		GasTipCap: big.NewInt(1000000000),
		//		GasFeeCap: big.NewInt(6000000000),
		//		Data:      ExpectErrChainIdNoSupportArgs.CallOncePackWithoutErr(),
		//	}),
		//	Args:         ExpectErrChainIdNoSupportArgs,
		//	ExpectTxData: ExpectErrChainIdNoSupportArgs.CallOncePack,
		//	happenError:  vm.NewExpectCallErr(fmt.Sprintf("CrossChainCall: chainId %d no support", ExpectErrChainIdNoSupportArgs.ChainId)),
		//},
		// cross-chain-call twice
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      BatchCallArgs.BatchCallPackWithoutErr(3),
			}),
			Args: BatchCallArgs,
			ExpectTraces: []*ExpectTrace{
				BatchCallTrace0.CrossChainCallResultToExpectCallResult(),
				BatchCallTrace1.CrossChainCallResultToExpectCallResult(),
				BatchCallTrace2.CrossChainCallResultToExpectCallResult(),
			},
		},
	}

	var singedWrapTxs []*WrapTx
	for i, wrapTx := range wrapTxs {
		signer := types.LatestSignerForChainID(globalchainId)
		signTx, err := types.SignTx(wrapTx.Tx, signer, key1)
		if err != nil {
			t.Error(err)
		}

		wrapTx.Tx = signTx

		if wrapTx.ExpectTxData != nil {
			txData, err := wrapTx.ExpectTxData()
			if err != nil {
				t.Fatal(err)
			}
			if common.Bytes2Hex(txData) != common.Bytes2Hex(wrapTx.Tx.Data()) {
				t.Fatalf("%d Tx data no match. wrapTx.ExpectTxData():%s ,", i, common.Bytes2Hex(wrapTx.Tx.Data()))
			}
		}

		singedWrapTxs = append(singedWrapTxs, wrapTx)
	}

	// evm executes a transaction while the external calling client is active
	for txIndex, stx := range singedWrapTxs {
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(core.GasPool)
		gaspool.AddGas(8000000000)

		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		vmconfig := vm.Config{Debug: true, Tracer: tracer}
		mrCtx := vm.NewMindReadingContext(externalClient, false, true, config)
		_, statedb := MakePreState(db, gspec.Alloc, false)

		msg, err := stx.Tx.AsMessage(types.MakeSigner(config, block.Header().Number), block.Header().BaseFee)
		if err != nil {
			t.Fatal(err)
		}
		// Create a new context to be used in the EVM environment
		blockContext := core.NewEVMBlockContext(block.Header(), chainContext, &addr1)
		vmenv := vm.NewEVMWithMRC(blockContext, vm.TxContext{}, mrCtx, statedb, config, vmconfig)
		execResult, err := core.ApplyMessage(vmenv, msg, gaspool)
		if err != nil {
			stx.VerifyCallResult(nil, err, txIndex, t)
		} else {
			stx.VerifyCallResult(execResult.CCCOutputs, err, txIndex, t)
			stx.SetExternalCallRes(execResult.CCCOutputs)
		}
	}

	t.Log("================preset crossChainCall output=====================")
	//evm executes a transaction while the external calling client is inactive
	for txIndex, stx := range singedWrapTxs {
		if stx.happenError != nil {
			continue
		}
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(core.GasPool)
		gaspool.AddGas(8000000000)

		var actualUsedGas uint64 = 0
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		// set the externalCallClient as nil
		//
		vmconfig := vm.Config{Debug: true, Tracer: tracer}

		mrCtx := vm.NewMindReadingContext(nil, true, true, config)

		_, statedb := MakePreState(db, gspec.Alloc, false)

		msg, err := stx.Tx.AsMessage(types.MakeSigner(config, block.Header().Number), block.Header().BaseFee)
		if err != nil {
			t.Error(err)
		}
		// Create a new context to be used in the EVM environment
		blockContext := core.NewEVMBlockContext(block.Header(), chainContext, &addr1)
		vmenv := vm.NewEVMWithMRC(blockContext, vm.TxContext{}, mrCtx, statedb, config, vmconfig)

		// preset CrossChainCall outputs in evm
		vmenv.PresetCCCOutputs(stx.ExpectCCRBytes)
		execResult, err := core.ApplyMessage(vmenv, msg, gaspool)

		if err != nil {
			stx.VerifyCallResult(nil, err, txIndex, t)
		} else {
			stx.VerifyCallResult(execResult.CCCOutputs, err, txIndex, t)
		}

		// compare gas use
		if actualUsedGas != stx.GasUsed {
			t.Errorf("The gas consumption is different when the client is nil and not nil, txIndex=[%d] , nil gas used (%d) , no nil gas used (%d) ", txIndex, actualUsedGas, stx.GasUsed)
		}
	}
}
