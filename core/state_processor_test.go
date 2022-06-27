// Copyright 2020 The go-ethereum Authors
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

package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

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
	Tx                    *types.Transaction
	GasUsed               uint64
	TxWithExternalCallRes *types.Transaction
	Args                  *CrossChainCallArgment
	ExpectTxData          func() ([]byte, error)
	ExpectTraces          []*ExpectTrace
	ExpectCCRBytes        []byte
	UnExpectErr           error
	Index                 int
}

func (wt *WrapTx) SetTxWithExternalCallRes(crossChainCallRes []byte) {
	cpy := wt.Tx.WithExternalCallResult(crossChainCallRes)
	wt.TxWithExternalCallRes = cpy
}

func (wt *WrapTx) SetUnexpectErr(err error) {
	wt.UnExpectErr = err
}

func (wt *WrapTx) MarkTransitionIndex() string {
	return fmt.Sprintf("[Transaction Index %d]", wt.Index)
}

func NewWrapTx(tx *types.Transaction, args *CrossChainCallArgment) *WrapTx {
	return &WrapTx{Tx: tx, Args: args}
}

func (wt *WrapTx) VerifyCallResult(crossCallResult []byte, unexpErr error, t *testing.T) {
	if unexpErr != nil {
		if wt.UnExpectErr == nil {
			t.Error("happen unexpect err:", unexpErr)
		}

		if unexpErr != wt.UnExpectErr {
			t.Error("\nexpect happen unexpect err:", wt.UnExpectErr, "\nactual happen unexpect err:", wt.UnExpectErr)
		} else {
			t.Log("WoW! unexpect err match:", unexpErr.Error())
		}
		// todo
	}

	tracesWithVersion := &vm.CrossChainCallTracesWithVersion{}
	err := rlp.DecodeBytes(crossCallResult, tracesWithVersion)
	if err != nil {
		t.Fatal(err)
	}

	actualTraces := tracesWithVersion.Traces

	if len(wt.ExpectTraces) != len(actualTraces) {
		t.Fatalf("wrapTx.ExpectTraces length [%d] no match actualTraces length [%d]", len(wt.ExpectTraces), len(actualTraces))
	}

	for i, v := range actualTraces {
		cs := v.CallRes
		wt.ExpectTraces[i].verifyRes(cs, t, i, v.Success)
	}

}

type ExpectTrace struct {
	CallResultBytes []byte // call result
	ExpectErrBytes  []byte
	success         bool
	UnExpectErr     error
}

func NewExpectTrace(callResultBytes []byte, expectErrBytes []byte, unExpectErr error) *ExpectTrace {
	return &ExpectTrace{CallResultBytes: callResultBytes, ExpectErrBytes: expectErrBytes, UnExpectErr: unExpectErr}
}

func (et *ExpectTrace) compareRes(cs []byte) bool {
	if len(et.ExpectErrBytes) != 0 {
		return bytes.Equal(et.ExpectErrBytes, cs)
	} else {
		return bytes.Equal(et.CallResultBytes, cs)
	}
}

func (et *ExpectTrace) verifyRes(cs []byte, t *testing.T, traceIndex int, success bool) {
	if len(et.ExpectErrBytes) != 0 {
		if success != false {
			t.Error("the trace.Success should be false when happen Expect Err")
		}
		exp := vm.NewExpectCallErr("")
		err := exp.ABIUnpack(et.ExpectErrBytes)
		if err != nil {
			t.Fatal(err)
		}

		act := vm.NewExpectCallErr("")
		err = act.ABIUnpack(cs)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(et.ExpectErrBytes, cs) {
			t.Logf("[TraceIndex %d] expect err match:%s", traceIndex, exp.Error())
		} else {
			t.Errorf("[TraceIndex %d] expect err no match , expect %s , actual %s", traceIndex, exp.Error(), act.Error())
		}
	} else {
		if success != true {
			t.Error("the trace.Success should be true when execute succeed")
		}
		if bytes.Equal(et.CallResultBytes, cs) {
			t.Logf("[TraceIndex %d] res match!!! \ncall_result{%s} ", traceIndex, common.Bytes2Hex(et.CallResultBytes))
		} else {
			t.Errorf("[TraceIndex %d] res no match ,expect : %s, actual: %s", traceIndex, common.Bytes2Hex(et.CallResultBytes), common.Bytes2Hex(cs))
		}
	}
}

type CrossChainCallArgment struct {
	ChainId     uint64
	TxHash      common.Hash
	LogIdx      uint64
	MaxDataLen  uint64
	Confirms    uint64
	contractAbi abi.ABI
	env         *vm.PrecompiledContractCallEnv
}

const CrossChainCallContract = `
[
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
	}
]`

func NewCrossChainCallArgment(chainconfig *params.ChainConfig, client *ethclient.Client, chainId uint64, txHash common.Hash, logIdx uint64, maxDataLen uint64, confirms uint64) *CrossChainCallArgment {
	evmConfig := vm.Config{ExternalCallClient: client}
	evm := vm.NewEVM(vm.BlockContext{}, vm.TxContext{}, nil, chainconfig, evmConfig)
	env := vm.NewPrecompiledContractCallEnv(evm, nil)
	abi, err := abi.JSON(strings.NewReader(CrossChainCallContract))
	if err != nil {
		panic(err)
	}
	return &CrossChainCallArgment{ChainId: chainId, TxHash: txHash, LogIdx: logIdx, MaxDataLen: maxDataLen, Confirms: confirms, contractAbi: abi, env: env}
}

func (c *CrossChainCallArgment) CallOncePack() ([]byte, error) {
	return c.contractAbi.Pack("callOnce", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
}

func (c *CrossChainCallArgment) CallTwicePack() ([]byte, error) {
	return c.contractAbi.Pack("callTwice", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
}

func (c *CrossChainCallArgment) CrossChainCallResult() (*vm.GetLogByTxHash, *vm.ExpectCallErr, error) {
	return vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
}

func (c *CrossChainCallArgment) CrossChainCallResultToExpectCallResult() *ExpectTrace {
	cs, expErr, unExpErr := vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
	if unExpErr != nil {
		return NewExpectTrace(nil, nil, unExpErr)
	} else if expErr != nil {
		pack, err := expErr.ABIPack()
		if err != nil {
			panic(err)
		}
		return NewExpectTrace(nil, pack, nil)
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
			ExternalCall: &params.ExternalCallConfig{
				Version:        1,
				SupportChainId: 4,
			},
		}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
	)

	var (
		db           = rawdb.NewMemoryDatabase()
		preAddr      = common.HexToAddress("0x0000000000000000000000000000000000033303")
		contractAddr = common.HexToAddress("0xa000000000000000000000000000000000000aaa")
		gspec        = &Genesis{
			Config: config,
			Alloc: GenesisAlloc{
				addr1: GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   0,
				},
				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
				},
				contractAddr: GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
					Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100415760003560e01c80632061536214610046578063518a3510146100775780638c95e054146100a7575b600080fd5b610060600480360381019061005b9190610510565b6100c5565b60405161006e9291906106df565b60405180910390f35b610091600480360381019061008c9190610510565b610382565b60405161009e91906106bd565b60405180910390f35b6100af6104df565b6040516100bc91906106a2565b60405180910390f35b606080600087878787876040516024016100e3959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff168360405161018d919061068b565b6000604051808303816000865af19150503d80600081146101ca576040519150601f19603f3d011682016040523d82523d6000602084013e6101cf565b606091505b509150915081610214576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020b90610756565b60405180910390fd5b60008a8a60018b6102259190610801565b8a8a60405160240161023b959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff16836040516102e5919061068b565b6000604051808303816000865af19150503d8060008114610322576040519150601f19603f3d011682016040523d82523d6000602084013e610327565b606091505b50915091508161036c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036390610736565b60405180910390fd5b8381975097505050505050509550959350505050565b60606000868686868660405160240161039f959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff1683604051610449919061068b565b6000604051808303816000865af19150503d8060008114610486576040519150601f19603f3d011682016040523d82523d6000602084013e61048b565b606091505b5091509150816104d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c790610716565b60405180910390fd5b80935050505095945050505050565b6203330381565b6000813590506104f5816109dc565b92915050565b60008135905061050a816109f3565b92915050565b600080600080600060a0868803121561052c5761052b6108ff565b5b600061053a888289016104fb565b955050602061054b888289016104e6565b945050604061055c888289016104fb565b935050606061056d888289016104fb565b925050608061057e888289016104fb565b9150509295509295909350565b61059481610857565b82525050565b6105a381610869565b82525050565b60006105b4826107c9565b6105be81856107d4565b93506105ce81856020860161089d565b6105d781610904565b840191505092915050565b60006105ed826107c9565b6105f781856107e5565b935061060781856020860161089d565b80840191505092915050565b60006106206018836107f0565b915061062b82610915565b602082019050919050565b60006106436025836107f0565b915061064e8261093e565b604082019050919050565b60006106666025836107f0565b91506106718261098d565b604082019050919050565b61068581610893565b82525050565b600061069782846105e2565b915081905092915050565b60006020820190506106b7600083018461058b565b92915050565b600060208201905081810360008301526106d781846105a9565b905092915050565b600060408201905081810360008301526106f981856105a9565b9050818103602083015261070d81846105a9565b90509392505050565b6000602082019050818103600083015261072f81610613565b9050919050565b6000602082019050818103600083015261074f81610636565b9050919050565b6000602082019050818103600083015261076f81610659565b9050919050565b600060a08201905061078b600083018861067c565b610798602083018761059a565b6107a5604083018661067c565b6107b2606083018561067c565b6107bf608083018461067c565b9695505050505050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061080c82610893565b915061081783610893565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561084c5761084b6108d0565b5b828201905092915050565b600061086282610873565b9050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156108bb5780820151818401526020810190506108a0565b838111156108ca576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6109e581610869565b81146109f057600080fd5b50565b6109fc81610893565b8114610a0757600080fd5b5056fea2646970667358221220cb96efc14e55caf807c664755d68fa44a3228605b33e42bc7be92933e03ba95364736f6c63430008070033"),
				},
			},
		}

		globalchainId = config.ChainID
		genesis       = gspec.MustCommit(db)
	)

	externalClient, err := ethclient.Dial("https://rinkeby.infura.io/v3/4e3e18f80d8d4ad5959b7404e85e0143")
	if err != nil {
		t.Error(err)
	}

	const RinkebyTxHash = "0x7ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e46"
	const RinkebyTxHashNotFound = "0x0000000000000000000000000000000000000000000000000000000000000001"

	Args_CallOnce := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 0, 300, 10)

	Args_ExpectErrAsLogIdxExceed := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 2, 300, 10)

	Args_ExpectErrAsNotFound := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHashNotFound), 2, 300, 10)

	Args_Twice_Trace0 := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 0, 300, 10)
	Args_Twice_Trace1 := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 1, 300, 10)
	Args_CallTwice := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 0, 300, 10)

	Args_ExpectErrChainIdNoSupport := NewCrossChainCallArgment(config, externalClient, 5, common.HexToHash(RinkebyTxHash), 0, 300, 10)

	_wrapTxs := []*WrapTx{
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("0x518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			Args:         Args_CallOnce,
			ExpectTxData: Args_CallOnce.CallOncePack,
			ExpectTraces: []*ExpectTrace{
				Args_CallOnce.CrossChainCallResultToExpectCallResult(),
			},
		},
		// expect err match:CrossChainCall:logIdx out-of-bound
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			Args:         Args_ExpectErrAsLogIdxExceed,
			ExpectTxData: Args_ExpectErrAsLogIdxExceed.CallOncePack,
			ExpectTraces: []*ExpectTrace{
				Args_ExpectErrAsLogIdxExceed.CrossChainCallResultToExpectCallResult(),
			},
		},
		// expect err txHash not found
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("518a3510000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			Args:         Args_ExpectErrAsNotFound,
			ExpectTxData: Args_ExpectErrAsNotFound.CallOncePack,
			ExpectTraces: []*ExpectTrace{
				Args_ExpectErrAsNotFound.CrossChainCallResultToExpectCallResult(),
			},
		},
		// expect err chainId no support
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("518a351000000000000000000000000000000000000000000000000000000000000000057ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			Args:         Args_ExpectErrChainIdNoSupport,
			ExpectTxData: Args_ExpectErrChainIdNoSupport.CallOncePack,
			ExpectTraces: []*ExpectTrace{
				Args_ExpectErrChainIdNoSupport.CrossChainCallResultToExpectCallResult(),
			},
		},
		// external call twice
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("0x2061536200000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			Args:         Args_CallTwice,
			ExpectTxData: Args_CallTwice.CallTwicePack,
			ExpectTraces: []*ExpectTrace{
				Args_Twice_Trace0.CrossChainCallResultToExpectCallResult(),
				Args_Twice_Trace1.CrossChainCallResultToExpectCallResult(),
			},
		},
		// call crossChainCall precompile contract directly
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &preAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("0x99e2007000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),
			//Args:         Args_CallTwice,
			//ExpectTxData: Args_CallTwice.CallTwicePack,
			ExpectTraces: []*ExpectTrace{
				Args_CallOnce.CrossChainCallResultToExpectCallResult(),
			},
		},
	}

	var wrapTxs []*WrapTx
	for i, wrapTx := range _wrapTxs {
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
				t.Fatalf("%d Tx data no match. wrapTx.ExpectTxData():%s ,", i, common.Bytes2Hex(txData))
			}
		}

		wrapTxs = append(wrapTxs, wrapTx)
	}

	// evm executes a transaction while the external calling client is active
	for _, wtx := range wrapTxs {
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(GasPool)
		gaspool.AddGas(8000000000)

		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: externalClient}

		_, statedb := MakePreState(db, gspec.Alloc, false)
		_, crossCallResult, err := ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), wtx.Tx, &wtx.GasUsed, vmconfig)

		wtx.VerifyCallResult(crossCallResult, err, t)
		wtx.SetTxWithExternalCallRes(crossCallResult)

		w.Flush()
		if err != nil {
			t.Log(err)
			if buf.Len() == 0 {
				t.Log("no EVM operation logs generated")
			} else {
				t.Log("EVM operation log:\n" + buf.String())
			}
		}

	}

	//evm executes a transaction while the external calling client is inactive
	for index, wtx := range wrapTxs {
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(GasPool)
		gaspool.AddGas(8000000000)

		var actualUsedGas uint64 = 0
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		// set the externalCallClient as nil
		vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: nil}

		_, statedb := MakePreState(db, gspec.Alloc, false)
		_, crossCallResult, err := ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), wtx.TxWithExternalCallRes, &actualUsedGas, vmconfig)
		wtx.VerifyCallResult(crossCallResult, err, t)

		// compare gas use
		if actualUsedGas != wtx.GasUsed {
			t.Errorf("The gas consumption is different when the client is nil and not nil, txIndex=[%d] , nil gas used (%d) , no nil gas used (%d) ", index, actualUsedGas, wtx.GasUsed)
		}

		w.Flush()
		if err != nil {
			t.Log(err)
			if buf.Len() == 0 {
				t.Log("no EVM operation logs generated")
			} else {
				t.Log("EVM operation log:\n" + buf.String())
			}
		}
	}
}

func BenchmarkApplyTransactionWithCallResult(b *testing.B) {
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
			ExternalCall: &params.ExternalCallConfig{
				Version:        1,
				SupportChainId: 4,
			},
		}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
	)

	var (
		db           = rawdb.NewMemoryDatabase()
		contractAddr = common.HexToAddress("0xa000000000000000000000000000000000000aaa")
		gspec        = &Genesis{
			Config: config,
			Alloc: GenesisAlloc{
				addr1: GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   0,
				},
				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
				},
				contractAddr: GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
					Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100415760003560e01c80632061536214610046578063518a3510146100775780638c95e054146100a7575b600080fd5b610060600480360381019061005b9190610510565b6100c5565b60405161006e9291906106df565b60405180910390f35b610091600480360381019061008c9190610510565b610382565b60405161009e91906106bd565b60405180910390f35b6100af6104df565b6040516100bc91906106a2565b60405180910390f35b606080600087878787876040516024016100e3959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff168360405161018d919061068b565b6000604051808303816000865af19150503d80600081146101ca576040519150601f19603f3d011682016040523d82523d6000602084013e6101cf565b606091505b509150915081610214576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020b90610756565b60405180910390fd5b60008a8a60018b6102259190610801565b8a8a60405160240161023b959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff16836040516102e5919061068b565b6000604051808303816000865af19150503d8060008114610322576040519150601f19603f3d011682016040523d82523d6000602084013e610327565b606091505b50915091508161036c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036390610736565b60405180910390fd5b8381975097505050505050509550959350505050565b60606000868686868660405160240161039f959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff1683604051610449919061068b565b6000604051808303816000865af19150503d8060008114610486576040519150601f19603f3d011682016040523d82523d6000602084013e61048b565b606091505b5091509150816104d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c790610716565b60405180910390fd5b80935050505095945050505050565b6203330381565b6000813590506104f5816109dc565b92915050565b60008135905061050a816109f3565b92915050565b600080600080600060a0868803121561052c5761052b6108ff565b5b600061053a888289016104fb565b955050602061054b888289016104e6565b945050604061055c888289016104fb565b935050606061056d888289016104fb565b925050608061057e888289016104fb565b9150509295509295909350565b61059481610857565b82525050565b6105a381610869565b82525050565b60006105b4826107c9565b6105be81856107d4565b93506105ce81856020860161089d565b6105d781610904565b840191505092915050565b60006105ed826107c9565b6105f781856107e5565b935061060781856020860161089d565b80840191505092915050565b60006106206018836107f0565b915061062b82610915565b602082019050919050565b60006106436025836107f0565b915061064e8261093e565b604082019050919050565b60006106666025836107f0565b91506106718261098d565b604082019050919050565b61068581610893565b82525050565b600061069782846105e2565b915081905092915050565b60006020820190506106b7600083018461058b565b92915050565b600060208201905081810360008301526106d781846105a9565b905092915050565b600060408201905081810360008301526106f981856105a9565b9050818103602083015261070d81846105a9565b90509392505050565b6000602082019050818103600083015261072f81610613565b9050919050565b6000602082019050818103600083015261074f81610636565b9050919050565b6000602082019050818103600083015261076f81610659565b9050919050565b600060a08201905061078b600083018861067c565b610798602083018761059a565b6107a5604083018661067c565b6107b2606083018561067c565b6107bf608083018461067c565b9695505050505050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061080c82610893565b915061081783610893565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561084c5761084b6108d0565b5b828201905092915050565b600061086282610873565b9050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156108bb5780820151818401526020810190506108a0565b838111156108ca576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6109e581610869565b81146109f057600080fd5b50565b6109fc81610893565b8114610a0757600080fd5b5056fea2646970667358221220cb96efc14e55caf807c664755d68fa44a3228605b33e42bc7be92933e03ba95364736f6c63430008070033"),
				},
			},
		}

		globalchainId = config.ChainID
		genesis       = gspec.MustCommit(db)
	)

	externalClient, err := ethclient.Dial("https://rinkeby.infura.io/v3/63aa34e959614d01a9a65d3f93b70e66")
	if err != nil {
		b.Error(err)
	}

	const RinkebyTxHash = "0x7ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e46"
	Args_CallOnce := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 0, 300, 10)

	gaspool := new(GasPool)
	gaspool.AddGas(30000000)
	cli := &clique.Clique{}
	wtm := NewWrapTendermint(cli, nil)
	chainContext := NewTestChainContext(wtm)

	// prepare block
	block := genesis

	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)
	tracer := logger.NewJSONLogger(&logger.Config{}, w)
	// set the externalCallClient as nil
	vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: externalClient}

	_, statedb := MakePreState(db, gspec.Alloc, false)
	for i := 0; i < b.N; i++ {
		wrapTx :=
			&WrapTx{
				Tx: types.NewTx(&types.DynamicFeeTx{
					ChainID:   globalchainId,
					Nonce:     uint64(i),
					To:        &contractAddr,
					Value:     big.NewInt(0),
					Gas:       5000000,
					GasTipCap: big.NewInt(1000000000),
					GasFeeCap: big.NewInt(6000000000),
					Data:      common.FromHex("0x518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
				}),
				Args:           Args_CallOnce,
				ExpectTxData:   Args_CallOnce.CallOncePack,
				ExpectCCRBytes: common.FromHex("f901ae01f901aaf901a7b901a0000000000000000000000000751320c36f413a6280ad54487766ae0f780b6f58000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000028bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000000000000000000000000000000000000018206cc"),
			}

		signer := types.LatestSignerForChainID(globalchainId)
		signTx, err := types.SignTx(wrapTx.Tx, signer, key1)
		if err != nil {
			b.Error(err)
		}

		wrapTx.Tx = signTx

		if wrapTx.ExpectTxData != nil {
			txData, err := wrapTx.ExpectTxData()
			if err != nil {
				b.Fatal(err)
			}
			if common.Bytes2Hex(txData) != common.Bytes2Hex(wrapTx.Tx.Data()) {
				b.Fatalf("%d Tx data no match. wrapTx.ExpectTxData():%s ,", i, common.Bytes2Hex(txData))
			}
		}

		var actualUsedGas uint64 = 0
		_, cs, err := ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), wrapTx.Tx, &actualUsedGas, vmconfig)
		b.Log("i:", i, "\nCS:", common.Bytes2Hex(cs), "\nGasUsed:", actualUsedGas)
		if err != nil {
			b.Fatal(err)
			break
		}
		if !bytes.Equal(cs, wrapTx.ExpectCCRBytes) {
			b.Fatal("cross_chain_result err")
		}
		if gaspool.Gas() < actualUsedGas {
			break
		}
		statedb.Commit(config.IsEIP158(block.Number()))

	}
}

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
func TestStateProcessorErrors(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      big.NewInt(0),
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			MuirGlacierBlock:    big.NewInt(0),
			BerlinBlock:         big.NewInt(0),
			LondonBlock:         big.NewInt(0),
			Ethash:              new(params.EthashConfig),
		}
		signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	)
	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data), signer, key)
		return tx
	}
	var mkDynamicTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     big.NewInt(0),
		}), signer, key1)
		return tx
	}
	{ // Tests against a 'recent' chain definition
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
					common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   math.MaxUint64,
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		bigNumber := new(big.Int).SetBytes(common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
		tooBigNumber := new(big.Int).Set(bigNumber)
		tooBigNumber.Add(tooBigNumber, common.Big1)
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrNonceTooLow
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 1 [0x0026256b3939ed97e2c4a6f3fce8ecf83bdcfa6d507c47838c308a1fb0436f62]: nonce too low: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 0 state: 1",
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xdebad714ca7f363bd0d8121c4518ad48fa469ca81b0a081be3d10c17460f751b]: nonce too high: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 100 state: 0",
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0x84ea18d60eb2bb3b040e3add0eb72f757727122cc257dd858c67cb6591a85986]: nonce has max value: address 0xfd0810DD14796680f72adf1a371963d0745BCc64, nonce: 18446744073709551615",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), 21000000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xbd49d8dadfd47fb846986695f7d4da3f7b2c48c8da82dbc211a26eb124883de9]: gas limit reached",
			},
			{ // ErrInsufficientFundsForTransfer
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(1000000000000000000), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0x98c796b470f7fcab40aaef5c965a602b0238e1034cce6fb73823042dd0638d74]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1000018375000000000",
			},
			{ // ErrInsufficientFunds
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(900000000000000000), nil),
				},
				want: "could not apply tx 0 [0x4a69690c4b0cd85e64d0d9ea06302455b01e10a83db964d60281739752003440]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 18900000000000000000000",
			},
			// ErrGasUintOverflow
			// One missing 'core' error is ErrGasUintOverflow: "gas uint64 overflow",
			// In order to trigger that one, we'd have to allocate a _huge_ chunk of data, such that the
			// multiplication len(data) +gas_per_byte overflows uint64. Not testable at the moment
			{ // ErrIntrinsicGas
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas-1000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xcf3b049a0b516cb4f9274b3e2a264359e2ba53b2fb64b7bda2c634d5c9d01fca]: intrinsic gas too low: have 20000, want 21000",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas*1000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xbd49d8dadfd47fb846986695f7d4da3f7b2c48c8da82dbc211a26eb124883de9]: gas limit reached",
			},
			{ // ErrFeeCapTooLow
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0xc4ab868fef0c82ae0387b742aee87907f2d0fc528fc6ea0a021459fb0fc4a4a8]: max fee per gas less than block base fee: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas: 0 baseFee: 875000000",
			},
			{ // ErrTipVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, tooBigNumber, big.NewInt(1)),
				},
				want: "could not apply tx 0 [0x15b8391b9981f266b32f3ab7da564bbeb3d6c21628364ea9b32a21139f89f712]: max priority fee per gas higher than 2^256-1: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas bit length: 257",
			},
			{ // ErrFeeCapVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), tooBigNumber),
				},
				want: "could not apply tx 0 [0x48bc299b83fdb345c57478f239e89814bb3063eb4e4b49f3b6057a69255c16bd]: max fee per gas higher than 2^256-1: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas bit length: 257",
			},
			{ // ErrTipAboveFeeCap
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(2), big.NewInt(1)),
				},
				want: "could not apply tx 0 [0xf987a31ff0c71895780a7612f965a0c8b056deb54e020bb44fa478092f14c9b4]: max priority fee per gas higher than max fee per gas: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas: 2, maxFeePerGas: 1",
			},
			{ // ErrInsufficientFunds
				// Available balance:           1000000000000000000
				// Effective cost:                   18375000021000
				// FeeCap * gas:                1050000000000000000
				// This test is designed to have the effective cost be covered by the balance, but
				// the extended requirement on FeeCap*gas < balance to fail
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), big.NewInt(50000000000000)),
				},
				want: "could not apply tx 0 [0x413603cd096a87f41b1660d3ed3e27d62e1da78eac138961c0a1314ed43bd129]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1050000000000000000",
			},
			{ // Another ErrInsufficientFunds, this one to ensure that feecap/tip of max u256 is allowed
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, bigNumber, bigNumber),
				},
				want: "could not apply tx 0 [0xd82a0c2519acfeac9a948258c47e784acd20651d9d80f9a1c67b4137651c3a24]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 2431633873983640103894990685182446064918669677978451844828609264166175722438635000",
			},
		} {
			block := GenerateBadBlock(genesis, ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrTxTypeNotSupported, For this, we need an older chain
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: &params.ChainConfig{
					ChainID:             big.NewInt(1),
					HomesteadBlock:      big.NewInt(0),
					EIP150Block:         big.NewInt(0),
					EIP155Block:         big.NewInt(0),
					EIP158Block:         big.NewInt(0),
					ByzantiumBlock:      big.NewInt(0),
					ConstantinopleBlock: big.NewInt(0),
					PetersburgBlock:     big.NewInt(0),
					IstanbulBlock:       big.NewInt(0),
					MuirGlacierBlock:    big.NewInt(0),
				},
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrTxTypeNotSupported
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0x88626ac0d53cb65308f2416103c62bb1f18b805573d4f96a3640bbbfff13c14f]: transaction type not supported",
			},
		} {
			block := GenerateBadBlock(genesis, ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrSenderNoEOA, for this we need the sender to have contract code
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
						Code:    common.FromHex("0xB0B0FACE"),
					},
				},
			}
			genesis       = gspec.MustCommit(db)
			blockchain, _ = NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrSenderNoEOA
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0x88626ac0d53cb65308f2416103c62bb1f18b805573d4f96a3640bbbfff13c14f]: sender not an eoa: address 0x71562b71999873DB5b286dF957af199Ec94617F7, codehash: 0x9280914443471259d4570a8661015ae4a5b80186dbc619658fb494bebc3da3d1",
			},
		} {
			block := GenerateBadBlock(genesis, ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(parent *types.Block, engine consensus.Engine, txs types.Transactions, config *params.ChainConfig) *types.Block {
	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(&fakeChainReader{config}, parent.Time()+10, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		}),
		GasLimit:  parent.GasLimit(),
		Number:    new(big.Int).Add(parent.Number(), common.Big1),
		Time:      parent.Time() + 10,
		UncleHash: types.EmptyUncleHash,
	}
	if config.IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(config, parent.Header())
	}
	var receipts []*types.Receipt
	// The post-state result doesn't need to be correct (this is a bad block), but we do need something there
	// Preferably something unique. So let's use a combo of blocknum + txhash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(header.Number.Bytes())
	var cumulativeGas uint64
	for _, tx := range txs {
		txh := tx.Hash()
		hasher.Write(txh[:])
		receipt := types.NewReceipt(nil, false, cumulativeGas+tx.Gas())
		receipt.TxHash = tx.Hash()
		receipt.GasUsed = tx.Gas()
		receipts = append(receipts, receipt)
		cumulativeGas += tx.Gas()
	}
	header.Root = common.BytesToHash(hasher.Sum(nil))
	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
}

func MakePreState(db ethdb.Database, accounts GenesisAlloc, snapshotter bool) (*snapshot.Tree, *state.StateDB) {
	sdb := state.NewDatabase(db)
	statedb, _ := state.New(common.Hash{}, sdb, nil)
	for addr, a := range accounts {
		statedb.SetCode(addr, a.Code)
		statedb.SetNonce(addr, a.Nonce)
		statedb.SetBalance(addr, a.Balance)
		for k, v := range a.Storage {
			statedb.SetState(addr, k, v)
		}
	}
	// Commit and re-open to start with a clean state.
	root, _ := statedb.Commit(false)

	var snaps *snapshot.Tree
	if snapshotter {
		snaps, _ = snapshot.New(db, sdb.TrieDB(), 1, root, false, true, false)
	}
	statedb, _ = state.New(root, sdb, snaps)
	return snaps, statedb
}
