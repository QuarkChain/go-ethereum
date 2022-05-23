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
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
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

func (t *WrapTendermint) ExternalCallClient() *ethclient.Client {
	return t.Client
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
			ExternalCall:        &params.ExternalCallConfig{Version: "1.0.0"},
		}
		//signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		//key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	)

	var (
		db           = rawdb.NewMemoryDatabase()
		preAddr      = common.HexToAddress("0x0000000000000000000000000000000000000014")
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
					Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100415760003560e01c80632061536214610046578063518a3510146100775780638c95e054146100a7575b600080fd5b610060600480360381019061005b9190610508565b6100c5565b60405161006e9291906106d7565b60405180910390f35b610091600480360381019061008c9190610508565b61037e565b60405161009e91906106b5565b60405180910390f35b6100af6104d9565b6040516100bc919061069a565b60405180910390f35b606080600087878787876040516024016100e395949392919061076e565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050509050600080601473ffffffffffffffffffffffffffffffffffffffff168360405161018b9190610683565b6000604051808303816000865af19150503d80600081146101c8576040519150601f19603f3d011682016040523d82523d6000602084013e6101cd565b606091505b509150915081610212576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102099061074e565b60405180910390fd5b60008a8a60018b61022391906107f9565b8a8a60405160240161023995949392919061076e565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050509050600080601473ffffffffffffffffffffffffffffffffffffffff16836040516102e19190610683565b6000604051808303816000865af19150503d806000811461031e576040519150601f19603f3d011682016040523d82523d6000602084013e610323565b606091505b509150915081610368576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161035f9061072e565b60405180910390fd5b8381975097505050505050509550959350505050565b60606000868686868660405160240161039b95949392919061076e565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050509050600080601473ffffffffffffffffffffffffffffffffffffffff16836040516104439190610683565b6000604051808303816000865af19150503d8060008114610480576040519150601f19603f3d011682016040523d82523d6000602084013e610485565b606091505b5091509150816104ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c19061070e565b60405180910390fd5b80935050505095945050505050565b601481565b6000813590506104ed816109d4565b92915050565b600081359050610502816109eb565b92915050565b600080600080600060a08688031215610524576105236108f7565b5b6000610532888289016104f3565b9550506020610543888289016104de565b9450506040610554888289016104f3565b9350506060610565888289016104f3565b9250506080610576888289016104f3565b9150509295509295909350565b61058c8161084f565b82525050565b61059b81610861565b82525050565b60006105ac826107c1565b6105b681856107cc565b93506105c6818560208601610895565b6105cf816108fc565b840191505092915050565b60006105e5826107c1565b6105ef81856107dd565b93506105ff818560208601610895565b80840191505092915050565b60006106186018836107e8565b91506106238261090d565b602082019050919050565b600061063b6025836107e8565b915061064682610936565b604082019050919050565b600061065e6025836107e8565b915061066982610985565b604082019050919050565b61067d8161088b565b82525050565b600061068f82846105da565b915081905092915050565b60006020820190506106af6000830184610583565b92915050565b600060208201905081810360008301526106cf81846105a1565b905092915050565b600060408201905081810360008301526106f181856105a1565b9050818103602083015261070581846105a1565b90509392505050565b600060208201905081810360008301526107278161060b565b9050919050565b600060208201905081810360008301526107478161062e565b9050919050565b6000602082019050818103600083015261076781610651565b9050919050565b600060a0820190506107836000830188610674565b6107906020830187610592565b61079d6040830186610674565b6107aa6060830185610674565b6107b76080830184610674565b9695505050505050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b60006108048261088b565b915061080f8361088b565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610844576108436108c8565b5b828201905092915050565b600061085a8261086b565b9050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156108b3578082015181840152602081019050610898565b838111156108c2576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6109dd81610861565b81146109e857600080fd5b50565b6109f48161088b565b81146109ff57600080fd5b5056fea2646970667358221220d59400f6d3d8ac194c9395a74a3ea0cbd9785111f5472ed5669a2147511852c664736f6c63430008070033"),
				},
			},
		}

		globalchainId = config.ChainID

		externalCallTxs = []*types.Transaction{
			types.NewTx(&types.LegacyTx{
				Nonce:    0,
				To:       &contractAddr,
				Value:    big.NewInt(0),
				Gas:      5000000,
				GasPrice: big.NewInt(6000000000),
				Data:     common.FromHex("0x518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
			}),

			types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("0x518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
				//ExternalCallResult: common.FromHex("1122334455667788998877665544332211"),
			}),

			types.NewTx(&types.DynamicFeeTx{
				Nonce:     0,
				To:        &preAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      common.FromHex("0x99e20070000000000000000000000000000000000000000000000000000000000000000419c0c9b16f4e5cf388581ce71aea86641fdd877ce11af2c60d8db523cd2e02e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000a"),
				//ExternalCallResult: common.FromHex("1122334455667788998877665544332211"),
			}),
		}

		expectResults = []string{
			"f9012d85312e302e30f90124f90121f9011b94751320c36f413a6280ad54487766ae0f780b6f58f842a0dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9a00000000000000000000000000000000000000000000000000000000000000001b8c00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000028bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000082054c",
			"f9012d85312e302e30f90124f90121f9011b94751320c36f413a6280ad54487766ae0f780b6f58f842a0dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9a00000000000000000000000000000000000000000000000000000000000000001b8c00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000028bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000082054c",
			"f9010c85312e302e30f90103f90100f8fb94a1230a772e3501b09fc6dcae819889bf30d1415ef842a0dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9a00000000000000000000000000000000000000000000000000000000000000002b8a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000002aaaa0000000000000000000000000000000000000000000000000000000000008204ec",
		}

		genesis = gspec.MustCommit(db)
	)

	// prepare tx
	var signTxs []*types.Transaction
	for _, extx := range externalCallTxs {
		signer := types.LatestSignerForChainID(globalchainId)
		signTx, err := types.SignTx(extx, signer, key1)
		if err != nil {
			t.Error(err)
		}
		signTxs = append(signTxs, signTx)
	}

	for i, tx := range signTxs {
		// prepare chainContext
		externalClient, err := ethclient.Dial("https://rinkeby.infura.io/v3/4e3e18f80d8d4ad5959b7404e85e0143")
		if err != nil {
			t.Error(err)
		}
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, externalClient)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(GasPool)
		gaspool.AddGas(8000000000)

		var usedGas uint64 = 0
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		vmconfig := vm.Config{Debug: true, Tracer: tracer}

		_, statedb := MakePreState(db, gspec.Alloc, false)
		_, err = ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), tx, &usedGas, vmconfig)
		w.Flush()
		if err != nil {
			t.Log(err)
			if buf.Len() == 0 {
				t.Log("no EVM operation logs generated")
			} else {
				t.Log("EVM operation log:\n" + buf.String())
			}
		}

		if common.Bytes2Hex(tx.ExternalCallResult()) != expectResults[i] {
			t.Errorf("%d Tx ExternalCallResult no match", i)
		}

		resDecode := &vm.CrossChainCallResult{}
		err = rlp.DecodeBytes(tx.ExternalCallResult(), resDecode)
		if err != nil {
			t.Error(err)
		}
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
