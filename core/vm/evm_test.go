// Copyright 2017 The go-ethereum Authors
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

package vm

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/params"
)

var contractCheckStakingTests = []struct {
	codeSize uint
	staked   int64
	failure  error
}{
	{params.MaxCodeSizeSoft, 0, nil},                                                              // no need to stake
	{params.MaxCodeSizeSoft + 1, 0, ErrCodeInsufficientStake},                                     //reading code size > threshold, need to stake
	{params.MaxCodeSizeSoft + 1, int64(params.CodeStakingPerChunk - 1), ErrCodeInsufficientStake}, // not enough staking
	{params.MaxCodeSizeSoft + 1, int64(params.CodeStakingPerChunk), nil},                          // barely enough staking
	{params.MaxCodeSizeSoft * 2, int64(params.CodeStakingPerChunk), nil},
	{params.MaxCodeSizeSoft*2 + 1, int64(params.CodeStakingPerChunk*2 - 1), ErrCodeInsufficientStake},
	{params.MaxCodeSizeSoft*2 + 1, int64(params.CodeStakingPerChunk * 2), nil},
}

func TestContractCheckStakingW3IP002(t *testing.T) {
	caddr := common.BytesToAddress([]byte("contract"))
	calls := []string{"call", "callCode", "delegateCall"}
	for _, callMethod := range calls {
		for i, tt := range contractCheckStakingTests {
			statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
			statedb.CreateAccount(caddr)
			statedb.SetCode(caddr, codegenWithSize(nil, tt.codeSize))

			vmctx := BlockContext{
				BlockNumber: big.NewInt(0),
				CanTransfer: func(_ StateDB, _ common.Address, toAmount *big.Int) bool {
					return big.NewInt(tt.staked).Cmp(toAmount) >= 0
				},
				Transfer: func(StateDB, common.Address, common.Address, *big.Int) {},
			}
			vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})

			caller := AccountRef(caddr)
			var err error
			if callMethod == "call" {
				_, _, err = vmenv.Call(AccountRef(common.Address{}), caddr, nil, math.MaxUint64, new(big.Int))
			} else if callMethod == "callCode" {
				_, _, err = vmenv.CallCode(caller, caddr, nil, math.MaxUint64, new(big.Int))
			} else if callMethod == "delegateCall" {
				_, _, err = vmenv.DelegateCall(NewContract(caller, caller, big.NewInt(0), 0), caddr, nil, math.MaxUint64)
			} else {
				panic("invalid call method")
			}

			if err != tt.failure {
				t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
			}
		}
	}
}

var createTests = []struct {
	pushByte    byte
	codeSizeHex string
	staked      int64
	usedGas     uint64
	failure     error
}{
	{byte(PUSH1), "0xff", 0, 51030, nil},                                     // no need to stake
	{byte(PUSH2), "0x6000", 0, 4918662, nil},                                 // no need to stake
	{byte(PUSH2), "0x6001", 0, math.MaxUint64, ErrCodeInsufficientStake},     // code size > soft limit, have to stake
	{byte(PUSH2), "0x6001", int64(params.CodeStakingPerChunk), 4918668, nil}, // staked
	{byte(PUSH2), "0xc000", int64(params.CodeStakingPerChunk), 4924422, nil}, // size = soft limit * 2, creation gas capped
	{byte(PUSH2), "0xc001", int64(params.CodeStakingPerChunk), math.MaxUint64, ErrCodeInsufficientStake},
	{byte(PUSH2), "0xc001", int64(params.CodeStakingPerChunk*2 - 1), math.MaxUint64, ErrCodeInsufficientStake},
	{byte(PUSH2), "0xc001", int64(params.CodeStakingPerChunk * 2), 4924431, nil},
}

func TestCreateW3IP002(t *testing.T) {
	addr := common.BytesToAddress([]byte("caller"))
	for i, tt := range createTests {
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)

		// PUSHx <size>, PUSH1 00, RETURN
		// to manipulate how much data should be stored as code
		code := []byte{tt.pushByte}
		code = append(code, hexutil.MustDecode(tt.codeSizeHex)...)
		code = append(code, hexutil.MustDecode("0x6000f3")...) // PUSH1 00, RETURN

		vmctx := BlockContext{
			BlockNumber: big.NewInt(0),
			CanTransfer: func(_ StateDB, _ common.Address, toAmount *big.Int) bool {
				return big.NewInt(tt.staked).Cmp(toAmount) >= 0
			},
			Transfer: func(StateDB, common.Address, common.Address, *big.Int) {},
		}
		vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})

		_, _, leftOverGas, err := vmenv.Create(
			AccountRef(addr),
			code,
			math.MaxUint64,
			big.NewInt(0),
		)
		if err != tt.failure {
			t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
		}
		if used := math.MaxUint64 - leftOverGas; used != tt.usedGas {
			t.Errorf("test %d: gas used mismatch: have %v, want %v", i, used, tt.usedGas)
		}
	}
}

func canTransfer(db StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

func transfer(db StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}

var withdrawStakingTests = []struct {
	codeSize   uint
	staked     int64
	toWithdraw int64
	failure    error
}{
	{params.MaxCodeSizeSoft, 123, 123, nil},                        // can withdraw all
	{params.MaxCodeSizeSoft, 123, 124, ErrExecutionReverted},       // withdraw more than balance
	{params.MaxCodeSizeSoft + 1, 123, 0, ErrCodeInsufficientStake}, // can't withdraw because staking is required
	{params.MaxCodeSizeSoft + 1, 123, 1, ErrCodeInsufficientStake}, // can't withdraw because staking is required
	{params.MaxCodeSizeSoft + 1, int64(params.CodeStakingPerChunk), 1, ErrCodeInsufficientStake},
	{params.MaxCodeSizeSoft + 1, int64(params.CodeStakingPerChunk) + 5, 5, nil}, // can withdraw extra
}

func TestWithdrawStakingW3IP002(t *testing.T) {
	addr := common.BytesToAddress([]byte("addr"))
	calls := []string{"call", "callCode", "delegateCall"}
	// compiler: 0.8.7, no optimization
	// contract Contract {
	//   function withdraw(uint256 amount, address payable to) external payable {
	//     to.transfer(amount);
	//   }
	// }
	initCode := hexutil.MustDecode("0x60806040526004361061001d5760003560e01c8062f714ce14610022575b600080fd5b61003c60048036038101906100379190610122565b61003e565b005b8073ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f19350505050158015610084573d6000803e3d6000fd5b505050565b600080fd5b6000819050919050565b6100a18161008e565b81146100ac57600080fd5b50565b6000813590506100be81610098565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006100ef826100c4565b9050919050565b6100ff816100e4565b811461010a57600080fd5b50565b60008135905061011c816100f6565b92915050565b6000806040838503121561013957610138610089565b5b6000610147858286016100af565b92505060206101588582860161010d565b915050925092905056fea264697066735822122087ac4dd4a397d6abb35fd02d3945c392429ab58f1bcf76e724e6e8534373e84d64736f6c634300080c0033")
	for _, callMethod := range calls {
		for i, tt := range withdrawStakingTests {
			code := codegenWithSize(initCode, tt.codeSize)
			statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
			statedb.CreateAccount(addr)
			statedb.SetCode(addr, code)
			statedb.SetBalance(addr, big.NewInt(tt.staked))

			vmctx := BlockContext{BlockNumber: big.NewInt(0), CanTransfer: canTransfer, Transfer: transfer}
			vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})
			// func selector + uint256 amount + to address 0xffff
			funcCall := hexutil.MustDecode(fmt.Sprintf("0x00f714ce%064x%064x", tt.toWithdraw, 0xffff))

			var err error
			// withdraw
			if callMethod == "call" {
				_, _, err = vmenv.Call(AccountRef(common.Address{}), addr, funcCall, math.MaxUint64, new(big.Int))
			} else if callMethod == "callCode" { // can't withdraw stakes under `addr`
				_, _, err = vmenv.CallCode(AccountRef(addr), addr, funcCall, math.MaxUint64, new(big.Int))
			} else if callMethod == "delegateCall" { // can't withdraw stakes under `addr`
				caller := NewContract(AccountRef(addr), AccountRef(addr), big.NewInt(0), 0)
				_, _, err = vmenv.DelegateCall(caller, addr, funcCall, math.MaxUint64)
			} else {
				panic("unrecognized call method")
			}
			if err != tt.failure {
				t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
			}
		}
	}
}

var selfDestructTests = []struct {
	codeSize uint
	staked   int64
	failure  error
}{
	{params.MaxCodeSizeSoft, 123, nil},                                   // happy path
	{params.MaxCodeSizeSoft + 1, 123, nil},                               // can transfer staked funds out
	{params.MaxCodeSizeSoft + 1, int64(params.CodeStakingPerChunk), nil}, // can transfer staked funds out
}

func TestSelfDestructW3IP002(t *testing.T) {
	addr := common.BytesToAddress([]byte("addr"))
	calls := []string{"call", "callCode", "delegateCall"}
	// compiler: 0.8.7, no optimization
	// contract Contract {
	// 	function die(address payable to) external {
	// 			selfdestruct(to);
	// 	}
	// }
	initCode := hexutil.MustDecode("0x6080604052348015600f57600080fd5b506004361060285760003560e01c8063c9353cb514602d575b600080fd5b60436004803603810190603f919060ba565b6045565b005b8073ffffffffffffffffffffffffffffffffffffffff16ff5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000608c826063565b9050919050565b609a816083565b811460a457600080fd5b50565b60008135905060b4816093565b92915050565b60006020828403121560cd5760cc605e565b5b600060d98482850160a7565b9150509291505056fea2646970667358221220880ff39475cde4d997f052a7d0fb15be29d0a473fb55594f46e1a63c847f87f964736f6c634300080c0033")
	for _, callMethod := range calls {
		for i, tt := range selfDestructTests {
			code := codegenWithSize(initCode, tt.codeSize)
			statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
			statedb.CreateAccount(addr)
			statedb.SetCode(addr, code)
			statedb.SetBalance(addr, big.NewInt(tt.staked))

			vmctx := BlockContext{BlockNumber: big.NewInt(0), CanTransfer: canTransfer, Transfer: transfer}
			vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})
			// func selector + to address 0xffff
			funcCall := hexutil.MustDecode(fmt.Sprintf("0xc9353cb5%064x", 0xffff))

			var err error
			// self destruct
			if callMethod == "call" {
				_, _, err = vmenv.Call(AccountRef(common.Address{}), addr, funcCall, math.MaxUint64, new(big.Int))
			} else if callMethod == "callCode" {
				_, _, err = vmenv.CallCode(AccountRef(addr), addr, funcCall, math.MaxUint64, new(big.Int))
			} else if callMethod == "delegateCall" {
				caller := NewContract(AccountRef(addr), AccountRef(addr), big.NewInt(0), 0)
				_, _, err = vmenv.DelegateCall(caller, addr, funcCall, math.MaxUint64)
			} else {
				panic("unrecognized call method")
			}
			if err != tt.failure {
				t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
			}
			if err == nil { // post check for selfdestruct
				if bal := statedb.GetBalance(common.HexToAddress(fmt.Sprintf("0x%064x", 0xffff))); bal.Cmp(big.NewInt(tt.staked)) != 0 {
					t.Errorf("test %d: destructed balance mismatch: have %v, want %v", i, bal.Int64(), tt.staked)
				}
				if bal := statedb.GetBalance(addr); bal.Cmp(big.NewInt(0)) != 0 {
					t.Errorf("test %d: contract balance mismatch: have %v, want %v", i, bal.Int64(), 0)
				}
			}
		}
	}
}
