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
	for i, tt := range withdrawStakingTests {

		// contract Contract {
		// 	function withdraw(uint256 amount) external payable {
		// 			payable(msg.sender).transfer(amount);
		// 	}
		// }
		code := hexutil.MustDecode("0x608060405260043610601c5760003560e01c80632e1a7d4d146021575b600080fd5b603760048036038101906033919060b8565b6039565b005b3373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015607e573d6000803e3d6000fd5b5050565b600080fd5b6000819050919050565b6098816087565b811460a257600080fd5b50565b60008135905060b2816091565b92915050565b60006020828403121560cb5760ca6082565b5b600060d78482850160a5565b9150509291505056fea26469706673582212207df8a71f97150069218babb49bbc23dd8cee55156d4c6b0a7160287ff81d946d64736f6c634300080c0033")
		code = codegenWithSize(code, tt.codeSize)
		initBal := big.NewInt(tt.staked)
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.CreateAccount(addr)
		statedb.SetCode(addr, code)
		statedb.SetBalance(addr, initBal)

		vmctx := BlockContext{
			BlockNumber: big.NewInt(0),
			CanTransfer: func(_ StateDB, sender common.Address, toAmount *big.Int) bool {
				if sender == addr {
					// balance should be greater than transfer amount
					return initBal.Cmp(toAmount) >= 0
				}
				return true
			},
			Transfer: func(_ StateDB, sender, _ common.Address, toAmount *big.Int) {
				// simulate withdrawal success
				if sender == addr {
					initBal = initBal.Sub(initBal, toAmount)
				}
			},
		}
		vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})
		// func selector + uint256 amount
		funcCall := fmt.Sprintf("0x2e1a7d4d%064x", tt.toWithdraw)
		// withdraw
		_, _, err := vmenv.Call(AccountRef(common.Address{}), addr, hexutil.MustDecode(funcCall), math.MaxUint64, new(big.Int))
		if err != tt.failure {
			t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
		}
	}
}
