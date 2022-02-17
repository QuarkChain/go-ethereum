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
	"math"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/params"
)

func TestMemoryGasCost(t *testing.T) {
	tests := []struct {
		size     uint64
		cost     uint64
		overflow bool
	}{
		{0x1fffffffe0, 36028809887088637, false},
		{0x1fffffffe1, 0, true},
	}
	for i, tt := range tests {
		v, err := memoryGasCost(&Memory{}, tt.size)
		if (err == ErrGasUintOverflow) != tt.overflow {
			t.Errorf("test %d: overflow mismatch: have %v, want %v", i, err == ErrGasUintOverflow, tt.overflow)
		}
		if v != tt.cost {
			t.Errorf("test %d: gas cost mismatch: have %v, want %v", i, v, tt.cost)
		}
	}
}

var eip2200Tests = []struct {
	original byte
	gaspool  uint64
	input    string
	used     uint64
	refund   uint64
	failure  error
}{
	{0, math.MaxUint64, "0x60006000556000600055", 1612, 0, nil},                // 0 -> 0 -> 0
	{0, math.MaxUint64, "0x60006000556001600055", 20812, 0, nil},               // 0 -> 0 -> 1
	{0, math.MaxUint64, "0x60016000556000600055", 20812, 19200, nil},           // 0 -> 1 -> 0
	{0, math.MaxUint64, "0x60016000556002600055", 20812, 0, nil},               // 0 -> 1 -> 2
	{0, math.MaxUint64, "0x60016000556001600055", 20812, 0, nil},               // 0 -> 1 -> 1
	{1, math.MaxUint64, "0x60006000556000600055", 5812, 15000, nil},            // 1 -> 0 -> 0
	{1, math.MaxUint64, "0x60006000556001600055", 5812, 4200, nil},             // 1 -> 0 -> 1
	{1, math.MaxUint64, "0x60006000556002600055", 5812, 0, nil},                // 1 -> 0 -> 2
	{1, math.MaxUint64, "0x60026000556000600055", 5812, 15000, nil},            // 1 -> 2 -> 0
	{1, math.MaxUint64, "0x60026000556003600055", 5812, 0, nil},                // 1 -> 2 -> 3
	{1, math.MaxUint64, "0x60026000556001600055", 5812, 4200, nil},             // 1 -> 2 -> 1
	{1, math.MaxUint64, "0x60026000556002600055", 5812, 0, nil},                // 1 -> 2 -> 2
	{1, math.MaxUint64, "0x60016000556000600055", 5812, 15000, nil},            // 1 -> 1 -> 0
	{1, math.MaxUint64, "0x60016000556002600055", 5812, 0, nil},                // 1 -> 1 -> 2
	{1, math.MaxUint64, "0x60016000556001600055", 1612, 0, nil},                // 1 -> 1 -> 1
	{0, math.MaxUint64, "0x600160005560006000556001600055", 40818, 19200, nil}, // 0 -> 1 -> 0 -> 1
	{1, math.MaxUint64, "0x600060005560016000556000600055", 10818, 19200, nil}, // 1 -> 0 -> 1 -> 0
	{1, 2306, "0x6001600055", 2306, 0, ErrOutOfGas},                            // 1 -> 1 (2300 sentry + 2xPUSH)
	{1, 2307, "0x6001600055", 806, 0, nil},                                     // 1 -> 1 (2301 sentry + 2xPUSH)
}

func TestEIP2200(t *testing.T) {
	for i, tt := range eip2200Tests {
		address := common.BytesToAddress([]byte("contract"))

		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.CreateAccount(address)
		statedb.SetCode(address, hexutil.MustDecode(tt.input))
		statedb.SetState(address, common.Hash{}, common.BytesToHash([]byte{tt.original}))
		statedb.Finalise(true) // Push the state into the "original" slot

		vmctx := BlockContext{
			CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
			Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
		}
		vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{ExtraEips: []int{2200}})

		_, gas, err := vmenv.Call(AccountRef(common.Address{}), address, nil, tt.gaspool, new(big.Int))
		if err != tt.failure {
			t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
		}
		if used := tt.gaspool - gas; used != tt.used {
			t.Errorf("test %d: gas used mismatch: have %v, want %v", i, used, tt.used)
		}
		if refund := vmenv.StateDB.GetRefund(); refund != tt.refund {
			t.Errorf("test %d: gas refund mismatch: have %v, want %v", i, refund, tt.refund)
		}
	}
}

var extraGasCodeTests = []struct {
	codeSize uint
	gaspool  uint64
	used     uint64
	call     byte
	failure  error
}{
	// CALL
	{params.MaxCodeSizeSoft, math.MaxUint64, 2627, byte(CALL), nil},
	{params.MaxCodeSizeSoft + 1, math.MaxUint64, 2627 + params.CallGasEIP150, byte(CALL), nil},
	{params.MaxCodeSizeSoft * 2, math.MaxUint64, 2627 + params.CallGasEIP150, byte(CALL), nil},
	{params.MaxCodeSizeSoft*2 + 1, math.MaxUint64, 2627 + params.CallGasEIP150*2, byte(CALL), nil},
	// CALLCODE
	{params.MaxCodeSizeSoft, math.MaxUint64, 2627, byte(CALLCODE), nil},
	{params.MaxCodeSizeSoft + 1, math.MaxUint64, 2627 + params.CallGasEIP150, byte(CALLCODE), nil},
	{params.MaxCodeSizeSoft * 2, math.MaxUint64, 2627 + params.CallGasEIP150, byte(CALLCODE), nil},
	{params.MaxCodeSizeSoft*2 + 1, math.MaxUint64, 2627 + params.CallGasEIP150*2, byte(CALLCODE), nil},
	// DELEGATECALL
	{params.MaxCodeSizeSoft, math.MaxUint64, 2627, byte(DELEGATECALL), nil},
	{params.MaxCodeSizeSoft + 1, math.MaxUint64, 2627 + params.CallGasEIP150, byte(DELEGATECALL), nil},
	{params.MaxCodeSizeSoft * 2, math.MaxUint64, 2627 + params.CallGasEIP150, byte(DELEGATECALL), nil},
	{params.MaxCodeSizeSoft*2 + 1, math.MaxUint64, 2627 + params.CallGasEIP150*2, byte(DELEGATECALL), nil},
	// STATICCALL
	{params.MaxCodeSizeSoft, math.MaxUint64, 2627, byte(STATICCALL), nil},
	{params.MaxCodeSizeSoft + 1, math.MaxUint64, 2627 + params.CallGasEIP150, byte(STATICCALL), nil},
	{params.MaxCodeSizeSoft * 2, math.MaxUint64, 2627 + params.CallGasEIP150, byte(STATICCALL), nil},
	{params.MaxCodeSizeSoft*2 + 1, math.MaxUint64, 2627 + params.CallGasEIP150*2, byte(STATICCALL), nil},
}

func codegenWithSize(sz uint) []byte {
	// PUSH1 00, PUSH1 00, RETURN
	pushAndReturn := hexutil.MustDecode("0x60006000f3")
	ret := make([]byte, sz-5) // first 5 bytes are for early return
	for i := range ret {
		ret[i] = 42 // meaning of life, bloating the code size
	}
	return append(pushAndReturn, ret...)
}

func TestExtraGasForCallW3IP002(t *testing.T) {
	caller := common.BytesToAddress([]byte("caller"))
	calleeAddr := "0x0101010101010101010101010101010101010101"
	callee := common.HexToAddress(calleeAddr)
	for i, tt := range extraGasCodeTests {
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.CreateAccount(caller)
		// set up stack for CALL family
		callerCode := []byte{
			byte(PUSH1), 0, // output size
			byte(PUSH1), 0, // output mem
			byte(PUSH1), 0, // input size
			byte(PUSH1), 0, // input mem
			byte(PUSH1), 0, // no value
		}
		pushAddr := append([]byte{byte(PUSH20)}, hexutil.MustDecode(calleeAddr)...)
		callerCode = append(callerCode, pushAddr...) // callee addr
		pushGas := append([]byte{byte(PUSH32)}, common.LeftPadBytes(uint256.NewInt(math.MaxUint64).Bytes(), 32)...)
		callerCode = append(callerCode, pushGas...) // gas arg
		callerCode = append(callerCode, tt.call)

		statedb.SetCode(caller, callerCode)
		statedb.SetCode(callee, codegenWithSize(tt.codeSize))

		vmctx := BlockContext{
			BlockNumber: big.NewInt(0),
			CanTransfer: func(StateDB, common.Address, *big.Int) bool { return true },
			Transfer:    func(StateDB, common.Address, common.Address, *big.Int) {},
		}
		vmenv := NewEVM(vmctx, TxContext{}, statedb, params.AllEthashProtocolChanges, Config{})

		_, gas, err := vmenv.Call(AccountRef(common.Address{}), caller, nil, tt.gaspool, new(big.Int))
		if err != tt.failure {
			t.Errorf("test %d: failure mismatch: have %v, want %v", i, err, tt.failure)
		}
		if used := tt.gaspool - gas; used != tt.used {
			t.Errorf("test %d: gas used mismatch: have %v, want %v", i, used, tt.used)
		}
	}
}
