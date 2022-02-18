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
			statedb.SetCode(caddr, codegenWithSize(tt.codeSize))

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
