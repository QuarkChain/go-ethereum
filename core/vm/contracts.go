// Copyright 2014 The go-ethereum Authors
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
	"bytes"
	"context"
	"github.com/ethereum/go-ethereum/log"

	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"

	//lint:ignore SA1019 Needed for precompile
	"golang.org/x/crypto/ripemd160"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}

type PrecompiledContractCallEnv struct {
	evm    *EVM
	caller ContractRef
}

func NewPrecompiledContractCallEnv(evm *EVM, caller ContractRef) *PrecompiledContractCallEnv {
	return &PrecompiledContractCallEnv{evm: evm, caller: caller}
}

type PrecompiledContractWithEVM interface {
	RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error)
}

type PrecompiledContractToExternalCall interface {
	RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, uint64, error)
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddByzantium{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulByzantium{},
	common.BytesToAddress([]byte{8}): &bn256PairingByzantium{},
}

// PrecompiledContractsIstanbul contains the default set of pre-compiled Ethereum
// contracts used in the Istanbul release.
var PrecompiledContractsIstanbul = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},
}

// PrecompiledContractsBerlin contains the default set of pre-compiled Ethereum
// contracts used in the Berlin release.
var PrecompiledContractsBerlin = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},
}

// PrecompiledContractsPisa contains the default set of pre-compiled Ethereum
// contracts used in the Berlin release.
var PrecompiledContractsPisa = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):          &ecrecover{},
	common.BytesToAddress([]byte{2}):          &sha256hash{},
	common.BytesToAddress([]byte{3}):          &ripemd160hash{},
	common.BytesToAddress([]byte{4}):          &dataCopy{},
	common.BytesToAddress([]byte{5}):          &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):          &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):          &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):          &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):          &blake2F{},
	common.BytesToAddress([]byte{3, 0x33, 1}): &systemContractDeployer{},
	common.BytesToAddress([]byte{3, 0x33, 2}): &sstoragePisa{},
	common.BytesToAddress([]byte{3, 0x33, 3}): &crossChainCall{},
	common.BytesToAddress([]byte{3, 0x33, 4}): &nativeToken{},
}

// PrecompiledContractsBLS contains the set of pre-compiled Ethereum
// contracts specified in EIP-2537. These are exported for testing purposes.
var PrecompiledContractsBLS = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{10}): &bls12381G1Add{},
	common.BytesToAddress([]byte{11}): &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}): &bls12381G2Add{},
	common.BytesToAddress([]byte{14}): &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}): &bls12381Pairing{},
	common.BytesToAddress([]byte{17}): &bls12381MapG1{},
	common.BytesToAddress([]byte{18}): &bls12381MapG2{},
}

var (
	PrecompiledAddressesBerlin    []common.Address
	PrecompiledAddressesIstanbul  []common.Address
	PrecompiledAddressesByzantium []common.Address
	PrecompiledAddressesHomestead []common.Address
)

func init() {
	for k := range PrecompiledContractsHomestead {
		PrecompiledAddressesHomestead = append(PrecompiledAddressesHomestead, k)
	}
	for k := range PrecompiledContractsByzantium {
		PrecompiledAddressesByzantium = append(PrecompiledAddressesByzantium, k)
	}
	for k := range PrecompiledContractsIstanbul {
		PrecompiledAddressesIstanbul = append(PrecompiledAddressesIstanbul, k)
	}
	for k := range PrecompiledContractsBerlin {
		PrecompiledAddressesBerlin = append(PrecompiledAddressesBerlin, k)
	}
}

// ActivePrecompiles returns the precompiles enabled with the current configuration.
func ActivePrecompiles(rules params.Rules) []common.Address {
	switch {
	case rules.IsBerlin:
		return PrecompiledAddressesBerlin
	case rules.IsIstanbul:
		return PrecompiledAddressesIstanbul
	case rules.IsByzantium:
		return PrecompiledAddressesByzantium
	default:
		return PrecompiledAddressesHomestead
	}
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
// It returns
// - the returned bytes,
// - the _remaining_ gas,
// - any error that occurred
func RunPrecompiledContract(env *PrecompiledContractCallEnv, p PrecompiledContract, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost
	if pw, ok := p.(PrecompiledContractToExternalCall); ok {
		var actualGasUsed uint64
		ret, actualGasUsed, err = pw.RunWith(env, input)
		// gas refund
		suppliedGas += gasCost - actualGasUsed
	} else if pw, ok := p.(PrecompiledContractWithEVM); ok {
		ret, err = pw.RunWith(env, input)
	} else {
		ret, err = p.Run(input)
	}
	return ret, suppliedGas, err
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// We must make sure not to modify the 'input', so placing the 'v' along with
	// the signature needs to be done on a new allocation
	sig := make([]byte, 65)
	copy(sig, input[64:128])
	sig[64] = v
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], sig)
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
func (c *dataCopy) Run(in []byte) ([]byte, error) {
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct {
	eip2565 bool
}

var (
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	big3      = big.NewInt(3)
	big4      = big.NewInt(4)
	big7      = big.NewInt(7)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big20     = big.NewInt(20)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198
//
// def mult_complexity(x):
//    if x <= 64: return x ** 2
//    elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//    else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
func modexpMultComplexity(x *big.Int) *big.Int {
	switch {
	case x.Cmp(big64) <= 0:
		x.Mul(x, x) // x ** 2
	case x.Cmp(big1024) <= 0:
		// (x ** 2 // 4 ) + ( 96 * x - 3072)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, x), big3072),
		)
	default:
		// (x ** 2 // 16) + (480 * x - 199680)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, x), big199680),
		)
	}
	return x
}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))
	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	if c.eip2565 {
		// EIP-2565 has three changes
		// 1. Different multComplexity (inlined here)
		// in EIP-2565 (https://eips.ethereum.org/EIPS/eip-2565):
		//
		// def mult_complexity(x):
		//    ceiling(x/8)^2
		//
		//where is x is max(length_of_MODULUS, length_of_BASE)
		gas = gas.Add(gas, big7)
		gas = gas.Div(gas, big8)
		gas.Mul(gas, gas)

		gas.Mul(gas, math.BigMax(adjExpLen, big1))
		// 2. Different divisor (`GQUADDIVISOR`) (3)
		gas.Div(gas, big3)
		if gas.BitLen() > 64 {
			return math.MaxUint64
		}
		// 3. Minimum price of 200 gas
		if gas.Uint64() < 200 {
			return 200
		}
		return gas.Uint64()
	}
	gas = modexpMultComplexity(gas)
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, big20)

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// runBn256Add implements the Bn256Add precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Add(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256Add implements a native elliptic curve point addition conforming to
// Istanbul consensus rules.
type bn256AddIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasIstanbul
}

func (c *bn256AddIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// bn256AddByzantium implements a native elliptic curve point addition
// conforming to Byzantium consensus rules.
type bn256AddByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasByzantium
}

func (c *bn256AddByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// runBn256ScalarMul implements the Bn256ScalarMul precompile, referenced by
// both Byzantium and Istanbul operations.
func runBn256ScalarMul(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

// bn256ScalarMulIstanbul implements a native elliptic curve scalar
// multiplication conforming to Istanbul consensus rules.
type bn256ScalarMulIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasIstanbul
}

func (c *bn256ScalarMulIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256ScalarMulByzantium implements a native elliptic curve scalar
// multiplication conforming to Byzantium consensus rules.
type bn256ScalarMulByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasByzantium
}

func (c *bn256ScalarMulByzantium) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// runBn256Pairing implements the Bn256Pairing precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Pairing(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// bn256PairingIstanbul implements a pairing pre-compile for the bn256 curve
// conforming to Istanbul consensus rules.
type bn256PairingIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasIstanbul + uint64(len(input)/192)*params.Bn256PairingPerPointGasIstanbul
}

func (c *bn256PairingIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

// bn256PairingByzantium implements a pairing pre-compile for the bn256 curve
// conforming to Byzantium consensus rules.
type bn256PairingByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasByzantium + uint64(len(input)/192)*params.Bn256PairingPerPointGasByzantium
}

func (c *bn256PairingByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

type blake2F struct{}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// If the input is malformed, we can't calculate the gas, return 0 and let the
	// actual call choke and fault.
	if len(input) != blake2FInputLength {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

const (
	blake2FInputLength        = 213
	blake2FFinalBlockBytes    = byte(1)
	blake2FNonFinalBlockBytes = byte(0)
)

var (
	errBlake2FInvalidInputLength = errors.New("invalid input length")
	errBlake2FInvalidFinalFlag   = errors.New("invalid final flag")
)

func (c *blake2F) Run(input []byte) ([]byte, error) {
	// Make sure the input is valid (correct length and final flag)
	if len(input) != blake2FInputLength {
		return nil, errBlake2FInvalidInputLength
	}
	if input[212] != blake2FNonFinalBlockBytes && input[212] != blake2FFinalBlockBytes {
		return nil, errBlake2FInvalidFinalFlag
	}
	// Parse the input into the Blake2b call parameters
	var (
		rounds = binary.BigEndian.Uint32(input[0:4])
		final  = (input[212] == blake2FFinalBlockBytes)

		h [8]uint64
		m [16]uint64
		t [2]uint64
	)
	for i := 0; i < 8; i++ {
		offset := 4 + i*8
		h[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	for i := 0; i < 16; i++ {
		offset := 68 + i*8
		m[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	t[0] = binary.LittleEndian.Uint64(input[196:204])
	t[1] = binary.LittleEndian.Uint64(input[204:212])

	// Execute the compression function, extract and return the result
	blake2b.F(&h, m, t, final, rounds)

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		offset := i * 8
		binary.LittleEndian.PutUint64(output[offset:offset+8], h[i])
	}
	return output, nil
}

type systemContractDeployer struct{}

var (
	w3qNativeContractAddr = common.HexToAddress("0x0000000000000000000000000000000003330002")

	// contract at 0x0000000000000000000000000000000003330001 is complied DecentralizedKV(0x33302, 4096, 1652641001, 1000000000000000, 340282365784068676928457747575078800565)+3b2d31+0.8.13 solc
	systemContracts = map[common.Address][]byte{
		common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("6080604052600436106100dd5760003560e01c8063749cf2821161007f5780639cf001fe116100595780639cf001fe146102c6578063a097365f14610312578063a4a8435e14610346578063afd5644d1461037a57600080fd5b8063749cf2821461024557806378e979251461027257806395bc2673146102a657600080fd5b8063429dd7ad116100bb578063429dd7ad1461016e57806344e77d99146101a257806349bdd6f5146101b757806373e8b3d4146101d757600080fd5b80631ccbc6da146100e2578063258ae5821461010a5780633cb2fecc1461013a575b600080fd5b3480156100ee57600080fd5b506100f76103dc565b6040519081526020015b60405180910390f35b34801561011657600080fd5b5061012a610125366004610e28565b6103ec565b6040519015158152602001610101565b34801561014657600080fd5b506100f77f00000000000000000000000000000000000000000000000000038d7ea4c6800081565b34801561017a57600080fd5b5060005461018c9064ffffffffff1681565b60405164ffffffffff9091168152602001610101565b6101b56101b0366004610e28565b6104ed565b005b3480156101c357600080fd5b506101b56101d2366004610eb2565b6107f1565b3480156101e357600080fd5b5061012a6101f2366004610eee565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b34801561025157600080fd5b50610265610260366004610f07565b610aa1565b6040516101019190610f8f565b34801561027e57600080fd5b506100f77f0000000000000000000000000000000000000000000000000000000062814ce981565b3480156102b257600080fd5b506101b56102c1366004610eee565b610ccf565b3480156102d257600080fd5b506102fa7f000000000000000000000000000000000000000000000000000000000003330281565b6040516001600160a01b039091168152602001610101565b34801561031e57600080fd5b506100f77f000000000000000000000000000000000000000000000000000000000000100081565b34801561035257600080fd5b506100f77f00000000000000000000000000000000fffffff1a6935a84491b53a3b65e4cb581565b34801561038657600080fd5b506100f7610395366004610eee565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b60006103e742610cdc565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff19169284018390529350036104aa5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064015b60405180910390fd5b8351816020015162ffffff16146104c6576000925050506104e7565b8351602085012060409091015167ffffffffffffffff199081169116149150505b92915050565b7f00000000000000000000000000000000000000000000000000000000000010008151111561054f5760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b60448201526064016104a1565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610674576105d76103dc565b34101561061b5760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b60448201526064016104a1565b6000805464ffffffffff908116808452855162ffffff166020808601919091529083526002905260408220849055905461065791166001610fb8565b6000805464ffffffffff191664ffffffffff929092169190911790555b825160208085019190912067ffffffffffffffff19908116604080850191825260008681526001855281812086518154968801519451841c600160401b0262ffffff909516600160281b029690951664ffffffffff8616179590951767ffffffffffffffff169290921790935591516001600160a01b037f000000000000000000000000000000000000000000000000000000000003330216916304fb033960e41b9161072691908890602401610fe1565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b03199094169390931790925290516107649190611009565b6000604051808303816000865af19150503d80600081146107a1576040519150601f19603f3d011682016040523d82523d6000602084013e6107a6565b606091505b50509050806107ea5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2070757452617760801b60448201526064016104a1565b5050505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff1916938501849052909450909190036108ac5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064016104a1565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff968716179190911767ffffffffffffffff16179092558054909260029284926109319216611025565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff1916909117905581549095509093849261098f9216611025565b64ffffffffff9081168252602082019290925260400160009081209290925590546109bd9160019116611025565b6000805464ffffffffff191664ffffffffff928316908117909155604051633625b3bb60e11b8152600481019190915290831660248201527f00000000000000000000000000000000000000000000000000000000000333026001600160a01b031690636c4b677690604401600060405180830381600087803b158015610a4357600080fd5b505af1158015610a57573d6000803e3d6000fd5b50505050846001600160a01b03166108fc610a706103dc565b6040518115909202916000818181858888f19350505050158015610a98573d6000803e3d6000fd5b50505050505050565b606081600003610ac05750604080516000815260208101909152610cc8565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff1916928401929092529092508510610b595750506040805160008152602081019091529050610cc8565b602081015162ffffff16610b6d868661104b565b1115610b8b5784816020015162ffffff16610b889190611063565b93505b6040818101518251825167ffffffffffffffff19909216602483015264ffffffffff1660448201526064810187905260848082018790528251808303909101815260a490910182526020810180516001600160e01b031663f835367f60e01b179052905160009182917f00000000000000000000000000000000000000000000000000000000000333026001600160a01b031691610c2891611009565b600060405180830381855afa9150503d8060008114610c63576040519150601f19603f3d011682016040523d82523d6000602084013e610c68565b606091505b509150915081610cad5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b60448201526064016104a1565b80806020019051810190610cc1919061107a565b9450505050505b9392505050565b610cd981336107f1565b50565b60006104e77f00000000000000000000000000000000000000000000000000038d7ea4c68000610d2c7f0000000000000000000000000000000000000000000000000000000062814ce985611063565b60006080610d5a7f00000000000000000000000000000000fffffff1a6935a84491b53a3b65e4cb584610d6d565b610d6490856110f1565b901c9392505050565b6000600160801b5b8215610cc85782600116600103610d97576080610d9285836110f1565b901c90505b6080610da385806110f1565b901c9350610db2600284611110565b9250610d75565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff81118282101715610df857610df8610db9565b604052919050565b600067ffffffffffffffff821115610e1a57610e1a610db9565b50601f01601f191660200190565b60008060408385031215610e3b57600080fd5b82359150602083013567ffffffffffffffff811115610e5957600080fd5b8301601f81018513610e6a57600080fd5b8035610e7d610e7882610e00565b610dcf565b818152866020838501011115610e9257600080fd5b816020840160208301376000602083830101528093505050509250929050565b60008060408385031215610ec557600080fd5b8235915060208301356001600160a01b0381168114610ee357600080fd5b809150509250929050565b600060208284031215610f0057600080fd5b5035919050565b600080600060608486031215610f1c57600080fd5b505081359360208301359350604090920135919050565b60005b83811015610f4e578181015183820152602001610f36565b83811115610f5d576000848401525b50505050565b60008151808452610f7b816020860160208601610f33565b601f01601f19169290920160200192915050565b602081526000610cc86020830184610f63565b634e487b7160e01b600052601160045260246000fd5b600064ffffffffff808316818516808303821115610fd857610fd8610fa2565b01949350505050565b64ffffffffff831681526040602082015260006110016040830184610f63565b949350505050565b6000825161101b818460208701610f33565b9190910192915050565b600064ffffffffff8381169083168181101561104357611043610fa2565b039392505050565b6000821982111561105e5761105e610fa2565b500190565b60008282101561107557611075610fa2565b500390565b60006020828403121561108c57600080fd5b815167ffffffffffffffff8111156110a357600080fd5b8201601f810184136110b457600080fd5b80516110c2610e7882610e00565b8181528560208385010111156110d757600080fd5b6110e8826020830160208601610f33565b95945050505050565b600081600019048311821515161561110b5761110b610fa2565b500290565b60008261112d57634e487b7160e01b600052601260045260246000fd5b50049056fea2646970667358221220a681d6af7f28ec6eaae1a368ab315d95af7a70e728eae30bf889df807a79f36d64736f6c634300080d0033"),
		// debug code with putRaw() and getRaw() direclty.
		// common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("6080604052600436106100fe5760003560e01c806373e8b3d4116100955780639cf001fe116100645780639cf001fe14610327578063a097365f14610373578063a4a8435e146103a7578063afd5644d146103db578063bc5c77be1461043d57600080fd5b806373e8b3d414610245578063749cf282146102b357806378e97925146102d357806395bc26731461030757600080fd5b8063429dd7ad116100d1578063429dd7ad146101bc57806344e77d99146101f057806349bdd6f5146102055780634fb033901461022557600080fd5b80631ccbc6da14610103578063258ae5821461012b57806333b073391461015b5780633cb2fecc14610188575b600080fd5b34801561010f57600080fd5b5061011861045d565b6040519081526020015b60405180910390f35b34801561013757600080fd5b5061014b6101463660046111e3565b61046d565b6040519015158152602001610122565b34801561016757600080fd5b5061017b61017636600461122a565b61056e565b60405161012291906112a8565b34801561019457600080fd5b506101187f00000000000000000000000000000000000000000000000000038d7ea4c6800081565b3480156101c857600080fd5b506000546101da9064ffffffffff1681565b60405164ffffffffff9091168152602001610122565b6102036101fe3660046111e3565b61069a565b005b34801561021157600080fd5b506102036102203660046112bb565b610980565b34801561023157600080fd5b506102036102403660046111e3565b610c30565b34801561025157600080fd5b5061014b6102603660046112f7565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b3480156102bf57600080fd5b5061017b6102ce366004611310565b610d1d565b3480156102df57600080fd5b506101187f0000000000000000000000000000000000000000000000000000000062814ce981565b34801561031357600080fd5b506102036103223660046112f7565b610f4b565b34801561033357600080fd5b5061035b7f000000000000000000000000000000000000000000000000000000000003330281565b6040516001600160a01b039091168152602001610122565b34801561037f57600080fd5b506101187f000000000000000000000000000000000000000000000000000000000000100081565b3480156103b357600080fd5b506101187f00000000000000000000000000000000fffffff1a6935a84491b53a3b65e4cb581565b3480156103e757600080fd5b506101186103f63660046112f7565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b34801561044957600080fd5b506102036104583660046111e3565b610f58565b600061046842611041565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff191692840183905293500361052b5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064015b60405180910390fd5b8351816020015162ffffff161461054757600092505050610568565b8351602085012060409091015167ffffffffffffffff199081169116149150505b92915050565b60408051600060248201819052604482018590526064820181905260848083018590528351808403909101815260a490920183526020820180516001600160e01b031663f835367f60e01b17905291516060929182917f00000000000000000000000000000000000000000000000000000000000333026001600160a01b0316916105f89161133c565b600060405180830381855afa9150503d8060008114610633576040519150601f19603f3d011682016040523d82523d6000602084013e610638565b606091505b50915091508161067d5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b6044820152606401610522565b808060200190518101906106919190611358565b95945050505050565b7f0000000000000000000000000000000000000000000000000000000000001000815111156106fc5760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b6044820152606401610522565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff19169284018390529350036108215761078461045d565b3410156107c85760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b6044820152606401610522565b6000805464ffffffffff908116808452855162ffffff1660208086019190915290835260029052604082208490559054610804911660016113dc565b6000805464ffffffffff191664ffffffffff929092169190911790555b825162ffffff908116602080840191825285518187012067ffffffffffffffff199081166040808701918252600088815260019094528084208751815496519351831c600160401b0293909716600160281b029590931664ffffffffff8716179490941767ffffffffffffffff16179055905190916001600160a01b037f000000000000000000000000000000000000000000000000000000000003330216916304fb033960e41b916108d8918890602401611405565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b0319909416939093179092529051610916919061133c565b6000604051808303816000865af19150503d8060008114610953576040519150601f19603f3d011682016040523d82523d6000602084013e610958565b606091505b50509050806109795760405162461bcd60e51b81526004016105229061142d565b5050505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff191693850184905290945090919003610a3b5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b6044820152606401610522565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff968716179190911767ffffffffffffffff1617909255805490926002928492610ac09216611457565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff19169091179055815490955090938492610b1e9216611457565b64ffffffffff908116825260208201929092526040016000908120929092559054610b4c9160019116611457565b6000805464ffffffffff191664ffffffffff928316908117909155604051633625b3bb60e11b8152600481019190915290831660248201527f00000000000000000000000000000000000000000000000000000000000333026001600160a01b031690636c4b677690604401600060405180830381600087803b158015610bd257600080fd5b505af1158015610be6573d6000803e3d6000fd5b50505050846001600160a01b03166108fc610bff61045d565b6040518115909202916000818181858888f19350505050158015610c27573d6000803e3d6000fd5b50505050505050565b60007f00000000000000000000000000000000000000000000000000000000000333026001600160a01b0316634fb0339060e01b8484604051602401610c7792919061147d565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b0319909416939093179092529051610cb5919061133c565b6000604051808303816000865af19150503d8060008114610cf2576040519150601f19603f3d011682016040523d82523d6000602084013e610cf7565b606091505b5050905080610d185760405162461bcd60e51b81526004016105229061142d565b505050565b606081600003610d3c5750604080516000815260208101909152610f44565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff1916928401929092529092508510610dd55750506040805160008152602081019091529050610f44565b602081015162ffffff16610de98686611496565b1115610e075784816020015162ffffff16610e0491906114ae565b93505b6040818101518251825167ffffffffffffffff19909216602483015264ffffffffff1660448201526064810187905260848082018790528251808303909101815260a490910182526020810180516001600160e01b031663f835367f60e01b179052905160009182917f00000000000000000000000000000000000000000000000000000000000333026001600160a01b031691610ea49161133c565b600060405180830381855afa9150503d8060008114610edf576040519150601f19603f3d011682016040523d82523d6000602084013e610ee4565b606091505b509150915081610f295760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b6044820152606401610522565b80806020019051810190610f3d9190611358565b9450505050505b9392505050565b610f558133610980565b50565b60007f00000000000000000000000000000000000000000000000000000000000333026001600160a01b0316634fb0339060e01b8484604051602401610f9f92919061147d565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b0319909416939093179092529051610fdd919061133c565b6000604051808303816000865af19150503d806000811461101a576040519150601f19603f3d011682016040523d82523d6000602084013e61101f565b606091505b505090508015610d185760405162461bcd60e51b81526004016105229061142d565b60006105687f00000000000000000000000000000000000000000000000000038d7ea4c680006110917f0000000000000000000000000000000000000000000000000000000062814ce9856114ae565b600060806110bf7f00000000000000000000000000000000fffffff1a6935a84491b53a3b65e4cb5846110d2565b6110c990856114c5565b901c9392505050565b6000600160801b5b8215610f4457826001166001036110fc5760806110f785836114c5565b901c90505b608061110885806114c5565b901c93506111176002846114e4565b92506110da565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff8111828210171561115d5761115d61111e565b604052919050565b600067ffffffffffffffff82111561117f5761117f61111e565b50601f01601f191660200190565b600082601f83011261119e57600080fd5b81356111b16111ac82611165565b611134565b8181528460208386010111156111c657600080fd5b816020850160208301376000918101602001919091529392505050565b600080604083850312156111f657600080fd5b82359150602083013567ffffffffffffffff81111561121457600080fd5b6112208582860161118d565b9150509250929050565b6000806040838503121561123d57600080fd5b50508035926020909101359150565b60005b8381101561126757818101518382015260200161124f565b83811115611276576000848401525b50505050565b6000815180845261129481602086016020860161124c565b601f01601f19169290920160200192915050565b602081526000610f44602083018461127c565b600080604083850312156112ce57600080fd5b8235915060208301356001600160a01b03811681146112ec57600080fd5b809150509250929050565b60006020828403121561130957600080fd5b5035919050565b60008060006060848603121561132557600080fd5b505081359360208301359350604090920135919050565b6000825161134e81846020870161124c565b9190910192915050565b60006020828403121561136a57600080fd5b815167ffffffffffffffff81111561138157600080fd5b8201601f8101841361139257600080fd5b80516113a06111ac82611165565b8181528560208385010111156113b557600080fd5b61069182602083016020860161124c565b634e487b7160e01b600052601160045260246000fd5b600064ffffffffff8083168185168083038211156113fc576113fc6113c6565b01949350505050565b64ffffffffff83168152604060208201526000611425604083018461127c565b949350505050565b60208082526010908201526f6661696c656420746f2070757452617760801b604082015260600190565b600064ffffffffff83811690831681811015611475576114756113c6565b039392505050565b828152604060208201526000611425604083018461127c565b600082198211156114a9576114a96113c6565b500190565b6000828210156114c0576114c06113c6565b500390565b60008160001904831182151516156114df576114df6113c6565b500290565b60008261150157634e487b7160e01b600052601260045260246000fd5b50049056fea26469706673582212200938bd543a1cf6d60f50cbadfe7df73030e2c6803e6091684535c570e4a31c0c64736f6c634300080d0033"),

		//w3qNativeContractAddr: common.Hex2Bytes("60806040526004361061007b5760003560e01c80639f9d6b681161004e5780639f9d6b681461010d578063a30662ce1461012d578063a46632b71461014d578063dbc117581461019857600080fd5b80630f36915914610080578063474d6dea146100955780634b2f6ca7146100be5780638c95e054146100f6575b600080fd5b61009361008e3660046105a6565b6101c7565b005b3480156100a157600080fd5b506100ab60035481565b6040519081526020015b60405180910390f35b3480156100ca57600080fd5b506001546100de906001600160a01b031681565b6040516001600160a01b0390911681526020016100b5565b34801561010257600080fd5b506100de6203330381565b34801561011957600080fd5b506100936101283660046105ca565b610275565b34801561013957600080fd5b506000546100de906001600160a01b031681565b34801561015957600080fd5b506101886101683660046105ca565b600260209081526000928352604080842090915290825290205460ff1681565b60405190151581526020016100b5565b3480156101a457600080fd5b506101b86101b33660046105ec565b610469565b6040516100b593929190610683565b600054604051633a9e0e1360e01b81526001600160a01b03838116600483015234602483015290911690633a9e0e1390604401600060405180830381600087803b15801561021457600080fd5b505af1158015610228573d6000803e3d6000fd5b50505050806001600160a01b03166003547fa999eff97867b1c67e4ab6171e0fadb1d9fe5882e6a083887a39779cad358d4d3460405161026a91815260200190565b60405180910390a350565b600082815260026020908152604080832084845290915290205460ff16156102e45760405162461bcd60e51b815260206004820152601a60248201527f746865206275726e206c6f6720686173206265656e207573656400000000000060448201526064015b60405180910390fd5b600082815260026020908152604080832084845282528220805460ff191660011790558190819061031d9060049087908790600a610469565b60015492955090935091506001600160a01b0380851691161461037b5760405162461bcd60e51b81526020600482015260166024820152750c6dedce8e4c2c6e840c2c8c8e440dcde40dac2e8c6d60531b60448201526064016102db565b600082600181518110610390576103906106ec565b602002602001015160001c90506000828060200190518101906103b39190610702565b600054604051630315550b60e51b81526001600160a01b038581166004830152602482018490529293509116906362aaa16090604401600060405180830381600087803b15801561040357600080fd5b505af1158015610417573d6000803e3d6000fd5b50505050816001600160a01b031686887fede1ec221b93e714d4bbfb2e7aa2baf5d1778928742bd54ec9f2c9428c7d706e8460405161045891815260200190565b60405180910390a450505050505050565b6040516024810186905260448101859052606481018490526084810183905260a481018290526000906060908190839060c40160408051601f198184030181529181526020820180516001600160e01b031663099e200760e41b17905251909150600090819062033303906104df90859061071b565b6000604051808303816000865af19150503d806000811461051c576040519150601f19603f3d011682016040523d82523d6000602084013e610521565b606091505b50915091508161055d5760008180602001905181019061054191906107cd565b90508060405162461bcd60e51b81526004016102db919061081e565b6000806000838060200190518101906105769190610851565b919a5098509650505050505050955095509592505050565b6001600160a01b03811681146105a357600080fd5b50565b6000602082840312156105b857600080fd5b81356105c38161058e565b9392505050565b600080604083850312156105dd57600080fd5b50508035926020909101359150565b600080600080600060a0868803121561060457600080fd5b505083359560208501359550604085013594606081013594506080013592509050565b60005b8381101561064257818101518382015260200161062a565b83811115610651576000848401525b50505050565b6000815180845261066f816020860160208601610627565b601f01601f19169290920160200192915050565b6001600160a01b038416815260606020808301829052845191830182905260009185820191906080850190845b818110156106cc578451835293830193918301916001016106b0565b505084810360408601526106e08187610657565b98975050505050505050565b634e487b7160e01b600052603260045260246000fd5b60006020828403121561071457600080fd5b5051919050565b6000825161072d818460208701610627565b9190910192915050565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff8111828210171561077657610776610737565b604052919050565b600067ffffffffffffffff83111561079857610798610737565b6107ab601f8401601f191660200161074d565b90508281528383830111156107bf57600080fd5b6105c3836020830184610627565b6000602082840312156107df57600080fd5b815167ffffffffffffffff8111156107f657600080fd5b8201601f8101841361080757600080fd5b6108168482516020840161077e565b949350505050565b6020815260006105c36020830184610657565b600082601f83011261084257600080fd5b6105c38383516020850161077e565b60008060006060848603121561086657600080fd5b83516108718161058e565b8093505060208085015167ffffffffffffffff8082111561089157600080fd5b818701915087601f8301126108a557600080fd5b8151818111156108b7576108b7610737565b8060051b6108c685820161074d565b918252838101850191858101908b8411156108e057600080fd5b948601945b838610156108fe578551825294860194908601906108e5565b60408b015190985095505050508083111561091857600080fd5b505061092686828701610831565b915050925092509256fea2646970667358221220c3dedad281ea41842f2f27a8dba16c19d6686c457a6bbb1d7bd4aec8ee92d5f064736f6c63430008090033"),
		// debug code with mintNative() and burnNative() direclty.
		w3qNativeContractAddr: common.Hex2Bytes("6080604052600436106100a75760003560e01c80639f9d6b68116100645780639f9d6b68146101be578063a30662ce146101e7578063a3d9310414610212578063a46632b71461023b578063dbc1175814610278578063fbc7c433146102b7576100a7565b8063123fdffd146100ac5780632f6af8cc146100d7578063474d6dea1461010257806370a082311461012d578063885b012e1461016a5780638c95e05414610193575b600080fd5b3480156100b857600080fd5b506100c16102c1565b6040516100ce91906111a0565b60405180910390f35b3480156100e357600080fd5b506100ec6102e5565b6040516100f991906112e6565b60405180910390f35b34801561010e57600080fd5b506101176102ea565b60405161012491906112e6565b60405180910390f35b34801561013957600080fd5b50610154600480360381019061014f9190610d70565b6102f0565b60405161016191906112e6565b60405180910390f35b34801561017657600080fd5b50610191600480360381019061018c9190610d70565b610311565b005b34801561019f57600080fd5b506101a8610354565b6040516101b591906111a0565b60405180910390f35b3480156101ca57600080fd5b506101e560048036038101906101e09190610e68565b61035b565b005b3480156101f357600080fd5b506101fc610686565b60405161020991906111a0565b60405180910390f35b34801561021e57600080fd5b5061023960048036038101906102349190610e28565b61068d565b005b34801561024757600080fd5b50610262600480360381019061025d9190610e68565b610810565b60405161026f9190611229565b60405180910390f35b34801561028457600080fd5b5061029f600480360381019061029a9190610f1e565b61083f565b6040516102ae939291906111bb565b60405180910390f35b6102bf6109e3565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600a81565b60025481565b60008173ffffffffffffffffffffffffffffffffffffffff16319050919050565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b6203330381565b60016000838152602001908152602001600020600082815260200190815260200160002060009054906101000a900460ff16156103cd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103c490611266565b60405180910390fd5b6001806000848152602001908152602001600020600083815260200190815260200160002060006101000a81548160ff021916908315150217905550600080600061041e600486866020600a61083f565b92509250925060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16146104b2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104a990611286565b60405180910390fd5b6000826001815181106104c8576104c761154b565b5b602002602001015160001c90506000828060200190518101906104eb9190610ef1565b905060006203330473ffffffffffffffffffffffffffffffffffffffff16838360405160240161051c929190611200565b6040516020818303038152906040527f62aaa160000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040516105a69190611189565b6000604051808303816000865af19150503d80600081146105e3576040519150601f19603f3d011682016040523d82523d6000602084013e6105e8565b606091505b505090508061062c576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610623906112a6565b60405180910390fd5b8273ffffffffffffffffffffffffffffffffffffffff1687897fede1ec221b93e714d4bbfb2e7aa2baf5d1778928742bd54ec9f2c9428c7d706e8560405161067491906112e6565b60405180910390a45050505050505050565b6203330481565b600082826040516024016106a2929190611200565b6040516020818303038152906040527f62aaa160000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050905060006203330473ffffffffffffffffffffffffffffffffffffffff168260405161074b9190611189565b6000604051808303816000865af19150503d8060008114610788576040519150601f19603f3d011682016040523d82523d6000602084013e61078d565b606091505b50509050806107d1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107c8906112a6565b60405180910390fd5b7f9377811ba710d0ad51cde923ddc0a0bbd89a4d1318c9e1a67beff9baad029ca58484604051610802929190611200565b60405180910390a150505050565b60016020528160005260406000206020528060005260406000206000915091509054906101000a900460ff1681565b60006060806000888888888860405160240161085f959493929190611301565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff16836040516109099190611189565b6000604051808303816000865af19150503d8060008114610946576040519150601f19603f3d011682016040523d82523d6000602084013e61094b565b606091505b5091509150816109aa5760008180602001905181019061096b9190610ea8565b9050806040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109a19190611244565b60405180910390fd5b6000806000838060200190518101906109c39190610d9d565b925092509250828282985098509850505050505050955095509592505050565b60006203330473ffffffffffffffffffffffffffffffffffffffff1634604051602401610a1091906112e6565b6040516020818303038152906040527fabc10ca1000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff8381831617835250505050604051610a9a9190611189565b6000604051808303816000865af19150503d8060008114610ad7576040519150601f19603f3d011682016040523d82523d6000602084013e610adc565b606091505b5050905080610b20576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b17906112c6565b60405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff166002547fa999eff97867b1c67e4ab6171e0fadb1d9fe5882e6a083887a39779cad358d4d34604051610b6991906112e6565b60405180910390a350565b6000610b87610b8284611379565b611354565b90508083825260208201905082856020860282011115610baa57610ba96115ae565b5b60005b85811015610bda5781610bc08882610cd5565b845260208401935060208301925050600181019050610bad565b5050509392505050565b6000610bf7610bf2846113a5565b611354565b905082815260208101848484011115610c1357610c126115b3565b5b610c1e8482856114e7565b509392505050565b6000610c39610c34846113d6565b611354565b905082815260208101848484011115610c5557610c546115b3565b5b610c608482856114e7565b509392505050565b600081359050610c7781611677565b92915050565b600081519050610c8c8161168e565b92915050565b600082601f830112610ca757610ca66115a9565b5b8151610cb7848260208601610b74565b91505092915050565b600081359050610ccf816116a5565b92915050565b600081519050610ce4816116a5565b92915050565b600082601f830112610cff57610cfe6115a9565b5b8151610d0f848260208601610be4565b91505092915050565b600082601f830112610d2d57610d2c6115a9565b5b8151610d3d848260208601610c26565b91505092915050565b600081359050610d55816116bc565b92915050565b600081519050610d6a816116bc565b92915050565b600060208284031215610d8657610d856115bd565b5b6000610d9484828501610c68565b91505092915050565b600080600060608486031215610db657610db56115bd565b5b6000610dc486828701610c7d565b935050602084015167ffffffffffffffff811115610de557610de46115b8565b5b610df186828701610c92565b925050604084015167ffffffffffffffff811115610e1257610e116115b8565b5b610e1e86828701610cea565b9150509250925092565b60008060408385031215610e3f57610e3e6115bd565b5b6000610e4d85828601610c68565b9250506020610e5e85828601610d46565b9150509250929050565b60008060408385031215610e7f57610e7e6115bd565b5b6000610e8d85828601610cc0565b9250506020610e9e85828601610d46565b9150509250929050565b600060208284031215610ebe57610ebd6115bd565b5b600082015167ffffffffffffffff811115610edc57610edb6115b8565b5b610ee884828501610d18565b91505092915050565b600060208284031215610f0757610f066115bd565b5b6000610f1584828501610d5b565b91505092915050565b600080600080600060a08688031215610f3a57610f396115bd565b5b6000610f4888828901610d46565b9550506020610f5988828901610cc0565b9450506040610f6a88828901610d46565b9350506060610f7b88828901610d46565b9250506080610f8c88828901610d46565b9150509295509295909350565b6000610fa5838361102d565b60208301905092915050565b610fba81611483565b82525050565b6000610fcb82611417565b610fd58185611445565b9350610fe083611407565b8060005b83811015611011578151610ff88882610f99565b975061100383611438565b925050600181019050610fe4565b5085935050505092915050565b611027816114a7565b82525050565b611036816114b3565b82525050565b611045816114b3565b82525050565b600061105682611422565b6110608185611456565b93506110708185602086016114e7565b611079816115c2565b840191505092915050565b600061108f82611422565b6110998185611467565b93506110a98185602086016114e7565b80840191505092915050565b60006110c08261142d565b6110ca8185611472565b93506110da8185602086016114e7565b6110e3816115c2565b840191505092915050565b60006110fb601a83611472565b9150611106826115d3565b602082019050919050565b600061111e601683611472565b9150611129826115fc565b602082019050919050565b6000611141601783611472565b915061114c82611625565b602082019050919050565b6000611164601783611472565b915061116f8261164e565b602082019050919050565b611183816114dd565b82525050565b60006111958284611084565b915081905092915050565b60006020820190506111b56000830184610fb1565b92915050565b60006060820190506111d06000830186610fb1565b81810360208301526111e28185610fc0565b905081810360408301526111f6818461104b565b9050949350505050565b60006040820190506112156000830185610fb1565b611222602083018461117a565b9392505050565b600060208201905061123e600083018461101e565b92915050565b6000602082019050818103600083015261125e81846110b5565b905092915050565b6000602082019050818103600083015261127f816110ee565b9050919050565b6000602082019050818103600083015261129f81611111565b9050919050565b600060208201905081810360008301526112bf81611134565b9050919050565b600060208201905081810360008301526112df81611157565b9050919050565b60006020820190506112fb600083018461117a565b92915050565b600060a082019050611316600083018861117a565b611323602083018761103c565b611330604083018661117a565b61133d606083018561117a565b61134a608083018461117a565b9695505050505050565b600061135e61136f565b905061136a828261151a565b919050565b6000604051905090565b600067ffffffffffffffff8211156113945761139361157a565b5b602082029050602081019050919050565b600067ffffffffffffffff8211156113c0576113bf61157a565b5b6113c9826115c2565b9050602081019050919050565b600067ffffffffffffffff8211156113f1576113f061157a565b5b6113fa826115c2565b9050602081019050919050565b6000819050602082019050919050565b600081519050919050565b600081519050919050565b600081519050919050565b6000602082019050919050565b600082825260208201905092915050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061148e826114bd565b9050919050565b60006114a0826114bd565b9050919050565b60008115159050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156115055780820151818401526020810190506114ea565b83811115611514576000848401525b50505050565b611523826115c2565b810181811067ffffffffffffffff821117156115425761154161157a565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f746865206275726e206c6f6720686173206265656e2075736564000000000000600082015250565b7f636f6e74726163742061646472206e6f206d6174636800000000000000000000600082015250565b7f6d696e74206e617469766520746f6b656e206572726f72000000000000000000600082015250565b7f6275726e206e617469766520746f6b656e206572726f72000000000000000000600082015250565b61168081611483565b811461168b57600080fd5b50565b61169781611495565b81146116a257600080fd5b50565b6116ae816114b3565b81146116b957600080fd5b50565b6116c5816114dd565b81146116d057600080fd5b5056fea26469706673582212209814447d6cb80e680e155881e3c54740c697c8f9a66190be1aba9dffb095274c64736f6c63430008070033"),
	}
)

func (l *systemContractDeployer) RequiredGas(input []byte) uint64 {
	if len(input) < 32 {
		return 0
	}

	addr := common.BytesToAddress(input[0:32])
	if b, ok := systemContracts[addr]; ok {
		return uint64(len(b)) / params.CreateDataGas
	} else {
		return 0
	}
}

func (l *systemContractDeployer) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (l *systemContractDeployer) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	if len(input) < 32 {
		return nil, errors.New("invalid input length")
	}

	evm := env.evm
	addr := common.BytesToAddress(input[0:32])
	if b, ok := systemContracts[addr]; ok {
		if !evm.StateDB.Exist(addr) {
			evm.StateDB.CreateAccount(addr)
		}
		// allow override to upgrade the contract
		evm.StateDB.SetCode(addr, b)
		return nil, nil
	} else {
		return nil, errors.New("contract not found")
	}
}

var (
	putRawMethodId, _    = hex.DecodeString("4fb03390") // putRaw(uint256,bytes)
	getRawMethodId, _    = hex.DecodeString("f835367f") // getRaw(bytes32,uint256,uint256,uint256)
	removeRawMethodId, _ = hex.DecodeString("6c4b6776") // removeRaw(uint256,uint256)
)

type sstoragePisa struct{}

func (l *sstoragePisa) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}

	if bytes.Equal(input[0:4], putRawMethodId) {
		return params.SstoreResetGasEIP2200
	} else if bytes.Equal(input[0:4], getRawMethodId) {
		return params.SloadGasEIP2200
	} else {
		// TODO: remove is not supported yet
		return 0
	}
}

func (l *sstoragePisa) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (l *sstoragePisa) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errors.New("invalid input length")
	}

	evm := env.evm
	caller := env.caller.Address()
	maxKVSize := evm.StateDB.SstorageMaxKVSize(caller)
	if maxKVSize == 0 {
		return nil, errors.New("invalid caller")
	}

	if bytes.Equal(input[0:4], putRawMethodId) {
		if evm.interpreter.readOnly {
			return nil, ErrWriteProtection
		}
		kvIdx := new(big.Int).SetBytes(getData(input, 4, 32)).Uint64()
		dataPtr := new(big.Int).SetBytes(getData(input, 4+32, 32)).Uint64()
		if 4+dataPtr > uint64(len(input)) {
			return nil, errors.New("dataptr too large")
		}
		putLen := new(big.Int).SetBytes(getData(input, 4+dataPtr, 32)).Uint64()

		if putLen > maxKVSize {
			return nil, errors.New("put len too large")
		}
		evm.StateDB.SstorageWrite(caller, kvIdx, getData(input, 4+dataPtr+32, putLen))
		return nil, nil
	} else if bytes.Equal(input[0:4], getRawMethodId) {
		if !evm.Config.IsJsonRpc {
			return nil, errors.New("getRaw() must be called in JSON RPC")
		}
		// TODO: check hash correctness
		// hash := new(big.Int).SetBytes(getData(input, 4, 4+32))
		kvIdx := new(big.Int).SetBytes(getData(input, 4+32, 32)).Uint64()
		kvOff := new(big.Int).SetBytes(getData(input, 4+64, 32)).Uint64()
		kvLen := new(big.Int).SetBytes(getData(input, 4+96, 32)).Uint64()
		fb, ok, err := evm.StateDB.SstorageRead(caller, kvIdx, int(kvLen+kvOff))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("shard data not found: %s, %d", common.Bytes2Hex(env.caller.Address().Bytes()), kvIdx)
		}
		b := fb[kvOff:]
		pb := make([]byte, 64)
		binary.BigEndian.PutUint64(pb[32-8:32], 32)
		binary.BigEndian.PutUint64(pb[64-8:64], uint64(len(b)))
		return append(pb, b...), nil
	}
	// TODO: remove is not supported yet
	return nil, errors.New("unsupported method")
}

type nativeToken struct{}

var (
	//62aaa160  =>  mintNative(address,uint256)
	//abc10ca1  =>  burnNative(uint256)
	mintNativeId, _ = hex.DecodeString("62aaa160")
	burnNativeId, _ = hex.DecodeString("abc10ca1")
)

func (n *nativeToken) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}

	if bytes.Equal(input[0:4], mintNativeId) {
		return params.MintNativeTokenGas
	} else if bytes.Equal(input[0:4], burnNativeId) {
		return params.BurnNativeTokenGas
	} else {
		// TODO: remove is not supported yet
		return 0
	}
}

func (n *nativeToken) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (n *nativeToken) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errors.New("invalid input length")
	}

	evm := env.evm
	caller := env.caller.Address()
	if bytes.Equal(input[0:4], mintNativeId) {

		// verify caller
		log.Warn("Caller Info", "caller", caller, "Expect Caller", w3qNativeContractAddr)

		if caller != w3qNativeContractAddr {
			log.Warn("Error Caller", "caller", caller, "Expect Caller", w3qNativeContractAddr)
			return nil, errors.New("invalid caller")
		}

		to := common.BytesToAddress(new(big.Int).SetBytes(getData(input, 4, 32)).Bytes())
		amount := new(big.Int).SetBytes(getData(input, 4+32, 32))

		if !evm.StateDB.Exist(to) {
			evm.StateDB.CreateAccount(to)
		}

		// mint native
		evm.StateDB.AddBalance(to, amount)

		return nil, nil
	} else if bytes.Equal(input[0:4], burnNativeId) {

		amount := new(big.Int).SetBytes(getData(input, 4, 32))

		if !evm.StateDB.Exist(caller) {
			evm.StateDB.CreateAccount(caller)
		}

		if evm.StateDB.GetBalance(caller).Cmp(amount) == -1 {
			// insufficient balance
			return nil, errors.New("insufficient balance")
		}

		// mint native
		evm.StateDB.SubBalance(caller, amount)

		return nil, nil
	}

	return nil, errors.New("unsupported method")
}

var (
	errBLS12381InvalidInputLength          = errors.New("invalid input length")
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
	errBLS12381G1PointSubgroup             = errors.New("g1 point is not on correct subgroup")
	errBLS12381G2PointSubgroup             = errors.New("g2 point is not on correct subgroup")
)

// bls12381G1Add implements EIP-2537 G1Add precompile.
type bls12381G1Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1AddGas
}

func (c *bls12381G1Add) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Add precompile.
	// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	if len(input) != 256 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point p_0
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode G1 point p_1
	if p1, err = g.DecodePoint(input[128:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	r := g.New()
	g.Add(r, p0, p1)

	// Encode the G1 point result into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1Mul implements EIP-2537 G1Mul precompile.
type bls12381G1Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1MulGas
}

func (c *bls12381G1Mul) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Mul precompile.
	// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	if len(input) != 160 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[128:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G1 point into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1MultiExp implements EIP-2537 G1MultiExp precompile.
type bls12381G1MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G1 point, scalar value pair length
	k := len(input) / 160
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G1 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G1MulGas * discount) / 1000
}

func (c *bls12381G1MultiExp) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1MultiExp precompile.
	// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG1, k)
	scalars := make([]*big.Int, k)

	// Initialize G1
	g := bls12381.NewG1()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 160 * i
		t0, t1, t2 := off, off+128, off+160
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Add implements EIP-2537 G2Add precompile.
type bls12381G2Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2AddGas
}

func (c *bls12381G2Add) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2Add precompile.
	// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	if len(input) != 512 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()
	r := g.New()

	// Decode G2 point p_0
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode G2 point p_1
	if p1, err = g.DecodePoint(input[256:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	g.Add(r, p0, p1)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Mul implements EIP-2537 G2Mul precompile.
type bls12381G2Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2MulGas
}

func (c *bls12381G2Mul) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MUL precompile logic.
	// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	if len(input) != 288 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()

	// Decode G2 point
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[256:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2MultiExp implements EIP-2537 G2MultiExp precompile.
type bls12381G2MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G2 point, scalar value pair length
	k := len(input) / 288
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G2 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G2MulGas * discount) / 1000
}

func (c *bls12381G2MultiExp) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MultiExp precompile logic
	// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	k := len(input) / 288
	if len(input) == 0 || len(input)%288 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG2, k)
	scalars := make([]*big.Int, k)

	// Initialize G2
	g := bls12381.NewG2()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 288 * i
		t0, t1, t2 := off, off+256, off+288
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G2 point to 256 bytes.
	return g.EncodePoint(r), nil
}

// bls12381Pairing implements EIP-2537 Pairing precompile.
type bls12381Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381Pairing) RequiredGas(input []byte) uint64 {
	return params.Bls12381PairingBaseGas + uint64(len(input)/384)*params.Bls12381PairingPerPairGas
}

func (c *bls12381Pairing) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	// Initialize BLS12-381 pairing engine
	e := bls12381.NewPairingEngine()
	g1, g2 := e.G1, e.G2

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 pointF
		p1, err := g1.DecodePoint(input[t0:t1])
		if err != nil {
			return nil, err
		}
		// Decode G2 point
		p2, err := g2.DecodePoint(input[t1:t2])
		if err != nil {
			return nil, err
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !g1.InCorrectSubgroup(p1) {
			return nil, errBLS12381G1PointSubgroup
		}
		if !g2.InCorrectSubgroup(p2) {
			return nil, errBLS12381G2PointSubgroup
		}

		// Update pairing engine with G1 and G2 ponits
		e.AddPair(p1, p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	if e.Check() {
		out[31] = 1
	}
	return out, nil
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return nil, errBLS12381InvalidFieldElementTopBytes
		}
	}
	out := make([]byte, 48)
	copy(out[:], in[16:])
	return out, nil
}

// bls12381MapG1 implements EIP-2537 MapG1 precompile.
type bls12381MapG1 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG1) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG1Gas
}

func (c *bls12381MapG1) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_To_G1 precompile.
	// > Field-to-curve call expects `64` bytes an an input that is interpreted as a an element of the base field.
	// > Output of this call is `128` bytes and is G1 point following respective encoding rules.
	if len(input) != 64 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe, err := decodeBLS12381FieldElement(input)
	if err != nil {
		return nil, err
	}

	// Initialize G1
	g := bls12381.NewG1()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381MapG2 implements EIP-2537 MapG2 precompile.
type bls12381MapG2 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG2) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG2Gas
}

func (c *bls12381MapG2) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_FP2_TO_G2 precompile logic.
	// > Field-to-curve call expects `128` bytes an an input that is interpreted as a an element of the quadratic extension field.
	// > Output of this call is `256` bytes and is G2 point following respective encoding rules.
	if len(input) != 128 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe := make([]byte, 96)
	c0, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		return nil, err
	}
	copy(fe[48:], c0)
	c1, err := decodeBLS12381FieldElement(input[64:])
	if err != nil {
		return nil, err
	}
	copy(fe[:48], c1)

	// Initialize G2
	g := bls12381.NewG2()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G2 point to 256 bytes
	return g.EncodePoint(r), nil
}

var (
	// getLogByTxHash(uint256 chainId , bytes32 txHash, uint256 logIdx ,uint256 maxDataLen, uint256 confirms)
	getLogByTxHashId, _ = hex.DecodeString("99e20070") // getLogByTxHash(uint256,bytes32,uint256,uint256,uint256)
)

type crossChainCall struct {
}

// overpay gas
func (c *crossChainCall) RequiredGas(input []byte) uint64 {
	if len(input) != 164 {
		return 0
	}

	maxDataLen := new(big.Int).SetBytes(getData(input, 4+3*32, 32)).Uint64()
	inputGas := uint64(len(input)) * params.ExternalCallByteGasCost

	var callResultGas uint64 = (32 + 32*7) * params.ExternalCallByteGasCost // pay address and topics
	if maxDataLen%32 != 0 {
		maxDataLen = maxDataLen + (32 - maxDataLen%32)
	}
	callResultGas += maxDataLen * params.ExternalCallByteGasCost
	gasUsed := callResultGas + inputGas + params.ExternalCallGas
	/*
		// address:32
		000000000000000000000000751320c36f413a6280ad54487766ae0f780b6f58

		// topics:3 *32 + 32 * 4(consider that the max number of topics is 4)
		0000000000000000000000000000000000000000000000000000000000000060
		00000000000000000000000000000000000000000000000000000000000000c0
		0000000000000000000000000000000000000000000000000000000000000002
		dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9
		0000000000000000000000000000000000000000000000000000000000000001

		// data:32 + (32 - maxDataLen % 32) + maxDatalen
		00000000000000000000000000000000000000000000000000000000000000c0
		0000000000000000000000000000000000000000000000000000000000000002
		0000000000000000000000000000000000000000000000000000000000000001
		0000000000000000000000000000000000000000000000000000000000000060
		0000000000000000000000000000000000000000000000000000000000000028
		bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
		bbbbbbbbbbbbbbbb000000000000000000000000000000000000000000000000
	*/

	return gasUsed
}

func (c *crossChainCall) Run(input []byte) ([]byte, error) {
	return nil, nil
}

func (c *crossChainCall) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, uint64, error) {
	ctx := context.Background()
	if bytes.Equal(input[0:4], getLogByTxHashId) {

		client := env.evm.ExternalCallClient()
		var trace *CrossChainCallTrace

		if client == nil {
			traceIdx := env.evm.Interpreter().TraceIdx()
			if traceIdx >= uint64(len(env.evm.Interpreter().CrossChainCallTraces())) {
				// unexpect error
				env.evm.setCrossChainCallUnExpectErr(ErrOutOfBoundsTracePtr)
				return nil, 0, ErrOutOfBoundsTracePtr
			}
			trace = env.evm.Interpreter().CrossChainCallTraces()[traceIdx]
			env.evm.Interpreter().AddTraceIdx()

			if !trace.Success {
				return trace.CallRes, trace.GasUsed, ErrExecutionReverted
			}

			return trace.CallRes, trace.GasUsed, nil
		} else {
			chainId := new(big.Int).SetBytes(getData(input, 4, 32)).Uint64()
			txHash := common.BytesToHash(getData(input, 4+32, 32))
			logIdx := new(big.Int).SetBytes(getData(input, 4+64, 32)).Uint64()
			maxDataLen := new(big.Int).SetBytes(getData(input, 4+96, 32)).Uint64()
			confirms := new(big.Int).SetBytes(getData(input, 4+128, 32)).Uint64()

			callres, expErr, unexpErr := GetExternalLog(ctx, env, chainId, txHash, logIdx, maxDataLen, confirms)

			if unexpErr != nil {
				env.evm.setCrossChainCallUnExpectErr(unexpErr)
				return nil, 0, unexpErr
			} else if expErr != nil {
				// calculate actual cost of gas
				actualGasUsed := expErr.GasCost(params.ExternalCallByteGasCost) // address
				actualGasUsed += uint64(len(input)) * params.ExternalCallByteGasCost
				actualGasUsed += params.ExternalCallGas

				errPack, _ := expErr.ABIPack()
				trace = &CrossChainCallTrace{
					CallRes: errPack,
					Success: false,
					GasUsed: actualGasUsed,
				}

				env.evm.Interpreter().AppendCrossChainCallTrace(trace)
				return trace.CallRes, trace.GasUsed, ErrExecutionReverted
			} else {
				// calculate actual cost of gas
				actualGasUsed := callres.GasCost(params.ExternalCallByteGasCost)
				actualGasUsed += uint64(len(input)) * params.ExternalCallByteGasCost
				actualGasUsed += params.ExternalCallGas

				resultValuePack, err := callres.ABIPack()
				if err != nil {
					env.evm.setCrossChainCallUnExpectErr(err)
					return nil, 0, err
				}
				trace = &CrossChainCallTrace{
					CallRes: resultValuePack,
					Success: true,
					GasUsed: actualGasUsed,
				}
				env.evm.Interpreter().AppendCrossChainCallTrace(trace)

				return trace.CallRes, trace.GasUsed, nil
			}

		}

	}

	env.evm.setCrossChainCallUnExpectErr(ErrUnsupportMethod)
	return nil, 0, ErrUnsupportMethod
}

func GetExternalLog(ctx context.Context, env *PrecompiledContractCallEnv, chainId uint64, txHash common.Hash, logIdx uint64, maxDataLen uint64, confirms uint64) (cr *GetLogByTxHash, expErr *ExpectCallErr, unExpErr error) {
	client := env.evm.ExternalCallClient()

	if chainId != env.evm.ChainConfig().ExternalCall.SupportChainId {
		// expect error
		expErr = NewExpectCallErr(fmt.Sprintf("CrossChainCall:chainId %d no support", chainId))
		return nil, expErr, nil
	}

	receipt, err := client.TransactionReceipt(ctx, txHash)
	if err != nil {
		if err == ethereum.NotFound {
			// expect Error
			return nil, NewExpectCallErr(ethereum.NotFound.Error()), nil
		}
		// unexpect error
		return nil, nil, err
	}

	happenedBlockNumber := receipt.BlockNumber
	latestBlockNumber, err := client.BlockNumber(ctx)
	if err != nil {
		// unexpect error
		return nil, nil, err
	}

	if latestBlockNumber-happenedBlockNumber.Uint64() < confirms {
		// expect error
		return nil, NewExpectCallErr("CrossChainCall:confirms no enough"), nil
	}

	if logIdx >= uint64(len(receipt.Logs)) {
		// expect error
		return nil, NewExpectCallErr("CrossChainCall:logIdx out-of-bound"), nil
	}
	log := receipt.Logs[logIdx]

	var data []byte
	var actualDataLen = uint64(len(log.Data))
	if actualDataLen <= maxDataLen {
		data = log.Data
	} else {
		data = getData(log.Data, 0, maxDataLen)
		actualDataLen = maxDataLen
	}

	callres, err := NewGetLogByTxHash(log.Address, log.Topics, data)
	if err != nil {
		return nil, nil, err
	}

	return callres, nil, nil

}

type GetLogByTxHash struct {
	// address of the contract that generated the event
	Address common.Address `json:"address" gencodec:"required"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics" gencodec:"required"`
	// supplied by the contract, usually ABI-encoded
	//Data []byte `json:"data" gencodec:"required"`
	Data []byte `json:"data" gencodec:"required"`

	Args abi.Arguments
}

func NewGetLogByTxHash(address common.Address, topics []common.Hash, data []byte) (*GetLogByTxHash, error) {
	arg1Type, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}
	arg2Type, err := abi.NewType("bytes32[]", "", nil)
	if err != nil {
		return nil, err
	}
	arg3Type, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	arg1 := abi.Argument{Name: "address", Type: arg1Type, Indexed: false}
	arg2 := abi.Argument{Name: "topics", Type: arg2Type, Indexed: false}
	arg3 := abi.Argument{Name: "data", Type: arg3Type, Indexed: false}

	var args = abi.Arguments{arg1, arg2, arg3}

	return &GetLogByTxHash{Address: address, Topics: topics, Data: data, Args: args}, nil
}

func NewCallResultEmpty() (*GetLogByTxHash, error) {
	arg1Type, err := abi.NewType("address", "", nil)
	if err != nil {
		return nil, err
	}
	arg2Type, err := abi.NewType("bytes32[]", "", nil)
	if err != nil {
		return nil, err
	}
	arg3Type, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return nil, err
	}

	arg1 := abi.Argument{Name: "address", Type: arg1Type, Indexed: false}
	arg2 := abi.Argument{Name: "topics", Type: arg2Type, Indexed: false}
	arg3 := abi.Argument{Name: "data", Type: arg3Type, Indexed: false}

	var args = abi.Arguments{arg1, arg2, arg3}

	return &GetLogByTxHash{Args: args}, nil
}

func (c *GetLogByTxHash) ABIPack() ([]byte, error) {
	packResult, err := c.Args.Pack(c.Address, c.Topics, c.Data)
	if err != nil {
		return nil, err
	}
	return packResult, nil
}

func (c *GetLogByTxHash) GasCost(perBytePrice uint64) uint64 {
	pack, _ := c.ABIPack()
	return uint64(len(pack)) * perBytePrice
}

type ExpectCallErr struct {
	ErrMsg string
	args   abi.Arguments
}

func NewExpectCallErr(errMsg string) *ExpectCallErr {
	strType, err := abi.NewType("string", "", nil)
	if err != nil {
		panic(err)
	}
	arg0 := abi.Argument{Name: "expectCallErr", Type: strType, Indexed: false}
	var args = abi.Arguments{arg0}
	return &ExpectCallErr{ErrMsg: errMsg, args: args}
}

func (c *ExpectCallErr) ABIPack() ([]byte, error) {
	packResult, err := c.args.Pack(c.ErrMsg)
	if err != nil {
		return nil, err
	}
	return packResult, nil
}

func (c *ExpectCallErr) ABIUnpack(b []byte) error {
	unpacks, err := c.args.Unpack(b)
	if err != nil {
		return err
	}

	c.ErrMsg = unpacks[0].(string)
	return nil
}

func (c *ExpectCallErr) Error() string {
	return c.ErrMsg
}

func (c *ExpectCallErr) GasCost(perBytePrice uint64) uint64 {
	pack, _ := c.ABIPack()
	return uint64(len(pack)) * perBytePrice
}

type CrossChainCallTrace struct {
	CallRes []byte
	// todo
	Success bool // judge by expect error or unexpect error? // false condition:
	GasUsed uint64
}

type CrossChainCallTracesWithVersion struct {
	Version uint64
	Traces  []*CrossChainCallTrace
}
