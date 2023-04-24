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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/sstorage"

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
	RunWith(env *PrecompiledContractCallEnv, input []byte, prepayGas uint64) ([]byte, uint64, error)
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
	common.BytesToAddress([]byte{1}):             &ecrecover{},
	common.BytesToAddress([]byte{2}):             &sha256hash{},
	common.BytesToAddress([]byte{3}):             &ripemd160hash{},
	common.BytesToAddress([]byte{4}):             &dataCopy{},
	common.BytesToAddress([]byte{5}):             &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):             &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):             &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):             &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):             &blake2F{},
	common.BytesToAddress([]byte{3, 0x33, 1}):    &systemContractDeployer{},
	common.BytesToAddress([]byte{3, 0x33, 2}):    &sstoragePisaPutRaw{},
	common.BytesToAddress([]byte{3, 0x33, 3}):    &sstoragePisaGetRaw{},
	common.BytesToAddress([]byte{3, 0x33, 4}):    &sstoragePisaUnmaskDaggerData{},
	common.BytesToAddress([]byte{3, 0x33, 0x21}): &crossChainCall{},
	common.BytesToAddress([]byte{3, 0x33, 0x22}): &tokenIssuer{},
	common.BytesToAddress([]byte{3, 0x33, 0x23}): &tokenBurner{},
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
		ret, actualGasUsed, err = pw.RunWith(env, input, gasCost)
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
//
//	if x <= 64: return x ** 2
//	elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//	else: return x ** 2 // 16 + 480 * x - 199680
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
		// where is x is max(length_of_MODULUS, length_of_BASE)
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

var (
	tokenManager = common.HexToAddress("0x0000000000000000000000000000000003330002")
	// Get the url of PrecompileManager: https://github.com/ethstorage/storage-contracts/blob/developing/contracts/PrecompileManager.sol
	// contract at 0x0000000000000000000000000000000003330001 is complied PrecompileManager() + 0.8.16 solc (enable optimized)
	systemContracts = map[common.Address][]byte{
		// Get the url of PrecompileManager: https://github.com/ethstorage/storage-contracts/blob/developing/contracts/DecentralizedKVDaggerHashimoto.sol
		// contract at 0x0000000000000000000000000000000003330001 is complied DecentralizedKVDaggerHashimoto() + 0.8.16 solc (enable optimized)
		common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("60806040526004361061025c5760003560e01c8063749cf28211610144578063b1e1a344116100b6578063d32897131161007a578063d32897131461091c578063d4044b3314610950578063dca0051114610984578063dd7e57d4146109a7578063df80ca55146109be578063e7a84c46146109d357600080fd5b8063b1e1a34414610854578063b2aebe8814610874578063c4a942cb14610894578063c5d3490c146108c8578063ca2af623146108fc57600080fd5b8063896b499111610108578063896b49911461071f578063919c6eae1461073657806395bc26731461076a578063a097365f1461078a578063a4a8435e146107be578063afd5644d146107f257600080fd5b8063749cf2821461063d57806378e979251461066a578063812d2e721461069e5780638612af34146106d25780638891ce9c146106ff57600080fd5b8063429dd7ad116101dd5780636620dfc5116101a15780636620dfc5146104e45780636cece5f8146105185780636d951bc5146105385780636da6d51e1461056c578063739b482f1461059b57806373e8b3d4146105cf57600080fd5b8063429dd7ad1461041557806344e77d991461044957806349bdd6f51461045c5780634e86235e1461047c57806354b02ba4146104b057600080fd5b8063258ae58211610224578063258ae5821461032957806327c845dc146102f257806328de3c9b14610349578063390df0b6146103ad5780633cb2fecc146103e157600080fd5b806304cbaa51146102615780630fce307b1461029057806315853983146102d25780631aff59e2146102f45780631ccbc6da14610314575b600080fd5b34801561026d57600080fd5b5060045461027b9060ff1681565b60405190151581526020015b60405180910390f35b34801561029c57600080fd5b506102c47f6387d10d3fe6d4fcb51c9f9caf0c34f88526afc3d0c6a2b80adfceeea2b4a70181565b604051908152602001610287565b3480156102de57600080fd5b506102f26102ed366004612b7d565b6109ea565b005b34801561030057600080fd5b506102f261030f366004612c8b565b610a03565b34801561032057600080fd5b506102c4610b04565b34801561033557600080fd5b5061027b610344366004612cad565b610b14565b34801561035557600080fd5b5061038d610364366004612cf3565b600360208190526000918252604090912080546001820154600283015492909301549092919084565b604080519485526020850193909352918301526060820152608001610287565b3480156103b957600080fd5b506102c47fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e681565b3480156103ed57600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000000081565b34801561042157600080fd5b506000546104339064ffffffffff1681565b60405164ffffffffff9091168152602001610287565b6102f2610457366004612cad565b610c40565b34801561046857600080fd5b506102f2610477366004612d0c565b610e70565b34801561048857600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000001181565b3480156104bc57600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000002881565b3480156104f057600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000000581565b34801561052457600080fd5b506102f2610533366004612d51565b61109e565b34801561054457600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000006481565b34801561057857600080fd5b506105836203330281565b6040516001600160a01b039091168152602001610287565b3480156105a757600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000040081565b3480156105db57600080fd5b5061027b6105ea366004612cf3565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b34801561064957600080fd5b5061065d610658366004612da7565b611168565b6040516102879190612e23565b34801561067657600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000000181565b3480156106aa57600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000012c81565b3480156106de57600080fd5b506106e7600281565b6040516001600160401b039091168152602001610287565b34801561070b57600080fd5b5061065d61071a366004612e36565b611279565b34801561072b57600080fd5b506105836203330581565b34801561074257600080fd5b506102c47f00000000000000000000000000000000000000000000000000000000000003e881565b34801561077657600080fd5b506102f2610785366004612cf3565b611372565b34801561079657600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000002000081565b3480156107ca57600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000000081565b3480156107fe57600080fd5b506102c461080d366004612cf3565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b34801561086057600080fd5b5061027b61086f366004612e6f565b61137f565b34801561088057600080fd5b506102f261088f366004612c8b565b6115a1565b3480156108a057600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000100081565b3480156108d457600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000000a81565b34801561090857600080fd5b5061065d610917366004612f42565b61166f565b34801561092857600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000001081565b34801561095c57600080fd5b506102c47f000000000000000000000000000000000000000000000000000000000000001b81565b34801561099057600080fd5b5061065d61099f366004612cad565b606092915050565b3480156109b357600080fd5b506105836203330381565b3480156109ca57600080fd5b506102c4611755565b3480156109df57600080fd5b506105836203330481565b6109fa4288888888888888611799565b50505050505050565b60045460ff1615610a5b5760405162461bcd60e51b815260206004820152601960248201527f616c726561647920696e697469616c697a65642073686172640000000000000060448201526064015b60405180910390fd5b6004805460ff1916600190811790915560036020527f3617319a054d772f909f7c479a2cebe5066e836a939412e32403c99029b92f008390557f3617319a054d772f909f7c479a2cebe5066e836a939412e32403c99029b92eff8290556000527fa15bc60c955c405d20d9149c709e2460f1c2d9a497496a7f46004d1772c3054d919091557fa15bc60c955c405d20d9149c709e2460f1c2d9a497496a7f46004d1772c3054c55565b6000610b0f426118d0565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610bcd5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b6044820152606401610a52565b8351816020015162ffffff1614610be957600092505050610c38565b6000610c15857f0000000000000000000000000000000000000000000000000000000000001000611925565b9050806001600160401b03191682604001516001600160401b0319161493505050505b92915050565b565b7f000000000000000000000000000000000000000000000000000000000002000081511115610ca25760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b6044820152606401610a52565b610caa611b56565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610dbf57610d32610b04565b341015610d765760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b6044820152606401610a52565b6000805464ffffffffff90811680845282526002602052604082208490559054610da291166001612fb9565b6000805464ffffffffff191664ffffffffff929092169190911790555b825162ffffff166020820152610df5837f0000000000000000000000000000000000000000000000000000000000001000611925565b67ffffffffffffffff19908116604080840191825260008581526001602090815290829020855181549287015194519384901c600160401b0262ffffff909516600160281b029290951664ffffffffff909516948517919091176001600160401b031692909217909155610e6a91908561109e565b50505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff191693850184905290945090919003610f2b5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b6044820152606401610a52565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff96871617919091176001600160401b031617909255805490926002928492610faf9216612fde565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff1916909117905581549095509093849261100d9216612fde565b64ffffffffff90811682526020820192909252604001600090812092909255905461103b9160019116612fde565b6000805464ffffffffff191664ffffffffff9283169081179091556110619184166115a1565b846001600160a01b03166108fc611076610b04565b6040518115909202916000818181858888f193505050501580156109fa573d6000803e3d6000fd5b604080519083901c9060009062033302906110c190879085908790602001612ffc565b60408051601f19818403018152908290526110db91613024565b6000604051808303816000865af19150503d8060008114611118576040519150601f19603f3d011682016040523d82523d6000602084013e61111d565b606091505b50509050806111615760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2070757452617760801b6044820152606401610a52565b5050505050565b6060816000036111875750604080516000815260208101909152611272565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff19169284019290925290925085106112205750506040805160008152602081019091529050611272565b602081015162ffffff166112348686613040565b11156112525784816020015162ffffff1661124f9190613053565b93505b61126d8160400151826000015164ffffffffff168787611279565b925050505b9392505050565b6040805185821c6020820181905291810185905260608082018590526080820184905291906000908190620333039060a00160408051601f19818403018152908290526112c591613024565b600060405180830381855afa9150503d8060008114611300576040519150601f19603f3d011682016040523d82523d6000602084013e611305565b606091505b5091509150816113505760405162461bcd60e51b81526020600482015260166024820152756661696c656420746f2073797374656d47657452617760501b6044820152606401610a52565b808060200190518101906113649190613066565b93505050505b949350505050565b61137c8133610e70565b50565b600060017f00000000000000000000000000000000000000000000000000000000000000051b816113b082886130e9565b90506000866020015162ffffff167f0000000000000000000000000000000000000000000000000000000000001000836113ea91906130fd565b10611423577fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e6858051906020012014935050505061136a565b817f000000000000000000000000000000000000000000000000000000000000100060018960200151611456919061311c565b62ffffff166114659190613138565b036115685760006114967f0000000000000000000000000000000000000000000000000000000000001000846130fd565b886020015162ffffff166114aa9190613053565b602087018190209250905060006114e1827f0000000000000000000000000000000000000000000000000000000000001000613053565b90508015611561576000816001600160401b038111156115035761150361298a565b6040519080825280601f01601f19166020018201604052801561152d576020820181803683370190505b5090506000808360208401209150838560208c010120905080821461155d5760009850505050505050505061136a565b5050505b5050611571565b50835160208501205b600061157e828489611b5f565b604089015167ffffffffffffffff19918216911614945050505050949350505050565b6040805160208101849052908101829052600090620333059060600160408051601f19818403018152908290526115d791613024565b6000604051808303816000865af19150503d8060008114611614576040519150601f19603f3d011682016040523d82523d6000602084013e611619565b606091505b505090508061166a5760405162461bcd60e51b815260206004820152601960248201527f6661696c656420746f2073797374656d52656d6f7665526177000000000000006044820152606401610a52565b505050565b6040805160609185901c906000908190620333049061169b906002908b9087908b908b9060200161314c565b60408051601f19818403018152908290526116b591613024565b600060405180830381855afa9150503d80600081146116f0576040519150601f19603f3d011682016040523d82523d6000602084013e6116f5565b606091505b5091509150816113505760405162461bcd60e51b815260206004820152602560248201527f6661696c656420746f2073797374656d556e6d61736b4368756e6b57697468456044820152640e8d0c2e6d60db1b6064820152608401610a52565b6000805461178d9064ffffffffff167f000000000000000000000000000000000000000000000000000000000000000a1c6001612fb9565b64ffffffffff16905090565b878411156117dd5760405162461bcd60e51b81526020600482015260116024820152706d696e6564547320746f6f206c6172676560781b6044820152606401610a52565b6001861b600080806117f08b858a611c93565b604080516020808201939093526001600160a01b038e1681830152606081018d905260808082018d90528251808303909101815260a09091019091528051910120919450925090506118468b8b838c8a8a611e7d565b9050600061185684600019613138565b905060006118638361224a565b61186c8361224a565b60405160200161187d929190613199565b60408051601f19818403018152919052905080828411156118b15760405162461bcd60e51b8152600401610a529190612e23565b5050506118c28b858b8b86866122a1565b505050505050505050505050565b6000610c387f00000000000000000000000000000000000000000000000000000000000000006119207f000000000000000000000000000000000000000000000000000000000000000185613053565b612443565b6000825160000361193857506000610c38565b600082600184865161194a9190613040565b6119549190613053565b61195e9190613138565b9050600060018211156119795761197482612484565b61197c565b60015b90506000816001600160401b038111156119985761199861298a565b6040519080825280602002602001820160405280156119c1578160200160208202803683370190505b50905060005b82811015611a47576000806119dc88846130fd565b9050885181106119ed575050611a47565b6000818a516119fc9190613053565b9050888110611a085750875b808260208c010120925082858581518110611a2557611a25613205565b6020026020010181815250505050508080611a3f9061321b565b9150506119c7565b508192505b82600114611b305760005b611a62600285613138565b811015611b1d5781611a758260026130fd565b81518110611a8557611a85613205565b602002602001015182826002611a9b91906130fd565b611aa6906001613040565b81518110611ab657611ab6613205565b6020026020010151604051602001611ad8929190918252602082015260400190565b60405160208183030381529060405280519060200120828281518110611b0057611b00613205565b602090810291909101015280611b158161321b565b915050611a57565b50611b29600284613138565b9250611a4c565b80600081518110611b4357611b43613205565b6020026020010151935050505092915050565b610c3e426124c1565b805160009084906001811b8510611bac5760405162461bcd60e51b81526020600482015260116024820152706368756e6b4964206f766572666c6f777360781b6044820152606401610a52565b60005b81811015611c8857611bc26002876130e9565b600003611c1b5782858281518110611bdc57611bdc613205565b6020026020010151604051602001611bfe929190918252602082015260400190565b604051602081830303815290604052805190602001209250611c69565b848181518110611c2d57611c2d613205565b602002602001015183604051602001611c50929190918252602082015260400190565b6040516020818303038152906040528051906020012092505b611c74600287613138565b955080611c808161321b565b915050611baf565b509095945050505050565b600060606000846001600160401b03811115611cb157611cb161298a565b604051908082528060200260200182016040528015611cda578160200160208202803683370190505b50600093509150829050805b85811015611e73576000611cfa8289613040565b6000818152600360205260409020600181015491925090871015611d545760405162461bcd60e51b81526020600482015260116024820152701b5a5b9959151cc81d1bdbc81cdb585b1b607a1b6044820152606401610a52565b611de281887f000000000000000000000000000000000000000000000000000000000000012c7f00000000000000000000000000000000000000000000000000000000000000287f00000000000000000000000000000000000000000000000000000000000004007f00000000000000000000000000000000000000000000000000000000000000646125b4565b858481518110611df457611df4613205565b602002602001018181525050848381518110611e1257611e12613205565b602002602001015186611e259190613040565b81546040805160208101889052908101859052606081019190915290965060800160405160208183030381529060405280519060200120935050508080611e6b9061321b565b915050611ce6565b5093509350939050565b60007f0000000000000000000000000000000000000000000000000000000000000010825114611eef5760405162461bcd60e51b815260206004820152601f60248201527f6461746120767320636865636b733a206c656e677468206d69736d61746368006044820152606401610a52565b7f0000000000000000000000000000000000000000000000000000000000000010835114611f695760405162461bcd60e51b815260206004820152602160248201527f70726f6f667320767320636865636b733a206c656e677468206d69736d6174636044820152600d60fb1b6064820152608401610a52565b60007f0000000000000000000000000000000000000000000000000000000000000005611fb6887f000000000000000000000000000000000000000000000000000000000000000a613040565b611fc09190613040565b6001901b905060005b7f000000000000000000000000000000000000000000000000000000000000001081101561223d5760007f000000000000000000000000000000000000000000000000000000000000100090508085838151811061202957612029613205565b602002602001015151146120745760405162461bcd60e51b8152602060048201526012602482015271696e76616c69642070726f6f662073697a6560701b6044820152606401610a52565b6000612080848a6130e9565b905060006120ce7f00000000000000000000000000000000000000000000000000000000000000057f000000000000000000000000000000000000000000000000000000000000000a613040565b6120db908d901b83613040565b7f000000000000000000000000000000000000000000000000000000000000000581901c6000818152600260209081526040808320548352600182528083208151606081018352905464ffffffffff81168252600160281b810462ffffff1693820193909352600160401b909204811b67ffffffffffffffff19169082018190528b519495509293909261218d918691908f908e908c90811061218057612180613205565b602002602001015161166f565b90506121b484838d8a815181106121a6576121a6613205565b60200260200101518461137f565b6121f75760405162461bcd60e51b815260206004820152601460248201527334b73b30b634b21030b1b1b2b9b990383937b7b360611b6044820152606401610a52565b60008a888151811061220b5761220b613205565b602002602001015190508d81526020870181209d508681525050505050505080806122359061321b565b915050611fc9565b5094979650505050505050565b6060816000036122745750506040805180820190915260048152630307830360e41b602082015290565b8160005b811561229757806122888161321b565b915050600882901c9150612278565b61136a8482612682565b6000806122ac611755565b905060005b878110156123875760006122c5828b613040565b9050828111612374576000818152600360205260409020600181015461232f907f00000000000000000000000000000000000000000000000000000000000000007f000000000000000000000000000000000000000000000000000000000000000a1b908a61281d565b6123399086613040565b9450612372600360008481526020019081526020016000208989868151811061236457612364613205565b60200260200101518961287c565b505b508061237f8161321b565b9150506122b1565b5060006127106123b77f00000000000000000000000000000000000000000000000000000000000003e8856130fd565b6123c19190613138565b905060006123cf8285613053565b604051909150419083156108fc029084906000818181858888f193505050501580156123ff573d6000803e3d6000fd5b506040516001600160a01b0389169082156108fc029083906000818181858888f19350505050158015612436573d6000803e3d6000fd5b5050505050505050505050565b600060806124717f0000000000000000000000000000000000000000000000000000000000000000846128a0565b61247b90856130fd565b901c9392505050565b6000612491600183613053565b91505b61249f600183613053565b8216156124ba576124b1600183613053565b82169150612494565b5060011b90565b60005460017f000000000000000000000000000000000000000000000000000000000000000a81901b916124fe9164ffffffffff90911690612fb9565b64ffffffffff1661250f91906130e9565b60000361137c57600080547f000000000000000000000000000000000000000000000000000000000000000a9061254e9064ffffffffff166001612fb9565b64ffffffffff16901c60016125639190612fb9565b64ffffffffff16600081815260036020819052604082206001908101869055929350916125909084613053565b81526020808201929092526040908101600090812054938152600390925290205550565b6000808760010154876125c79190613053565b60028901549091508682101561261e5784816125e38885613138565b6125ee906001613053565b6125f891906130fd565b6126029190613138565b61260c9082613040565b9050838110156126195750825b612676565b60008582600161262e8a87613138565b6126389190613053565b61264291906130fd565b61264c9190613138565b9050816126598683613040565b111561266757849150612674565b6126718183613053565b91505b505b98975050505050505050565b606060006126918360026130fd565b61269c906002613040565b6001600160401b038111156126b3576126b361298a565b6040519080825280601f01601f1916602001820160405280156126dd576020820181803683370190505b509050600360fc1b816000815181106126f8576126f8613205565b60200101906001600160f81b031916908160001a905350600f60fb1b8160018151811061272757612727613205565b60200101906001600160f81b031916908160001a905350600061274b8460026130fd565b612756906001613040565b90505b60018111156127ce576f181899199a1a9b1b9c1cb0b131b232b360811b85600f166010811061278a5761278a613205565b1a60f81b8282815181106127a0576127a0613205565b60200101906001600160f81b031916908160001a90535060049490941c936127c781613234565b9050612759565b5083156112725760405162461bcd60e51b815260206004820181905260248201527f537472696e67733a20686578206c656e67746820696e73756666696369656e746044820152606401610a52565b600061136a8461284d7f000000000000000000000000000000000000000000000000000000000000000186613053565b6128777f000000000000000000000000000000000000000000000000000000000000000186613053565b6128ac565b600384015461288c906001613040565b600385015583556002830155600190910155565b60006112728383612922565b600060806128da7f0000000000000000000000000000000000000000000000000000000000000000846128a0565b6129047f0000000000000000000000000000000000000000000000000000000000000000866128a0565b61290e9190613053565b61291890866130fd565b901c949350505050565b6000600160801b5b8215611272578260011660010361294c57608061294785836130fd565b901c90505b608061295885806130fd565b901c9350612967600284613138565b925061292a565b80356001600160a01b038116811461298557600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b604051606081016001600160401b03811182821017156129c2576129c261298a565b60405290565b604051601f8201601f191681016001600160401b03811182821017156129f0576129f061298a565b604052919050565b60006001600160401b03821115612a1157612a1161298a565b5060051b60200190565b600082601f830112612a2c57600080fd5b81356020612a41612a3c836129f8565b6129c8565b82815260059290921b84018101918181019086841115612a6057600080fd5b8286015b84811015612a7b5780358352918301918301612a64565b509695505050505050565b60006001600160401b03821115612a9f57612a9f61298a565b50601f01601f191660200190565b600082601f830112612abe57600080fd5b8135612acc612a3c82612a86565b818152846020838601011115612ae157600080fd5b816020850160208301376000918101602001919091529392505050565b600082601f830112612b0f57600080fd5b81356020612b1f612a3c836129f8565b82815260059290921b84018101918181019086841115612b3e57600080fd5b8286015b84811015612a7b5780356001600160401b03811115612b615760008081fd5b612b6f8986838b0101612aad565b845250918301918301612b42565b600080600080600080600060e0888a031215612b9857600080fd5b8735965060208801359550612baf6040890161296e565b9450606088013593506080880135925060a08801356001600160401b0380821115612bd957600080fd5b818a0191508a601f830112612bed57600080fd5b8135612bfb612a3c826129f8565b8082825260208201915060208360051b86010192508d831115612c1d57600080fd5b602085015b83811015612c56578481351115612c3857600080fd5b612c488f60208335890101612a1b565b835260209283019201612c22565b509550505060c08a0135915080821115612c6f57600080fd5b50612c7c8a828b01612afe565b91505092959891949750929550565b60008060408385031215612c9e57600080fd5b50508035926020909101359150565b60008060408385031215612cc057600080fd5b8235915060208301356001600160401b03811115612cdd57600080fd5b612ce985828601612aad565b9150509250929050565b600060208284031215612d0557600080fd5b5035919050565b60008060408385031215612d1f57600080fd5b82359150612d2f6020840161296e565b90509250929050565b803567ffffffffffffffff198116811461298557600080fd5b600080600060608486031215612d6657600080fd5b83359250612d7660208501612d38565b915060408401356001600160401b03811115612d9157600080fd5b612d9d86828701612aad565b9150509250925092565b600080600060608486031215612dbc57600080fd5b505081359360208301359350604090920135919050565b60005b83811015612dee578181015183820152602001612dd6565b50506000910152565b60008151808452612e0f816020860160208601612dd3565b601f01601f19169290920160200192915050565b6020815260006112726020830184612df7565b60008060008060808587031215612e4c57600080fd5b612e5585612d38565b966020860135965060408601359560600135945092505050565b60008060008084860360c0811215612e8657600080fd5b853594506060601f1982011215612e9c57600080fd5b50612ea56129a0565b602086013564ffffffffff81168114612ebd57600080fd5b8152604086013562ffffff81168114612ed557600080fd5b6020820152612ee660608701612d38565b6040820152925060808501356001600160401b0380821115612f0757600080fd5b612f1388838901612a1b565b935060a0870135915080821115612f2957600080fd5b50612f3687828801612aad565b91505092959194509250565b60008060008060808587031215612f5857600080fd5b84356001600160401b038082168214612f7057600080fd5b819550612f7f60208801612d38565b9450612f8d6040880161296e565b93506060870135915080821115612f2957600080fd5b634e487b7160e01b600052601160045260246000fd5b64ffffffffff818116838216019080821115612fd757612fd7612fa3565b5092915050565b64ffffffffff828116828216039080821115612fd757612fd7612fa3565b83815282602082015260606040820152600061301b6060830184612df7565b95945050505050565b60008251613036818460208701612dd3565b9190910192915050565b80820180821115610c3857610c38612fa3565b81810381811115610c3857610c38612fa3565b60006020828403121561307857600080fd5b81516001600160401b0381111561308e57600080fd5b8201601f8101841361309f57600080fd5b80516130ad612a3c82612a86565b8181528560208385010111156130c257600080fd5b61301b826020830160208601612dd3565b634e487b7160e01b600052601260045260246000fd5b6000826130f8576130f86130d3565b500690565b600081600019048311821515161561311757613117612fa3565b500290565b62ffffff828116828216039080821115612fd757612fd7612fa3565b600082613147576131476130d3565b500490565b6001600160401b03868116825285166020820152604081018490526001600160a01b038316606082015260a06080820181905260009061318e90830184612df7565b979650505050505050565b753234b333103737ba1036b0ba31b41d903430b9b4181d60511b8152600083516131ca816016850160208801612dd3565b6e10103932b8bab4b932b22234b3331d60891b60169184019182015283516131f9816025840160208801612dd3565b01602501949350505050565b634e487b7160e01b600052603260045260246000fd5b60006001820161322d5761322d612fa3565b5060010190565b60008161324357613243612fa3565b50600019019056fea26469706673582212204fca2ca323dc60ce2f3d4311cf00f0f33ac3b656154fcd642a749218f334557164736f6c63430008100033"),
		// Get the url of Web3qBridge: https://github.com/QuarkChain/staking-contracts/blob/cross_chain_event/contracts/token/Web3qBridge.sol
		// contract at 0x0000000000000000000000000000000003330002 is complied Web3qBridge  0.8.9 solc (enable optimized)
		tokenManager: common.Hex2Bytes("60806040526004361061009c5760003560e01c8063885b012e11610064578063885b012e146101455780638929268814610184578063cde5f63b1461019b578063dbc11758146101a3578063ee271935146101d2578063ee9277b1146101f257600080fd5b80632362e53a146100a15780632996f972146100de5780632f6af8cc146100f55780633ffe450814610118578063474d6dea1461012f575b600080fd5b3480156100ad57600080fd5b506000546100c1906001600160a01b031681565b6040516001600160a01b0390911681526020015b60405180910390f35b3480156100ea57600080fd5b506100c16203332381565b34801561010157600080fd5b5061010a600a81565b6040519081526020016100d5565b34801561012457600080fd5b506100c16203332181565b34801561013b57600080fd5b5061010a60025481565b34801561015157600080fd5b506101826101603660046106b8565b600080546001600160a01b0319166001600160a01b0392909216919091179055565b005b34801561019057600080fd5b506100c16203332281565b61018261023d565b3480156101af57600080fd5b506101c36101be3660046106dc565b610297565b6040516100d593929190610773565b3480156101de57600080fd5b506101826101ed3660046107dc565b61031f565b3480156101fe57600080fd5b5061022d61020d3660046107dc565b600160209081526000928352604080842090915290825290205460ff1681565b60405190151581526020016100d5565b61024733346104b3565b60028054906000610257836107fe565b90915550506002546040513481523391907fc838383de55ec352dbaa3387ea63cfc867d4bddf19389bce783dbde403459c769060200160405180910390a3565b60006060806000806102ac8a8a8a8a8a61055a565b91509150816102f0576000818060200190518101906102cb91906108bd565b90508060405162461bcd60e51b81526004016102e7919061090e565b60405180910390fd5b6000806000838060200190518101906103099190610941565b919f909e50909c509a5050505050505050505050565b600082815260016020908152604080832084845290915290205460ff16156103895760405162461bcd60e51b815260206004820152601a60248201527f746865206275726e206c6f6720686173206265656e207573656400000000000060448201526064016102e7565b600082815260016020818152604080842085855282528320805460ff1916909217909155819081906103c39060049087908790600a610297565b60005492955090935091506001600160a01b038085169116146104215760405162461bcd60e51b81526020600482015260166024820152750c6dedce8e4c2c6e840c2c8c8e440dcde40dac2e8c6d60531b60448201526064016102e7565b60008260018151811061043657610436610a20565b602002602001015160001c90506000828060200190518101906104599190610a36565b905061046582826105fe565b816001600160a01b031686887fea683109724089070580fcd9f3e5f4a7e585bd0eb900a9cdc15903d6e82445ec846040516104a291815260200190565b60405180910390a450505050505050565b604080516001600160a01b0384166020820152908101829052600090620333239060600160408051601f19818403018152908290526104f191610a4f565b6000604051808303816000865af19150503d806000811461052e576040519150601f19603f3d011682016040523d82523d6000602084013e610533565b606091505b50509050806105555760405163ac5ca12160e01b815260040160405180910390fd5b505050565b604080516020810187905290810185905260608181018590526080820184905260a08201839052600091829060c00160408051601f1981840301815290829052915062033321906105ac908390610a4f565b6000604051808303816000865af19150503d80600081146105e9576040519150601f19603f3d011682016040523d82523d6000602084013e6105ee565b606091505b5092509250509550959350505050565b604080516001600160a01b0384166020820152908101829052600090620333229060600160408051601f198184030181529082905261063c91610a4f565b6000604051808303816000865af19150503d8060008114610679576040519150601f19603f3d011682016040523d82523d6000602084013e61067e565b606091505b505090508061055557604051635caede6760e11b815260040160405180910390fd5b6001600160a01b03811681146106b557600080fd5b50565b6000602082840312156106ca57600080fd5b81356106d5816106a0565b9392505050565b600080600080600060a086880312156106f457600080fd5b505083359560208501359550604085013594606081013594506080013592509050565b60005b8381101561073257818101518382015260200161071a565b83811115610741576000848401525b50505050565b6000815180845261075f816020860160208601610717565b601f01601f19169290920160200192915050565b6001600160a01b038416815260606020808301829052845191830182905260009185820191906080850190845b818110156107bc578451835293830193918301916001016107a0565b505084810360408601526107d08187610747565b98975050505050505050565b600080604083850312156107ef57600080fd5b50508035926020909101359150565b600060001982141561082057634e487b7160e01b600052601160045260246000fd5b5060010190565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff8111828210171561086657610866610827565b604052919050565b600067ffffffffffffffff83111561088857610888610827565b61089b601f8401601f191660200161083d565b90508281528383830111156108af57600080fd5b6106d5836020830184610717565b6000602082840312156108cf57600080fd5b815167ffffffffffffffff8111156108e657600080fd5b8201601f810184136108f757600080fd5b6109068482516020840161086e565b949350505050565b6020815260006106d56020830184610747565b600082601f83011261093257600080fd5b6106d58383516020850161086e565b60008060006060848603121561095657600080fd5b8351610961816106a0565b8093505060208085015167ffffffffffffffff8082111561098157600080fd5b818701915087601f83011261099557600080fd5b8151818111156109a7576109a7610827565b8060051b6109b685820161083d565b918252838101850191858101908b8411156109d057600080fd5b948601945b838610156109ee578551825294860194908601906109d5565b60408b0151909850955050505080831115610a0857600080fd5b5050610a1686828701610921565b9150509250925092565b634e487b7160e01b600052603260045260246000fd5b600060208284031215610a4857600080fd5b5051919050565b60008251610a61818460208701610717565b919091019291505056fea2646970667358221220b1003dd9a162c1405348aa2ed55f52d945e62f6e81f49565728124e95cce688564736f6c63430008090033"),
	}
)

type systemContractDeployer struct{}

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

type sstoragePisaPutRaw struct {
}

func (s *sstoragePisaPutRaw) RequiredGas(input []byte) uint64 {
	return params.SstoreResetGasEIP2200
}

func (l *sstoragePisaPutRaw) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (l *sstoragePisaPutRaw) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {

	// The solidity code to generate input as follows:
	// function putRaw(uint256 kvIdx, bytes memory data) internal {
	//     (bool success, ) = address(sstoragePisaPutRaw).call(
	//         abi.encode(kvIdx, data)
	//      );
	//  }
	//
	// The generated input data format is as follows:
	// 0000000000000000000000000000000000000000000000000000000000000001 (kvIdx)
	// 0000000000000000000000000000000000000000000000000000000000001240 (kvHash low-24byte)
	// 0000000000000000000000000000000000000000000000000000000000000040 (data offset)
	// 0000000000000000000000000000000000000000000000000000000000000020 (data length)
	// 6161616161616161616161616161616161616161616161616161616161616161 (0..32 data)

	evm := env.evm
	caller := env.caller.Address()
	maxKVSize := evm.StateDB.SstorageMaxKVSize(caller)

	if maxKVSize == 0 {
		return nil, errors.New("invalid caller")
	}

	if evm.interpreter.readOnly {
		return nil, ErrWriteProtection
	}

	kvIdx := new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
	kvHash := common.BytesToHash(getData(input, 32, 32))
	dataPtr := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()

	log.Info("put info", "caller", caller, "kvidx", kvIdx, "kvHash", kvHash, "dataPtr", dataPtr)

	if dataPtr > uint64(len(input)) {
		return nil, errors.New("dataptr too large")
	}
	putLen := new(big.Int).SetBytes(getData(input, dataPtr, 32)).Uint64()

	if putLen > maxKVSize {
		return nil, errors.New("put len too large")
	}
	err := evm.StateDB.SstorageWrite(caller, kvIdx, kvHash, getData(input, dataPtr+32, putLen))
	if err != nil {
		return nil, err
	}
	log.Info("sstoragePisaPutRaw() returns", "caller", caller, "kvidx", kvIdx, "dataPtr", dataPtr, "maxKVSize", maxKVSize)

	return nil, nil

}

type sstoragePisaGetRaw struct {
}

func (s *sstoragePisaGetRaw) RequiredGas(input []byte) uint64 {
	return params.SloadGasEIP2200
}

func (l *sstoragePisaGetRaw) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (l *sstoragePisaGetRaw) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	evm := env.evm
	caller := env.caller.Address()

	if !evm.Config.IsJsonRpc {
		return nil, errors.New("getRaw() must be called in JSON RPC")
	}
	// TODO: check hash correctness
	hash := common.BytesToHash(getData(input, 0, 32))
	kvIdx := new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
	kvOff := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	kvLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()

	log.Debug("sstoragePisaGetRaw() inputs", "dkv", caller, "hash", hash, "kvidx", kvIdx, "kvOff", kvOff, "kvLen", kvLen)
	maxKVSize := evm.StateDB.SstorageMaxKVSize(caller)
	if maxKVSize == 0 {
		return nil, errors.New("invalid dkvAddr")
	}

	fb, ok, err := evm.StateDB.SstorageRead(caller, kvIdx, int(kvLen+kvOff), hash)
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
	log.Debug("sstoragePisaGetRaw() returns", "dkv", caller, "hash", hash, "kvidx", kvIdx, "kvOff", kvOff, "kvLen", kvLen, "data", common.Bytes2Hex(append(pb, b...)))
	return append(pb, b...), nil
}

type sstoragePisaUnmaskDaggerData struct {
}

func (s *sstoragePisaUnmaskDaggerData) RequiredGas(input []byte) uint64 {
	return params.UnmaskDaggerDataGas
}

func (l *sstoragePisaUnmaskDaggerData) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (l *sstoragePisaUnmaskDaggerData) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {

	// solidity input format = abi.encode(address dkvAddr, uint64 encodeType,uint64 chunkIdx,bytes32 kvHash,address miner,bytes memory maskedData )
	// 0000000000000000000000000000000000000000000000000000000000000001
	// 0000000000000000000000000000000000000000000000000000000000000002
	// 0000000000000000000000000000000000000000000000000000000000000000
	// 0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4
	// 00000000000000000000000000000000000000000000000000000000000000a0
	// 0000000000000000000000000000000000000000000000000000000000000002
	// aaaa000000000000000000000000000000000000000000000000000000000000

	encodeType := new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
	chunkIdx := new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
	kvHash := common.BytesToHash(getData(input, 64, 32))
	miner := common.BytesToAddress(getData(input, 96, 32))
	dataptr := new(big.Int).SetBytes(getData(input, 128, 32)).Uint64()
	datalen := new(big.Int).SetBytes(getData(input, 160, 32)).Uint64()

	if dataptr > uint64(len(input)) {
		return nil, errors.New("dataptr too large")
	}

	if !sstorage.IsValidEncodeType(encodeType) {
		return nil, fmt.Errorf("invalid encode type %d", encodeType)
	}

	maskedChunkData := getData(input, dataptr+32, datalen)
	if uint64(len(maskedChunkData)) != sstorage.CHUNK_SIZE || datalen != sstorage.CHUNK_SIZE {
		return nil, fmt.Errorf("the length of maskedChunk no equals to CHUNK_SIZE")
	}

	// get encoded key and decode masked chunk
	encodeKey := sstorage.CalcEncodeKey(kvHash, chunkIdx, miner)
	unmaskedChunk := sstorage.DecodeChunk(maskedChunkData, encodeType, encodeKey)

	pb := make([]byte, 64)
	binary.BigEndian.PutUint64(pb[32-8:32], 32)
	binary.BigEndian.PutUint64(pb[64-8:64], uint64(len(unmaskedChunk)))

	if bytes.Compare(unmaskedChunk[:20], make([]byte, 20)) != 0 {
		log.Warn("sstoragePisaUnmaskDaggerData() returns", "encodeType", encodeType, "chunkIdx", chunkIdx, "kvHash",
			kvHash, "miner", miner, "datalen", datalen, "masked chunk data", maskedChunkData[:20], "unmasked chunk data", unmaskedChunk[:20])
	}
	return append(pb, unmaskedChunk...), nil
}

// TODO: remove is not supported yet
type sstoragePisaRemoveRaw struct {
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

		// Decode G1 point
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

type tokenIssuer struct {
}

func (c *tokenIssuer) RequiredGas(input []byte) uint64 {
	// Setting the gas cost equal to CallNewAccountGas is due to the state-tree needs to create a new account for the user
	// who uses the chain for the first time and load the account leaf at cache until completing the `AddBalance` operation,
	// then commit the account-leaf to disk.
	// At the same time, if the user is not a new account, this previously charged gas can cover the gas cost for
	// `AddBalance` operation and is similar to the gas cost of Transfer(21000) for users
	return params.CallNewAccountGas
}

func (c *tokenIssuer) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (m *tokenIssuer) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	evm := env.evm
	caller := env.caller.Address()

	if caller != tokenManager {
		return nil, errors.New("only tokenManager")
	}

	to := common.BytesToAddress(input[0:32])
	amount := new(big.Int).SetBytes(getData(input, 32, 32))
	if !evm.StateDB.Exist(to) {
		evm.StateDB.CreateAccount(to)
	}

	evm.StateDB.AddBalance(to, amount)

	return nil, nil
}

type tokenBurner struct {
}

func (c *tokenBurner) RequiredGas(input []byte) uint64 {
	return params.BurnTokenGasCost
}

func (c *tokenBurner) Run(input []byte) ([]byte, error) {
	panic("not supported")
}

func (m *tokenBurner) RunWith(env *PrecompiledContractCallEnv, input []byte) ([]byte, error) {
	evm := env.evm
	caller := env.caller.Address()
	if caller != tokenManager {
		return nil, errors.New("only tokenManager")
	}

	to := common.BytesToAddress(input[0:32])
	amount := new(big.Int).SetBytes(getData(input, 32, 32))

	if !evm.StateDB.Exist(to) {
		return nil, errors.New("account no exist")
	}

	balance := evm.StateDB.GetBalance(to)
	if balance.Cmp(amount) < 0 {
		return nil, errors.New("no enough balance")
	}

	evm.StateDB.SubBalance(to, amount)

	return nil, nil
}

type crossChainCall struct {
}

const CrossChainCallInputLength = 160
const MaxDataLenLimitation = 1024

// RequiredGas is the maximum gas consumption that will calculate the cross_chain_call
func (c *crossChainCall) RequiredGas(input []byte) uint64 {
	var (
		packedAddrTopicsLen uint64
		packedDataLen       uint64
		packedTotalLen      uint64
		outputDataGasCost   uint64
		totalGasCost        uint64
	)

	if len(input) != CrossChainCallInputLength {
		// charge a high gas when an error occurs to avoid DOS attack
		return 0
	}

	// The gas calculation formula is as follows：
	// gas_overpay =  CrossChainCallDataPerByteGas * (address_len + topics_len + data_len) + OnceCrossChainCallGas
	//
	// For example with 2 topics:
	// 000000000000000000000000751320c36f413a6280ad54487766ae0f780b6f58 (32-byte contract address)
	// 0000000000000000000000000000000000000000000000000000000000000060 (topics start offest)
	// 00000000000000000000000000000000000000000000000000000000000000c0 (topics end offset)
	// 0000000000000000000000000000000000000000000000000000000000000002 (2 topics)
	// dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9 (topic0)
	// 0000000000000000000000000000000000000000000000000000000000000000 (topic1)
	// 00000000000000000000000000000000000000000000000000000000000000c0 (data length, any size, may not be 32-aligned)
	// 0000000000000000000000000000000000000000000000000000000000000002 (0..32 packed data)
	// 0000000000000000000000000000000000000000000000000000000000000001 (32..64 packed data)
	// 0000000000000000000000000000000000000000000000000000000000000060 (64..96 packed data)
	// 0000000000000000000000000000000000000000000000000000000000000028 (96..128 packed data)
	// bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb (128..160 packed data)
	// bbbbbbbbbbbbbbbb000000000000000000000000000000000000000000000000 (160..192 packed data)

	maxDataLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
	if maxDataLen > MaxDataLenLimitation {
		return 0
	}

	// ABI.packed data len will be round up to 32-aligned (see above example).
	if maxDataLen%32 != 0 {
		maxDataLen = maxDataLen + 32 - maxDataLen%32
	}
	// data length is added with 32 bytes after packing
	packedDataLen = 32 + maxDataLen

	// the sum of address len and topics len (address_len = 32 , max_topics_len = 7 * 32)
	packedAddrTopicsLen = 8 * 32
	packedTotalLen = packedAddrTopicsLen + packedDataLen

	// calculate gas cost of outputData
	outputDataGasCost = packedTotalLen * params.CrossChainCallDataPerByteGas

	totalGasCost = outputDataGasCost + params.OnceCrossChainCallGas

	return totalGasCost
}

func (c *crossChainCall) Run(input []byte) ([]byte, error) {
	return nil, ErrUnsupportMethod
}

func (c *crossChainCall) RunWith(env *PrecompiledContractCallEnv, input []byte, prepaidGas uint64) ([]byte, uint64, error) {
	if len(input) != CrossChainCallInputLength {
		return nil, 0, ErrInvalidCrossChainCallInputLength
	}
	if !env.evm.IsMindReadingEnabled() {
		return nil, 0, ErrCrossChainCallNoEnabled
	}

	maxDataLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
	confirms := new(big.Int).SetBytes(getData(input, 128, 32)).Uint64()

	if maxDataLen > MaxDataLenLimitation {
		return nil, 0, ErrMaxDataLenOutOfLimit
	}

	// Ensure that the number of confirmations meets the minimum requirement which is defined by chainConfig
	if confirms < env.evm.MRContext.MinimumConfirms {
		return nil, 0, ErrUserDefinedConfirmsTooSmall
	}

	if env.evm.MRContext.ReuseMindReading {
		// we are replaying the cross chain calls with the majority votes of the validators (and trust them).
		crossChainCallOutput := env.evm.getNextReplayableCCCOutput()
		if crossChainCallOutput == nil {
			// we are out of call outputs, are the validators broken (or the local node is broken)?
			log.Error("Index out of CrossChainCall Outputs")
			env.evm.setCCCSystemError(ErrOutputIdxOutOfBounds)
			return nil, 0, ErrOutputIdxOutOfBounds
		}

		if !crossChainCallOutput.Success {
			return crossChainCallOutput.Output, crossChainCallOutput.GasUsed, ErrCrossChainCallFailed
		} else {
			// the gas metering differs from the local node, it may be broken validators or the node.
			if crossChainCallOutput.GasUsed > prepaidGas {
				log.Error("CrossChainCall actual gas > prepaid Gas", "actual", crossChainCallOutput.GasUsed, "prepaid", prepaidGas)
				env.evm.setCCCSystemError(ErrActualGasExceedChargedGas)
				return crossChainCallOutput.Output, crossChainCallOutput.GasUsed, ErrActualGasExceedChargedGas
			}
			return crossChainCallOutput.Output, crossChainCallOutput.GasUsed, nil
		}
	}

	output, gasUsed, err, fatal := c.mindReadFromExternalClient(env, input, prepaidGas)
	if fatal != nil {
		env.evm.setCCCSystemError(fatal)
		return nil, 0, fatal
	}

	crossChainCallOutput := &CrossChainCallOutput{
		Output:  output,
		Success: err == nil,
		GasUsed: gasUsed,
	}
	env.evm.appendCCCOutput(crossChainCallOutput)

	// make sure return the same expect-err if occurred in the case of 'replay' and 'self-play'
	if err != nil {
		err = ErrCrossChainCallFailed
	}
	return output, gasUsed, err
}

func (c *crossChainCall) mindReadFromExternalClient(env *PrecompiledContractCallEnv, input []byte, prepaidGas uint64) ([]byte, uint64, error, error) {
	ctx := context.Background()
	// The flag of ReplayMindReading is false means that the node will produce the cross-chain-call output by itself
	// Reaching here means the node is a validator in consensus mode or a node in JSON-RPC eth_call.
	if env.evm.MRContext.MRClient == nil {
		log.Error("No active MindReading client")
		return nil, 0, nil, ErrNoActiveClient
	}

	chainId := new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
	txHash := common.BytesToHash(getData(input, 32, 32))
	logIdx := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	maxDataLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
	confirms := new(big.Int).SetBytes(getData(input, 128, 32)).Uint64()

	logData, expErr, unexpErr := GetExternalLog(ctx, env, chainId, txHash, logIdx, maxDataLen, confirms)

	if unexpErr != nil {
		log.Error("MindReading client unexpected error", "error", unexpErr)
		return nil, 0, nil, unexpErr
	}

	if expErr != nil {
		return nil, 0, expErr, nil
	}

	// calculate actual cost of gas
	actualGasUsed := logData.GasCost(params.CrossChainCallDataPerByteGas)
	actualGasUsed += params.OnceCrossChainCallGas

	packedLogData, _ := logData.ABIPack()

	if actualGasUsed > prepaidGas {
		log.Error("CrossChainCall actual gas > prepaid Gas", "actual", actualGasUsed, "prepaid", prepaidGas)
		return packedLogData, actualGasUsed, nil, ErrActualGasExceedChargedGas
	} else {
		return packedLogData, actualGasUsed, nil, nil
	}
}

// GetExternalLog Call the RPC-JSON on target chain id and return the log information
// It will return two types of error.
// - Unexpected error is caused by uncertainties of external node.  The error may differ for each call.
// - Expected error is caused by errors from user input such as wrong Tx or log indices.  The error is reproducible for all nodes with a synced external node.
func GetExternalLog(ctx context.Context, env *PrecompiledContractCallEnv, chainId uint64, txHash common.Hash, logIdx uint64, maxDataLen uint64, confirms uint64) (cr *GetLogByTxHash, expErr *ExpectCallErr, unExpErr error) {
	client := env.evm.MindReadingClient()

	if chainId != env.evm.MRContext.ChainId {
		// expect error
		expErr = NewExpectCallErr(fmt.Sprintf("CrossChainCall: chainId %d no support", chainId))
		return nil, expErr, nil
	}

	latestBlockNumber, err := client.BlockNumber(ctx)
	if err != nil {
		// unexpect error
		return nil, nil, err
	}

	receipt, err := client.TransactionReceipt(ctx, txHash)
	if err != nil {
		// unexpect error
		return nil, nil, err
	}

	happenedBlockNumber := receipt.BlockNumber
	if latestBlockNumber-happenedBlockNumber.Uint64() < confirms {
		// TODO: a proposer may include a Tx that is not confirmed by other validators (if their external nodes are still syncing)
		// TODO: an optimization is that a proposer will only include a Tx with more confirmations.
		// unexpected error
		return nil, nil, ErrConfirmsNoEnough
	}

	if logIdx >= uint64(len(receipt.Logs)) {
		// expect error
		return nil, NewExpectCallErr("CrossChainCall: logIdx out-of-bound"), nil
	}
	log := receipt.Logs[logIdx]

	var data []byte
	if uint64(len(log.Data)) > maxDataLen {
		data = make([]byte, maxDataLen)
		copy(data, log.Data[:maxDataLen])
	} else {
		data = make([]byte, len(log.Data))
		copy(data, log.Data)
	}

	logData := NewGetLogByTxHash(log.Address, log.Topics, data)
	if err != nil {
		return nil, nil, err
	}

	return logData, nil, nil
}

type GetLogByTxHash struct {
	// address of the contract that generated the event
	Address common.Address `json:"address" gencodec:"required"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics" gencodec:"required"`
	// supplied by the contract, usually ABI-encoded
	Data []byte `json:"data" gencodec:"required"`

	Args abi.Arguments
}

func NewGetLogByTxHash(address common.Address, topics []common.Hash, data []byte) *GetLogByTxHash {
	arg1Type, _ := abi.NewType("address", "", nil)
	arg2Type, _ := abi.NewType("bytes32[]", "", nil)
	arg3Type, _ := abi.NewType("bytes", "", nil)

	arg1 := abi.Argument{Name: "address", Type: arg1Type, Indexed: false}
	arg2 := abi.Argument{Name: "topics", Type: arg2Type, Indexed: false}
	arg3 := abi.Argument{Name: "data", Type: arg3Type, Indexed: false}

	var args = abi.Arguments{arg1, arg2, arg3}

	return &GetLogByTxHash{Address: address, Topics: topics, Data: data, Args: args}
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
}

func NewExpectCallErr(errMsg string) *ExpectCallErr {
	return &ExpectCallErr{ErrMsg: errMsg}
}

func (c *ExpectCallErr) Error() string {
	return fmt.Sprintf("Expect Error:%s", c.ErrMsg)
}

type CrossChainCallOutput struct {
	Output  []byte
	Success bool // Success is the flag to mark the status(success/failure) of cross-chain-call execution
	GasUsed uint64
}

type CrossChainCallOutputsWithVersion struct {
	Version uint64
	Outputs []*CrossChainCallOutput
}

// VerifyCrossChainCall is only used in tests to avoid circular reference
func VerifyCrossChainCall(client MindReadingClient, externalCallInput string) ([]byte, error) {
	p := &crossChainCall{}

	gas := p.RequiredGas(common.FromHex(externalCallInput))

	evmConfig := Config{}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, err
	}
	supportChainID := chainId.Uint64()
	chainCfg := &params.ChainConfig{MindReading: &params.MindReadingConfig{EnableBlockNumber: big.NewInt(0), SupportChainId: supportChainID, Version: 1}}

	mrctx := &MindReadingContext{
		MRClient:         client,
		MREnable:         true,
		ReuseMindReading: false,
		ChainId:          chainId.Uint64(),
		MinimumConfirms:  10,
	}
	evm := NewEVMWithMRC(BlockContext{BlockNumber: big.NewInt(0)}, TxContext{}, mrctx, nil, chainCfg, evmConfig)
	// evmInterpreter := NewEVMInterpreter(evm, evm.Config)
	// evm.interpreter = evmInterpreter

	if res, _, err := RunPrecompiledContract(&PrecompiledContractCallEnv{evm: evm}, p, common.FromHex(externalCallInput), gas); err != nil {
		return nil, err
	} else {
		return res, nil
	}
}
