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
		common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("6080604052600436106101f95760003560e01c8063749cf2821161010d578063a4a8435e116100a0578063c4a942cb1161006f578063c4a942cb146107c4578063c5d3490c146107f8578063d32897131461082c578063d4044b3314610860578063df80ca551461089457600080fd5b8063a4a8435e146106da578063afd5644d1461070e578063b1e1a34414610770578063bb88b7691461079057600080fd5b8063919c6eae116100dc578063919c6eae1461060657806395bc26731461063a5780639cf001fe1461065a578063a097365f146106a657600080fd5b8063749cf2821461053d57806378e979251461056a5780637e9dd69e1461059e578063812d2e72146105d257600080fd5b80634390bf0e1161019057806354b02ba41161015f57806354b02ba4146103ff5780636620dfc5146104335780636d951bc514610467578063739b482f1461049b57806373e8b3d4146104cf57600080fd5b80634390bf0e1461037857806344e77d991461039857806349bdd6f5146103ab5780634e86235e146103cb57600080fd5b806327c845dc116101cc57806327c845dc1461021e57806328de3c9b146102ac5780633cb2fecc14610310578063429dd7ad1461034457600080fd5b806315853983146101fe5780631b3143af146102205780631ccbc6da14610267578063258ae5821461027c575b600080fd5b34801561020a57600080fd5b5061021e6102193660046126ee565b6108a9565b005b34801561022c57600080fd5b506102547f6387d10d3fe6d4fcb51c9f9caf0c34f88526afc3d0c6a2b80adfceeea2b4a70181565b6040519081526020015b60405180910390f35b34801561027357600080fd5b506102546108c2565b34801561028857600080fd5b5061029c6102973660046127fc565b6108d2565b604051901515815260200161025e565b3480156102b857600080fd5b506102f06102c7366004612842565b600360208190526000918252604090912080546001820154600283015492909301549092919084565b60408051948552602085019390935291830152606082015260800161025e565b34801561031c57600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000000081565b34801561035057600080fd5b506000546103629064ffffffffff1681565b60405164ffffffffff909116815260200161025e565b34801561038457600080fd5b5061021e610393366004612874565b610a03565b61021e6103a63660046127fc565b610ac5565b3480156103b757600080fd5b5061021e6103c63660046128ca565b610cf5565b3480156103d757600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000001181565b34801561040b57600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000002881565b34801561043f57600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000000581565b34801561047357600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000006481565b3480156104a757600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000040081565b3480156104db57600080fd5b5061029c6104ea366004612842565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b34801561054957600080fd5b5061055d6105583660046128f6565b610f9b565b60405161025e9190612972565b34801561057657600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000000081565b3480156105aa57600080fd5b506102547fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e681565b3480156105de57600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000012c81565b34801561061257600080fd5b506102547f00000000000000000000000000000000000000000000000000000000000003e881565b34801561064657600080fd5b5061021e610655366004612842565b6111c9565b34801561066657600080fd5b5061068e7f000000000000000000000000000000000000000000000000000000000333000381565b6040516001600160a01b03909116815260200161025e565b3480156106b257600080fd5b506102547f000000000000000000000000000000000000000000000000000000000002000081565b3480156106e657600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000000081565b34801561071a57600080fd5b50610254610729366004612842565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b34801561077c57600080fd5b5061029c61078b366004612985565b6111d6565b34801561079c57600080fd5b5061068e7f000000000000000000000000000000000000000000000000000000000333000381565b3480156107d057600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000100081565b34801561080457600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000001281565b34801561083857600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000001081565b34801561086c57600080fd5b506102547f000000000000000000000000000000000000000000000000000000000000002381565b3480156108a057600080fd5b506102546113f8565b6108b9428888888888888861143c565b50505050505050565b60006108cd42611559565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff19169284018390529350036109905760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064015b60405180910390fd5b8351816020015162ffffff16146109ac576000925050506109fb565b60006109d8857f00000000000000000000000000000000000000000000000000000000000010006115ae565b9050806001600160401b03191682604001516001600160401b0319161493505050505b92915050565b565b60007f00000000000000000000000000000000000000000000000000000000033300036001600160a01b031663949dff3d60e01b858585604051602401610a4c93929190612a58565b60408051601f198184030181529181526020820180516001600160e01b03166001600160e01b0319909416939093179092529051610a8a9190612a8a565b600060405180830381855af49150503d80600081146108b9576040519150601f19603f3d011682016040523d82523d6000602084013e6108b9565b7f000000000000000000000000000000000000000000000000000000000002000081511115610b275760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b6044820152606401610987565b610b2f6117df565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610c4457610bb76108c2565b341015610bfb5760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b6044820152606401610987565b6000805464ffffffffff90811680845282526002602052604082208490559054610c2791166001612abc565b6000805464ffffffffff191664ffffffffff929092169190911790555b825162ffffff166020820152610c7a837f00000000000000000000000000000000000000000000000000000000000010006115ae565b67ffffffffffffffff19908116604080840191825260008581526001602090815290829020855181549287015194519384901c600160401b0262ffffff909516600160281b029290951664ffffffffff909516948517919091176001600160401b031692909217909155610cef919085610a03565b50505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff191693850184905290945090919003610db05760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b6044820152606401610987565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff96871617919091176001600160401b031617909255805490926002928492610e349216612ae1565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff19169091179055815490955090938492610e929216612ae1565b64ffffffffff908116825260208201929092526040016000908120929092559054610ec09160019116612ae1565b6000805464ffffffffff191664ffffffffff928316908117909155604051633625b3bb60e11b8152600481019190915290831660248201527f00000000000000000000000000000000000000000000000000000000033300036001600160a01b031690636c4b677690604401600060405180830381600087803b158015610f4657600080fd5b505af1158015610f5a573d6000803e3d6000fd5b50505050846001600160a01b03166108fc610f736108c2565b6040518115909202916000818181858888f193505050501580156108b9573d6000803e3d6000fd5b606081600003610fba57506040805160008152602081019091526111c2565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff191692840192909252909250851061105357505060408051600081526020810190915290506111c2565b602081015162ffffff166110678686612aff565b11156110855784816020015162ffffff166110829190612b12565b93505b6040818101518251825167ffffffffffffffff19909216602483015264ffffffffff1660448201526064810187905260848082018790528251808303909101815260a490910182526020810180516001600160e01b031663048a466160e01b179052905160009182917f00000000000000000000000000000000000000000000000000000000033300036001600160a01b03169161112291612a8a565b600060405180830381855afa9150503d806000811461115d576040519150601f19603f3d011682016040523d82523d6000602084013e611162565b606091505b5091509150816111a75760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b6044820152606401610987565b808060200190518101906111bb9190612b25565b9450505050505b9392505050565b6111d38133610cf5565b50565b600060017f00000000000000000000000000000000000000000000000000000000000000051b816112078288612ba8565b90506000866020015162ffffff167f0000000000000000000000000000000000000000000000000000000000001000836112419190612bbc565b1061127a577fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e685805190602001201493505050506113f0565b817f0000000000000000000000000000000000000000000000000000000000001000600189602001516112ad9190612bdb565b62ffffff166112bc9190612bf7565b036113be5760006112ed7f000000000000000000000000000000000000000000000000000000000000100084612bbc565b886020015162ffffff166113019190612b12565b60208701819020925090506000611338827f0000000000000000000000000000000000000000000000000000000000001000612b12565b905080156113b7576000816001600160401b0381111561135a5761135a6124fb565b6040519080825280601f01601f191660200182016040528015611384576020820181803683370190505b5060208082018490208a860190910184902091925090808214806113b25798506113f0975050505050505050565b505050505b50506113c7565b50835160208501205b60006113d48284896117e8565b604089015167ffffffffffffffff199182169116149450505050505b949350505050565b600080546114309064ffffffffff167f00000000000000000000000000000000000000000000000000000000000000121c6001612abc565b64ffffffffff16905090565b878411156114805760405162461bcd60e51b81526020600482015260116024820152706d696e6564547320746f6f206c6172676560781b6044820152606401610987565b6001861b600080806114938b858a61191c565b604080516020808201939093526001600160a01b038e1681830152606081018d905260808082018d90528251808303909101815260a09091019091528051910120919450925090506114e98b8b838c8a8a611b06565b905060006114f984600019612bf7565b90508082111561153c5760405162461bcd60e51b815260206004820152600e60248201526d0c8d2cccc40dcdee840dac2e8c6d60931b6044820152606401610987565b5061154b8b858b8b8686611fad565b505050505050505050505050565b60006109fb7f00000000000000000000000000000000000000000000000000000000000000006115a97f000000000000000000000000000000000000000000000000000000000000000085612b12565b61214f565b600082516000036115c1575060006109fb565b60008260018486516115d39190612aff565b6115dd9190612b12565b6115e79190612bf7565b905060006001821115611602576115fd82612190565b611605565b60015b90506000816001600160401b03811115611621576116216124fb565b60405190808252806020026020018201604052801561164a578160200160208202803683370190505b50905060005b828110156116d0576000806116658884612bbc565b9050885181106116765750506116d0565b6000818a516116859190612b12565b90508881106116915750875b808260208c0101209250828585815181106116ae576116ae612c0b565b60200260200101818152505050505080806116c890612c21565b915050611650565b508192505b826001146117b95760005b6116eb600285612bf7565b8110156117a657816116fe826002612bbc565b8151811061170e5761170e612c0b565b6020026020010151828260026117249190612bbc565b61172f906001612aff565b8151811061173f5761173f612c0b565b6020026020010151604051602001611761929190918252602082015260400190565b6040516020818303038152906040528051906020012082828151811061178957611789612c0b565b60209081029190910101528061179e81612c21565b9150506116e0565b506117b2600284612bf7565b92506116d5565b806000815181106117cc576117cc612c0b565b6020026020010151935050505092915050565b610a01426121cd565b805160009084906001811b85106118355760405162461bcd60e51b81526020600482015260116024820152706368756e6b4964206f766572666c6f777360781b6044820152606401610987565b60005b818110156119115761184b600287612ba8565b6000036118a4578285828151811061186557611865612c0b565b6020026020010151604051602001611887929190918252602082015260400190565b6040516020818303038152906040528051906020012092506118f2565b8481815181106118b6576118b6612c0b565b6020026020010151836040516020016118d9929190918252602082015260400190565b6040516020818303038152906040528051906020012092505b6118fd600287612bf7565b95508061190981612c21565b915050611838565b509095945050505050565b600060606000846001600160401b0381111561193a5761193a6124fb565b604051908082528060200260200182016040528015611963578160200160208202803683370190505b50600093509150829050805b85811015611afc5760006119838289612aff565b60008181526003602052604090206001810154919250908710156119dd5760405162461bcd60e51b81526020600482015260116024820152701b5a5b9959151cc81d1bdbc81cdb585b1b607a1b6044820152606401610987565b611a6b81887f000000000000000000000000000000000000000000000000000000000000012c7f00000000000000000000000000000000000000000000000000000000000000287f00000000000000000000000000000000000000000000000000000000000004007f00000000000000000000000000000000000000000000000000000000000000646122c0565b858481518110611a7d57611a7d612c0b565b602002602001018181525050848381518110611a9b57611a9b612c0b565b602002602001015186611aae9190612aff565b81546040805160208101889052908101859052606081019190915290965060800160405160208183030381529060405280519060200120935050508080611af490612c21565b91505061196f565b5093509350939050565b60007f0000000000000000000000000000000000000000000000000000000000000010825114611b785760405162461bcd60e51b815260206004820152601f60248201527f6461746120767320636865636b733a206c656e677468206d69736d61746368006044820152606401610987565b7f0000000000000000000000000000000000000000000000000000000000000010835114611bf25760405162461bcd60e51b815260206004820152602160248201527f70726f6f667320767320636865636b733a206c656e677468206d69736d6174636044820152600d60fb1b6064820152608401610987565b60007f0000000000000000000000000000000000000000000000000000000000000005611c3f887f0000000000000000000000000000000000000000000000000000000000000012612aff565b611c499190612aff565b6001901b905060005b7f0000000000000000000000000000000000000000000000000000000000000010811015611fa05760007f0000000000000000000000000000000000000000000000000000000000001000905080858381518110611cb257611cb2612c0b565b60200260200101515114611cfd5760405162461bcd60e51b8152602060048201526012602482015271696e76616c69642070726f6f662073697a6560701b6044820152606401610987565b6000611d09848a612ba8565b90506000611d577f00000000000000000000000000000000000000000000000000000000000000057f0000000000000000000000000000000000000000000000000000000000000012612aff565b611d64908d901b83612aff565b905060007f000000000000000000000000000000000000000000000000000000000000000582901c9050600060016000600260008581526020019081526020016000205481526020019081526020016000206040518060600160405290816000820160009054906101000a900464ffffffffff1664ffffffffff1664ffffffffff1681526020016000820160059054906101000a900462ffffff1662ffffff1662ffffff1681526020016000820160089054906101000a900460401b6001600160401b0319166001600160401b03191681525050905060007f00000000000000000000000000000000000000000000000000000000033300036001600160a01b0316636253a9318584604001518f8e8c81518110611e8457611e84612c0b565b60200260200101516040518563ffffffff1660e01b8152600401611eab9493929190612c3a565b600060405180830381865afa158015611ec8573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f19168201604052611ef09190810190612b25565b9050611f1784838d8a81518110611f0957611f09612c0b565b6020026020010151846111d6565b611f5a5760405162461bcd60e51b815260206004820152601460248201527334b73b30b634b21030b1b1b2b9b990383937b7b360611b6044820152606401610987565b60008a8881518110611f6e57611f6e612c0b565b602002602001015190508d81526020870181209d50868152505050505050508080611f9890612c21565b915050611c52565b5094979650505050505050565b600080611fb86113f8565b905060005b87811015612093576000611fd1828b612aff565b9050828111612080576000818152600360205260409020600181015461203b907f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000121b908a61238e565b6120459086612aff565b945061207e600360008481526020019081526020016000208989868151811061207057612070612c0b565b6020026020010151896123ed565b505b508061208b81612c21565b915050611fbd565b5060006127106120c37f00000000000000000000000000000000000000000000000000000000000003e885612bbc565b6120cd9190612bf7565b905060006120db8285612b12565b604051909150419083156108fc029084906000818181858888f1935050505015801561210b573d6000803e3d6000fd5b506040516001600160a01b0389169082156108fc029083906000818181858888f19350505050158015612142573d6000803e3d6000fd5b5050505050505050505050565b6000608061217d7f000000000000000000000000000000000000000000000000000000000000000084612411565b6121879085612bbc565b901c9392505050565b600061219d600183612b12565b91505b6121ab600183612b12565b8216156121c6576121bd600183612b12565b821691506121a0565b5060011b90565b60005460017f000000000000000000000000000000000000000000000000000000000000001281901b9161220a9164ffffffffff90911690612abc565b64ffffffffff1661221b9190612ba8565b6000036111d357600080547f00000000000000000000000000000000000000000000000000000000000000129061225a9064ffffffffff166001612abc565b64ffffffffff16901c600161226f9190612abc565b64ffffffffff166000818152600360208190526040822060019081018690559293509161229c9084612b12565b81526020808201929092526040908101600090812054938152600390925290205550565b6000808760010154876122d39190612b12565b60028901549091508682101561232a5784816122ef8885612bf7565b6122fa906001612b12565b6123049190612bbc565b61230e9190612bf7565b6123189082612aff565b9050838110156123255750825b612382565b60008582600161233a8a87612bf7565b6123449190612b12565b61234e9190612bbc565b6123589190612bf7565b9050816123658683612aff565b111561237357849150612380565b61237d8183612b12565b91505b505b98975050505050505050565b60006113f0846123be7f000000000000000000000000000000000000000000000000000000000000000086612b12565b6123e87f000000000000000000000000000000000000000000000000000000000000000086612b12565b61241d565b60038401546123fd906001612aff565b600385015583556002830155600190910155565b60006111c28383612493565b6000608061244b7f000000000000000000000000000000000000000000000000000000000000000084612411565b6124757f000000000000000000000000000000000000000000000000000000000000000086612411565b61247f9190612b12565b6124899086612bbc565b901c949350505050565b6000600160801b5b82156111c257826001166001036124bd5760806124b88583612bbc565b901c90505b60806124c98580612bbc565b901c93506124d8600284612bf7565b925061249b565b80356001600160a01b03811681146124f657600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b604051606081016001600160401b0381118282101715612533576125336124fb565b60405290565b604051601f8201601f191681016001600160401b0381118282101715612561576125616124fb565b604052919050565b60006001600160401b03821115612582576125826124fb565b5060051b60200190565b600082601f83011261259d57600080fd5b813560206125b26125ad83612569565b612539565b82815260059290921b840181019181810190868411156125d157600080fd5b8286015b848110156125ec57803583529183019183016125d5565b509695505050505050565b60006001600160401b03821115612610576126106124fb565b50601f01601f191660200190565b600082601f83011261262f57600080fd5b813561263d6125ad826125f7565b81815284602083860101111561265257600080fd5b816020850160208301376000918101602001919091529392505050565b600082601f83011261268057600080fd5b813560206126906125ad83612569565b82815260059290921b840181019181810190868411156126af57600080fd5b8286015b848110156125ec5780356001600160401b038111156126d25760008081fd5b6126e08986838b010161261e565b8452509183019183016126b3565b600080600080600080600060e0888a03121561270957600080fd5b8735965060208801359550612720604089016124df565b9450606088013593506080880135925060a08801356001600160401b038082111561274a57600080fd5b818a0191508a601f83011261275e57600080fd5b813561276c6125ad82612569565b8082825260208201915060208360051b86010192508d83111561278e57600080fd5b602085015b838110156127c75784813511156127a957600080fd5b6127b98f6020833589010161258c565b835260209283019201612793565b509550505060c08a01359150808211156127e057600080fd5b506127ed8a828b0161266f565b91505092959891949750929550565b6000806040838503121561280f57600080fd5b8235915060208301356001600160401b0381111561282c57600080fd5b6128388582860161261e565b9150509250929050565b60006020828403121561285457600080fd5b5035919050565b803567ffffffffffffffff19811681146124f657600080fd5b60008060006060848603121561288957600080fd5b833592506128996020850161285b565b915060408401356001600160401b038111156128b457600080fd5b6128c08682870161261e565b9150509250925092565b600080604083850312156128dd57600080fd5b823591506128ed602084016124df565b90509250929050565b60008060006060848603121561290b57600080fd5b505081359360208301359350604090920135919050565b60005b8381101561293d578181015183820152602001612925565b50506000910152565b6000815180845261295e816020860160208601612922565b601f01601f19169290920160200192915050565b6020815260006111c26020830184612946565b60008060008084860360c081121561299c57600080fd5b853594506060601f19820112156129b257600080fd5b506129bb612511565b602086013564ffffffffff811681146129d357600080fd5b8152604086013562ffffff811681146129eb57600080fd5b60208201526129fc6060870161285b565b6040820152925060808501356001600160401b0380821115612a1d57600080fd5b612a298883890161258c565b935060a0870135915080821115612a3f57600080fd5b50612a4c8782880161261e565b91505092959194509250565b8381526001600160401b031983166020820152606060408201526000612a816060830184612946565b95945050505050565b60008251612a9c818460208701612922565b9190910192915050565b634e487b7160e01b600052601160045260246000fd5b64ffffffffff818116838216019080821115612ada57612ada612aa6565b5092915050565b64ffffffffff828116828216039080821115612ada57612ada612aa6565b808201808211156109fb576109fb612aa6565b818103818111156109fb576109fb612aa6565b600060208284031215612b3757600080fd5b81516001600160401b03811115612b4d57600080fd5b8201601f81018413612b5e57600080fd5b8051612b6c6125ad826125f7565b818152856020838501011115612b8157600080fd5b612a81826020830160208601612922565b634e487b7160e01b600052601260045260246000fd5b600082612bb757612bb7612b92565b500690565b6000816000190483118215151615612bd657612bd6612aa6565b500290565b62ffffff828116828216039080821115612ada57612ada612aa6565b600082612c0657612c06612b92565b500490565b634e487b7160e01b600052603260045260246000fd5b600060018201612c3357612c33612aa6565b5060010190565b6001600160401b038516815267ffffffffffffffff19841660208201526001600160a01b0383166040820152608060608201819052600090612c7e90830184612946565b969550505050505056fea2646970667358221220fecfcc0cffed9143ba11518f3aa49aec7939725a02ed3845f8fce1c7e0340b1364736f6c63430008100033"),
		// Get the url of PrecompileManager: https://github.com/ethstorage/storage-contracts/blob/developing/contracts/PrecompileManager.sol
		// contract at 0x0000000000000000000000000000000003330003 is complied PrecompileManager() + 0.8.16 solc (enable optimized)
		common.HexToAddress("0x0000000000000000000000000000000003330003"): common.Hex2Bytes("608060405234801561001057600080fd5b506004361061009e5760003560e01c80638612af34116100665780638612af341461012c578063896b49911461014d578063949dff3d14610157578063dd7e57d41461016a578063e7a84c461461017457600080fd5b8063048a4661146100a35780634590c168146100cc5780636253a931146100e25780636c4b6776146100f55780636da6d51e1461010a575b600080fd5b6100b66100b13660046104e9565b61017e565b6040516100c39190610572565b60405180910390f35b6100b66100da36600461062f565b606092915050565b6100b66100f0366004610676565b610265565b610108610103366004610701565b61033d565b005b6101146203330281565b6040516001600160a01b0390911681526020016100c3565b610134600281565b60405167ffffffffffffffff90911681526020016100c3565b6101146203330581565b610108610165366004610723565b610401565b6101146203330381565b6101146203330481565b6040805133602082015285821c91810182905260608082018690526080820185905260a0820184905291906000908190620333039060c00160408051601f19818403018152908290526101d09161077a565b600060405180830381855afa9150503d806000811461020b576040519150601f19603f3d011682016040523d82523d6000602084013e610210565b606091505b50915091508161025a5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b60448201526064015b60405180910390fd5b979650505050505050565b6040805160609185901c9060009081906203330490610291906002908b9087908b908b90602001610796565b60408051601f19818403018152908290526102ab9161077a565b600060405180830381855afa9150503d80600081146102e6576040519150601f19603f3d011682016040523d82523d6000602084013e6102eb565b606091505b50915091508161025a5760405162461bcd60e51b815260206004820152601f60248201527f6661696c656420746f20756e6d61736b4368756e6b57697468457468617368006044820152606401610251565b6040805160208101849052908101829052600090620333059060600160408051601f19818403018152908290526103739161077a565b6000604051808303816000865af19150503d80600081146103b0576040519150601f19603f3d011682016040523d82523d6000602084013e6103b5565b606091505b50509050806103fc5760405162461bcd60e51b81526020600482015260136024820152726661696c656420746f2072656d6f766552617760681b6044820152606401610251565b505050565b604080519083901c906000906203330290610424908790859087906020016107d9565b60408051601f198184030181529082905261043e9161077a565b6000604051808303816000865af19150503d806000811461047b576040519150601f19603f3d011682016040523d82523d6000602084013e610480565b606091505b50509050806104c45760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2070757452617760801b6044820152606401610251565b5050505050565b803567ffffffffffffffff19811681146104e457600080fd5b919050565b600080600080608085870312156104ff57600080fd5b610508856104cb565b966020860135965060408601359560600135945092505050565b60005b8381101561053d578181015183820152602001610525565b50506000910152565b6000815180845261055e816020860160208601610522565b601f01601f19169290920160200192915050565b6020815260006105856020830184610546565b9392505050565b634e487b7160e01b600052604160045260246000fd5b600082601f8301126105b357600080fd5b813567ffffffffffffffff808211156105ce576105ce61058c565b604051601f8301601f19908116603f011681019082821181831017156105f6576105f661058c565b8160405283815286602085880101111561060f57600080fd5b836020870160208301376000602085830101528094505050505092915050565b6000806040838503121561064257600080fd5b82359150602083013567ffffffffffffffff81111561066057600080fd5b61066c858286016105a2565b9150509250929050565b6000806000806080858703121561068c57600080fd5b843567ffffffffffffffff80821682146106a557600080fd5b8195506106b4602088016104cb565b9450604087013591506001600160a01b03821682146106d257600080fd5b909250606086013590808211156106e857600080fd5b506106f5878288016105a2565b91505092959194509250565b6000806040838503121561071457600080fd5b50508035926020909101359150565b60008060006060848603121561073857600080fd5b83359250610748602085016104cb565b9150604084013567ffffffffffffffff81111561076457600080fd5b610770868287016105a2565b9150509250925092565b6000825161078c818460208701610522565b9190910192915050565b67ffffffffffffffff868116825285166020820152604081018490526001600160a01b038316606082015260a06080820181905260009061025a90830184610546565b8381528260208201526060604082015260006107f86060830184610546565b9594505050505056fea2646970667358221220cf38e2177054bfae3e632bc9fda3667ef93d99ac691a0b2a687b6abafc5726ce64736f6c63430008100033"),
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
		log.Error("SstorageWrite Error", "err", err)
	}
	log.Info("put ending", "caller", caller, "kvidx", kvIdx, "dataPtr", dataPtr, "maxKVSize", maxKVSize)

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

	if !evm.Config.IsJsonRpc {
		return nil, errors.New("getRaw() must be called in JSON RPC")
	}
	// TODO: check hash correctness
	dkvAddr := common.BytesToAddress(getData(input, 0, 32))
	hash := common.BytesToHash(getData(input, 32, 32))
	kvIdx := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	kvOff := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
	kvLen := new(big.Int).SetBytes(getData(input, 128, 32)).Uint64()

	log.Info("get info", "dkv", dkvAddr, "hash", hash, "kvidx", kvIdx, "kvOff", kvOff, "kvLen", kvLen)
	maxKVSize := evm.StateDB.SstorageMaxKVSize(dkvAddr)
	if maxKVSize == 0 {
		return nil, errors.New("invalid dkvAddr")
	}

	fb, ok, err := evm.StateDB.SstorageRead(dkvAddr, kvIdx, int(kvLen+kvOff), hash)
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
	log.Warn("get ending", "dkv", dkvAddr, "hash", hash, "kvidx", kvIdx, "kvOff", kvOff, "kvLen", kvLen)
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

	log.Info("unmask info", "encodeType", encodeType, "chunkIdx", chunkIdx, "kvHash", kvHash, "miner", miner, "datalen", datalen)

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
	log.Warn("unmask info", "encodeType", encodeType, "chunkIdx", chunkIdx, "kvHash", kvHash, "miner", miner, "datalen", datalen)
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
	//`AddBalance` operation and is similar to the gas cost of Transfer(21000) for users
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
const MaxDataLenLimitation = 100000

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

	ctx := context.Background()
	var crossChainCallOutput *CrossChainCallOutput

	if env.evm.MRContext.ReplayMindReading {
		// we are replaying the cross chain calls with the majority votes of the validators (and trust them).
		crossChainCallOutput = env.evm.getNextReplayableCCCOutput()
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

	// The flag of ReplayMindReading is false means that the node will produce the cross-chain-call output by itself
	// Reaching here means the node is a validator in consensus mode or a node in JSON-RPC eth_call.
	if env.evm.MRContext.MRClient == nil {
		log.Error("No active MindReading client")
		env.evm.setCCCSystemError(ErrNoActiveClient)
		return nil, 0, ErrNoActiveClient
	}

	chainId := new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
	txHash := common.BytesToHash(getData(input, 32, 32))
	logIdx := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	maxDataLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
	confirms := new(big.Int).SetBytes(getData(input, 128, 32)).Uint64()

	if maxDataLen > MaxDataLenLimitation {
		return nil, 0, ErrMaxDataLenOutOfLimit
	}

	// Ensure that the number of confirmations meets the minimum requirement which is defined by chainConfig
	if confirms < env.evm.MRContext.MinimumConfirms {
		return nil, 0, ErrUserDefinedConfirmsTooSmall
	}

	logData, expErr, unexpErr := GetExternalLog(ctx, env, chainId, txHash, logIdx, maxDataLen, confirms)

	if unexpErr != nil {
		log.Error("MindReading client unexpected error", "error", unexpErr)
		env.evm.setCCCSystemError(unexpErr)
		return nil, 0, unexpErr
	} else if expErr != nil {
		return nil, 0, expErr
	} else {
		// calculate actual cost of gas
		actualGasUsed := logData.GasCost(params.CrossChainCallDataPerByteGas)
		actualGasUsed += params.OnceCrossChainCallGas

		packedLogData, err := logData.ABIPack()
		// TODO: will the error happen?
		if err != nil {
			env.evm.setCCCSystemError(err)
			return nil, 0, err
		}
		crossChainCallOutput = &CrossChainCallOutput{
			Output:  packedLogData,
			Success: true,
			GasUsed: actualGasUsed,
		}
		env.evm.appendCCCOutput(crossChainCallOutput)
	}

	if crossChainCallOutput.GasUsed > prepaidGas {
		log.Error("CrossChainCall actual gas > prepaid Gas", "actual", crossChainCallOutput.GasUsed, "prepaid", prepaidGas)
		env.evm.setCCCSystemError(ErrActualGasExceedChargedGas)
		return crossChainCallOutput.Output, crossChainCallOutput.GasUsed, ErrActualGasExceedChargedGas
	} else {
		return crossChainCallOutput.Output, crossChainCallOutput.GasUsed, nil
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

	// TODO: the error should never happen?
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
		MRClient:          client,
		MREnable:          true,
		ReplayMindReading: false,
		ChainId:           chainId.Uint64(),
		MinimumConfirms:   10,
	}
	evm := NewEVMWithMRC(BlockContext{BlockNumber: big.NewInt(0)}, TxContext{}, mrctx, nil, chainCfg, evmConfig)
	//evmInterpreter := NewEVMInterpreter(evm, evm.Config)
	//evm.interpreter = evmInterpreter

	if res, _, err := RunPrecompiledContract(&PrecompiledContractCallEnv{evm: evm}, p, common.FromHex(externalCallInput), gas); err != nil {
		return nil, err
	} else {
		return res, nil
	}

}
