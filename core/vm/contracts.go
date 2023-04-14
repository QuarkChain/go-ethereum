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
		common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("6080604052600436106102465760003560e01c806378e9792511610139578063b1e1a344116100b6578063d32897131161007a578063d3289713146108cc578063d4044b3314610900578063dca0051114610934578063dd7e57d414610957578063df80ca551461096e578063e7a84c461461098357600080fd5b8063b1e1a34414610804578063b2aebe8814610824578063c4a942cb14610844578063c5d3490c14610878578063ca2af623146108ac57600080fd5b8063919c6eae116100fd578063919c6eae146106e657806395bc26731461071a578063a097365f1461073a578063a4a8435e1461076e578063afd5644d146107a257600080fd5b806378e979251461061a578063812d2e721461064e5780638612af34146106825780638891ce9c146106af578063896b4991146106cf57600080fd5b806349bdd6f5116101c75780636d951bc51161018b5780636d951bc5146104e85780636da6d51e1461051c578063739b482f1461054b57806373e8b3d41461057f578063749cf282146105ed57600080fd5b806349bdd6f51461040c5780634e86235e1461042c57806354b02ba4146104605780636620dfc5146104945780636cece5f8146104c857600080fd5b806328de3c9b1161020e57806328de3c9b146102f9578063390df0b61461035d5780633cb2fecc14610391578063429dd7ad146103c557806344e77d99146103f957600080fd5b80630fce307b1461024b57806315853983146102925780631ccbc6da146102b4578063258ae582146102c957806327c845dc146102b2575b600080fd5b34801561025757600080fd5b5061027f7f6387d10d3fe6d4fcb51c9f9caf0c34f88526afc3d0c6a2b80adfceeea2b4a70181565b6040519081526020015b60405180910390f35b34801561029e57600080fd5b506102b26102ad366004612829565b61099a565b005b3480156102c057600080fd5b5061027f6109b3565b3480156102d557600080fd5b506102e96102e4366004612937565b6109c3565b6040519015158152602001610289565b34801561030557600080fd5b5061033d61031436600461297d565b600360208190526000918252604090912080546001820154600283015492909301549092919084565b604080519485526020850193909352918301526060820152608001610289565b34801561036957600080fd5b5061027f7fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e681565b34801561039d57600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000000081565b3480156103d157600080fd5b506000546103e39064ffffffffff1681565b60405164ffffffffff9091168152602001610289565b6102b2610407366004612937565b610af4565b34801561041857600080fd5b506102b2610427366004612996565b610d24565b34801561043857600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000001181565b34801561046c57600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000002881565b3480156104a057600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000000581565b3480156104d457600080fd5b506102b26104e33660046129db565b610f52565b3480156104f457600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000006481565b34801561052857600080fd5b506105336203330281565b6040516001600160a01b039091168152602001610289565b34801561055757600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000040081565b34801561058b57600080fd5b506102e961059a36600461297d565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b3480156105f957600080fd5b5061060d610608366004612a31565b61101c565b6040516102899190612aad565b34801561062657600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000000181565b34801561065a57600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000012c81565b34801561068e57600080fd5b50610697600281565b6040516001600160401b039091168152602001610289565b3480156106bb57600080fd5b5061060d6106ca366004612ac0565b61112d565b3480156106db57600080fd5b506105336203330581565b3480156106f257600080fd5b5061027f7f00000000000000000000000000000000000000000000000000000000000003e881565b34801561072657600080fd5b506102b261073536600461297d565b611226565b34801561074657600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000002000081565b34801561077a57600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000000081565b3480156107ae57600080fd5b5061027f6107bd36600461297d565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b34801561081057600080fd5b506102e961081f366004612af9565b611233565b34801561083057600080fd5b506102b261083f366004612bcc565b611455565b34801561085057600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000100081565b34801561088457600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000000881565b3480156108b857600080fd5b5061060d6108c7366004612bee565b61151c565b3480156108d857600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000001081565b34801561090c57600080fd5b5061027f7f000000000000000000000000000000000000000000000000000000000000001981565b34801561094057600080fd5b5061060d61094f366004612937565b606092915050565b34801561096357600080fd5b506105336203330381565b34801561097a57600080fd5b5061027f61160d565b34801561098f57600080fd5b506105336203330481565b6109aa4288888888888888611651565b50505050505050565b60006109be4261176e565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610a815760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064015b60405180910390fd5b8351816020015162ffffff1614610a9d57600092505050610aec565b6000610ac9857f00000000000000000000000000000000000000000000000000000000000010006117c3565b9050806001600160401b03191682604001516001600160401b0319161493505050505b92915050565b565b7f000000000000000000000000000000000000000000000000000000000002000081511115610b565760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b6044820152606401610a78565b610b5e6119f4565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff1916928401839052935003610c7357610be66109b3565b341015610c2a5760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b6044820152606401610a78565b6000805464ffffffffff90811680845282526002602052604082208490559054610c5691166001612c65565b6000805464ffffffffff191664ffffffffff929092169190911790555b825162ffffff166020820152610ca9837f00000000000000000000000000000000000000000000000000000000000010006117c3565b67ffffffffffffffff19908116604080840191825260008581526001602090815290829020855181549287015194519384901c600160401b0262ffffff909516600160281b029290951664ffffffffff909516948517919091176001600160401b031692909217909155610d1e919085610f52565b50505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff191693850184905290945090919003610ddf5760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b6044820152606401610a78565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff96871617919091176001600160401b031617909255805490926002928492610e639216612c8a565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff19169091179055815490955090938492610ec19216612c8a565b64ffffffffff908116825260208201929092526040016000908120929092559054610eef9160019116612c8a565b6000805464ffffffffff191664ffffffffff928316908117909155610f15918416611455565b846001600160a01b03166108fc610f2a6109b3565b6040518115909202916000818181858888f193505050501580156109aa573d6000803e3d6000fd5b604080519083901c906000906203330290610f7590879085908790602001612ca8565b60408051601f1981840301815290829052610f8f91612cd0565b6000604051808303816000865af19150503d8060008114610fcc576040519150601f19603f3d011682016040523d82523d6000602084013e610fd1565b606091505b50509050806110155760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2070757452617760801b6044820152606401610a78565b5050505050565b60608160000361103b5750604080516000815260208101909152611126565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff19169284019290925290925085106110d45750506040805160008152602081019091529050611126565b602081015162ffffff166110e88686612cec565b11156111065784816020015162ffffff166111039190612cff565b93505b6111218160400151826000015164ffffffffff16878761112d565b925050505b9392505050565b6040805185821c6020820181905291810185905260608082018590526080820184905291906000908190620333039060a00160408051601f198184030181529082905261117991612cd0565b600060405180830381855afa9150503d80600081146111b4576040519150601f19603f3d011682016040523d82523d6000602084013e6111b9565b606091505b5091509150816112045760405162461bcd60e51b81526020600482015260166024820152756661696c656420746f2073797374656d47657452617760501b6044820152606401610a78565b808060200190518101906112189190612d12565b93505050505b949350505050565b6112308133610d24565b50565b600060017f00000000000000000000000000000000000000000000000000000000000000051b816112648288612d95565b90506000866020015162ffffff167f00000000000000000000000000000000000000000000000000000000000010008361129e9190612da9565b106112d7577fa8bae11751799de4dbe638406c5c9642c0e791f2a65e852a05ba4fdf0d88e3e6858051906020012014935050505061121e565b817f00000000000000000000000000000000000000000000000000000000000010006001896020015161130a9190612dc8565b62ffffff166113199190612de4565b0361141c57600061134a7f000000000000000000000000000000000000000000000000000000000000100084612da9565b886020015162ffffff1661135e9190612cff565b60208701819020925090506000611395827f0000000000000000000000000000000000000000000000000000000000001000612cff565b90508015611415576000816001600160401b038111156113b7576113b7612636565b6040519080825280601f01601f1916602001820160405280156113e1576020820181803683370190505b5090506000808360208401209150838560208c01012090508082146114115760009850505050505050505061121e565b5050505b5050611425565b50835160208501205b60006114328284896119fd565b604089015167ffffffffffffffff19918216911614945050505050949350505050565b6040805160208101849052908101829052600090620333059060600160408051601f198184030181529082905261148b91612cd0565b6000604051808303816000865af19150503d80600081146114c8576040519150601f19603f3d011682016040523d82523d6000602084013e6114cd565b606091505b50509050806115175760405162461bcd60e51b81526020600482015260166024820152756661696c656420746f2073797374656d50757452617760501b6044820152606401610a78565b505050565b6040805160609185901c9060009081906203330490611548906002908b9087908b908b90602001612df8565b60408051601f198184030181529082905261156291612cd0565b600060405180830381855afa9150503d806000811461159d576040519150601f19603f3d011682016040523d82523d6000602084013e6115a2565b606091505b5091509150816116025760405162461bcd60e51b815260206004820152602560248201527f6661696c656420746f2073797374656d556e6d61736b4368756e6b57697468456044820152640e8d0c2e6d60db1b6064820152608401610a78565b979650505050505050565b600080546116459064ffffffffff167f00000000000000000000000000000000000000000000000000000000000000081c6001612c65565b64ffffffffff16905090565b878411156116955760405162461bcd60e51b81526020600482015260116024820152706d696e6564547320746f6f206c6172676560781b6044820152606401610a78565b6001861b600080806116a88b858a611b31565b604080516020808201939093526001600160a01b038e1681830152606081018d905260808082018d90528251808303909101815260a09091019091528051910120919450925090506116fe8b8b838c8a8a611d1b565b9050600061170e84600019612de4565b9050808211156117515760405162461bcd60e51b815260206004820152600e60248201526d0c8d2cccc40dcdee840dac2e8c6d60931b6044820152606401610a78565b506117608b858b8b86866120e8565b505050505050505050505050565b6000610aec7f00000000000000000000000000000000000000000000000000000000000000006117be7f000000000000000000000000000000000000000000000000000000000000000185612cff565b61228a565b600082516000036117d657506000610aec565b60008260018486516117e89190612cec565b6117f29190612cff565b6117fc9190612de4565b90506000600182111561181757611812826122cb565b61181a565b60015b90506000816001600160401b0381111561183657611836612636565b60405190808252806020026020018201604052801561185f578160200160208202803683370190505b50905060005b828110156118e55760008061187a8884612da9565b90508851811061188b5750506118e5565b6000818a5161189a9190612cff565b90508881106118a65750875b808260208c0101209250828585815181106118c3576118c3612e3a565b60200260200101818152505050505080806118dd90612e50565b915050611865565b508192505b826001146119ce5760005b611900600285612de4565b8110156119bb5781611913826002612da9565b8151811061192357611923612e3a565b6020026020010151828260026119399190612da9565b611944906001612cec565b8151811061195457611954612e3a565b6020026020010151604051602001611976929190918252602082015260400190565b6040516020818303038152906040528051906020012082828151811061199e5761199e612e3a565b6020908102919091010152806119b381612e50565b9150506118f5565b506119c7600284612de4565b92506118ea565b806000815181106119e1576119e1612e3a565b6020026020010151935050505092915050565b610af242612308565b805160009084906001811b8510611a4a5760405162461bcd60e51b81526020600482015260116024820152706368756e6b4964206f766572666c6f777360781b6044820152606401610a78565b60005b81811015611b2657611a60600287612d95565b600003611ab95782858281518110611a7a57611a7a612e3a565b6020026020010151604051602001611a9c929190918252602082015260400190565b604051602081830303815290604052805190602001209250611b07565b848181518110611acb57611acb612e3a565b602002602001015183604051602001611aee929190918252602082015260400190565b6040516020818303038152906040528051906020012092505b611b12600287612de4565b955080611b1e81612e50565b915050611a4d565b509095945050505050565b600060606000846001600160401b03811115611b4f57611b4f612636565b604051908082528060200260200182016040528015611b78578160200160208202803683370190505b50600093509150829050805b85811015611d11576000611b988289612cec565b6000818152600360205260409020600181015491925090871015611bf25760405162461bcd60e51b81526020600482015260116024820152701b5a5b9959151cc81d1bdbc81cdb585b1b607a1b6044820152606401610a78565b611c8081887f000000000000000000000000000000000000000000000000000000000000012c7f00000000000000000000000000000000000000000000000000000000000000287f00000000000000000000000000000000000000000000000000000000000004007f00000000000000000000000000000000000000000000000000000000000000646123fb565b858481518110611c9257611c92612e3a565b602002602001018181525050848381518110611cb057611cb0612e3a565b602002602001015186611cc39190612cec565b81546040805160208101889052908101859052606081019190915290965060800160405160208183030381529060405280519060200120935050508080611d0990612e50565b915050611b84565b5093509350939050565b60007f0000000000000000000000000000000000000000000000000000000000000010825114611d8d5760405162461bcd60e51b815260206004820152601f60248201527f6461746120767320636865636b733a206c656e677468206d69736d61746368006044820152606401610a78565b7f0000000000000000000000000000000000000000000000000000000000000010835114611e075760405162461bcd60e51b815260206004820152602160248201527f70726f6f667320767320636865636b733a206c656e677468206d69736d6174636044820152600d60fb1b6064820152608401610a78565b60007f0000000000000000000000000000000000000000000000000000000000000005611e54887f0000000000000000000000000000000000000000000000000000000000000008612cec565b611e5e9190612cec565b6001901b905060005b7f00000000000000000000000000000000000000000000000000000000000000108110156120db5760007f0000000000000000000000000000000000000000000000000000000000001000905080858381518110611ec757611ec7612e3a565b60200260200101515114611f125760405162461bcd60e51b8152602060048201526012602482015271696e76616c69642070726f6f662073697a6560701b6044820152606401610a78565b6000611f1e848a612d95565b90506000611f6c7f00000000000000000000000000000000000000000000000000000000000000057f0000000000000000000000000000000000000000000000000000000000000008612cec565b611f79908d901b83612cec565b7f000000000000000000000000000000000000000000000000000000000000000581901c6000818152600260209081526040808320548352600182528083208151606081018352905464ffffffffff81168252600160281b810462ffffff1693820193909352600160401b909204811b67ffffffffffffffff19169082018190528b519495509293909261202b918691908f908e908c90811061201e5761201e612e3a565b602002602001015161151c565b905061205284838d8a8151811061204457612044612e3a565b602002602001015184611233565b6120955760405162461bcd60e51b815260206004820152601460248201527334b73b30b634b21030b1b1b2b9b990383937b7b360611b6044820152606401610a78565b60008a88815181106120a9576120a9612e3a565b602002602001015190508d81526020870181209d508681525050505050505080806120d390612e50565b915050611e67565b5094979650505050505050565b6000806120f361160d565b905060005b878110156121ce57600061210c828b612cec565b90508281116121bb5760008181526003602052604090206001810154612176907f00000000000000000000000000000000000000000000000000000000000000007f00000000000000000000000000000000000000000000000000000000000000081b908a6124c9565b6121809086612cec565b94506121b960036000848152602001908152602001600020898986815181106121ab576121ab612e3a565b602002602001015189612528565b505b50806121c681612e50565b9150506120f8565b5060006127106121fe7f00000000000000000000000000000000000000000000000000000000000003e885612da9565b6122089190612de4565b905060006122168285612cff565b604051909150419083156108fc029084906000818181858888f19350505050158015612246573d6000803e3d6000fd5b506040516001600160a01b0389169082156108fc029083906000818181858888f1935050505015801561227d573d6000803e3d6000fd5b5050505050505050505050565b600060806122b87f00000000000000000000000000000000000000000000000000000000000000008461254c565b6122c29085612da9565b901c9392505050565b60006122d8600183612cff565b91505b6122e6600183612cff565b821615612301576122f8600183612cff565b821691506122db565b5060011b90565b60005460017f000000000000000000000000000000000000000000000000000000000000000881901b916123459164ffffffffff90911690612c65565b64ffffffffff166123569190612d95565b60000361123057600080547f0000000000000000000000000000000000000000000000000000000000000008906123959064ffffffffff166001612c65565b64ffffffffff16901c60016123aa9190612c65565b64ffffffffff16600081815260036020819052604082206001908101869055929350916123d79084612cff565b81526020808201929092526040908101600090812054938152600390925290205550565b60008087600101548761240e9190612cff565b60028901549091508682101561246557848161242a8885612de4565b612435906001612cff565b61243f9190612da9565b6124499190612de4565b6124539082612cec565b9050838110156124605750825b6124bd565b6000858260016124758a87612de4565b61247f9190612cff565b6124899190612da9565b6124939190612de4565b9050816124a08683612cec565b11156124ae578491506124bb565b6124b88183612cff565b91505b505b98975050505050505050565b600061121e846124f97f000000000000000000000000000000000000000000000000000000000000000186612cff565b6125237f000000000000000000000000000000000000000000000000000000000000000186612cff565b612558565b6003840154612538906001612cec565b600385015583556002830155600190910155565b600061112683836125ce565b600060806125867f00000000000000000000000000000000000000000000000000000000000000008461254c565b6125b07f00000000000000000000000000000000000000000000000000000000000000008661254c565b6125ba9190612cff565b6125c49086612da9565b901c949350505050565b6000600160801b5b821561112657826001166001036125f85760806125f38583612da9565b901c90505b60806126048580612da9565b901c9350612613600284612de4565b92506125d6565b80356001600160a01b038116811461263157600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b604051606081016001600160401b038111828210171561266e5761266e612636565b60405290565b604051601f8201601f191681016001600160401b038111828210171561269c5761269c612636565b604052919050565b60006001600160401b038211156126bd576126bd612636565b5060051b60200190565b600082601f8301126126d857600080fd5b813560206126ed6126e8836126a4565b612674565b82815260059290921b8401810191818101908684111561270c57600080fd5b8286015b848110156127275780358352918301918301612710565b509695505050505050565b60006001600160401b0382111561274b5761274b612636565b50601f01601f191660200190565b600082601f83011261276a57600080fd5b81356127786126e882612732565b81815284602083860101111561278d57600080fd5b816020850160208301376000918101602001919091529392505050565b600082601f8301126127bb57600080fd5b813560206127cb6126e8836126a4565b82815260059290921b840181019181810190868411156127ea57600080fd5b8286015b848110156127275780356001600160401b0381111561280d5760008081fd5b61281b8986838b0101612759565b8452509183019183016127ee565b600080600080600080600060e0888a03121561284457600080fd5b873596506020880135955061285b6040890161261a565b9450606088013593506080880135925060a08801356001600160401b038082111561288557600080fd5b818a0191508a601f83011261289957600080fd5b81356128a76126e8826126a4565b8082825260208201915060208360051b86010192508d8311156128c957600080fd5b602085015b838110156129025784813511156128e457600080fd5b6128f48f602083358901016126c7565b8352602092830192016128ce565b509550505060c08a013591508082111561291b57600080fd5b506129288a828b016127aa565b91505092959891949750929550565b6000806040838503121561294a57600080fd5b8235915060208301356001600160401b0381111561296757600080fd5b61297385828601612759565b9150509250929050565b60006020828403121561298f57600080fd5b5035919050565b600080604083850312156129a957600080fd5b823591506129b96020840161261a565b90509250929050565b803567ffffffffffffffff198116811461263157600080fd5b6000806000606084860312156129f057600080fd5b83359250612a00602085016129c2565b915060408401356001600160401b03811115612a1b57600080fd5b612a2786828701612759565b9150509250925092565b600080600060608486031215612a4657600080fd5b505081359360208301359350604090920135919050565b60005b83811015612a78578181015183820152602001612a60565b50506000910152565b60008151808452612a99816020860160208601612a5d565b601f01601f19169290920160200192915050565b6020815260006111266020830184612a81565b60008060008060808587031215612ad657600080fd5b612adf856129c2565b966020860135965060408601359560600135945092505050565b60008060008084860360c0811215612b1057600080fd5b853594506060601f1982011215612b2657600080fd5b50612b2f61264c565b602086013564ffffffffff81168114612b4757600080fd5b8152604086013562ffffff81168114612b5f57600080fd5b6020820152612b70606087016129c2565b6040820152925060808501356001600160401b0380821115612b9157600080fd5b612b9d888389016126c7565b935060a0870135915080821115612bb357600080fd5b50612bc087828801612759565b91505092959194509250565b60008060408385031215612bdf57600080fd5b50508035926020909101359150565b60008060008060808587031215612c0457600080fd5b84356001600160401b038082168214612c1c57600080fd5b819550612c2b602088016129c2565b9450612c396040880161261a565b93506060870135915080821115612bb357600080fd5b634e487b7160e01b600052601160045260246000fd5b64ffffffffff818116838216019080821115612c8357612c83612c4f565b5092915050565b64ffffffffff828116828216039080821115612c8357612c83612c4f565b838152826020820152606060408201526000612cc76060830184612a81565b95945050505050565b60008251612ce2818460208701612a5d565b9190910192915050565b80820180821115610aec57610aec612c4f565b81810381811115610aec57610aec612c4f565b600060208284031215612d2457600080fd5b81516001600160401b03811115612d3a57600080fd5b8201601f81018413612d4b57600080fd5b8051612d596126e882612732565b818152856020838501011115612d6e57600080fd5b612cc7826020830160208601612a5d565b634e487b7160e01b600052601260045260246000fd5b600082612da457612da4612d7f565b500690565b6000816000190483118215151615612dc357612dc3612c4f565b500290565b62ffffff828116828216039080821115612c8357612c83612c4f565b600082612df357612df3612d7f565b500490565b6001600160401b03868116825285166020820152604081018490526001600160a01b038316606082015260a06080820181905260009061160290830184612a81565b634e487b7160e01b600052603260045260246000fd5b600060018201612e6257612e62612c4f565b506001019056fea264697066735822122072716e1b60b5ab22d33177b24cd13514667588f7c7a604a6defab6bfd247f2c864736f6c63430008100033"),
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
	evm.StateDB.SstorageWrite(caller, kvIdx, kvHash, getData(input, dataPtr+32, putLen))
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
	log.Debug("sstoragePisaUnmaskDaggerData() returns", "encodeType", encodeType, "chunkIdx", chunkIdx, "kvHash", kvHash, "miner", miner, "datalen", datalen)
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
