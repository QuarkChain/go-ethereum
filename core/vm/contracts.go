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
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/sstorage"
	"github.com/ethereum/go-ethereum/sstorage/pora"

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
	// Get the url of DecentralizedKVWithSM: https://github.com/ethstorage/storage-contracts/blob/precompile-debug/contracts/DecentralizedKVWthSM.sol
	// contract at 0x0000000000000000000000000000000003330001 is complied DecentralizedKVWithSM(4096, 4096, 0, 0, 0)+8df45f5f+0.8.17 solc (enable optimized)
	systemContracts = map[common.Address][]byte{
		common.HexToAddress("0x0000000000000000000000000000000003330001"): common.Hex2Bytes("6080604052600436106101145760003560e01c806378e97925116100a0578063afd5644d11610064578063afd5644d146103ab578063c4a942cb1461040d578063cde0ac8314610441578063dd7e57d414610458578063e7a84c461461046f57600080fd5b806378e97925146102d8578063896b49911461030c57806395bc267314610323578063a097365f14610343578063a4a8435e1461037757600080fd5b806344e77d99116100e757806344e77d99146101d957806349bdd6f5146101ee5780636da6d51e1461020e57806373e8b3d41461023d578063749cf282146102ab57600080fd5b80631ccbc6da14610119578063258ae582146101415780633cb2fecc14610171578063429dd7ad146101a5575b600080fd5b34801561012557600080fd5b5061012e610486565b6040519081526020015b60405180910390f35b34801561014d57600080fd5b5061016161015c366004611189565b610496565b6040519015158152602001610138565b34801561017d57600080fd5b5061012e7f000000000000000000000000000000000000000000000000000000000000000081565b3480156101b157600080fd5b506000546101c39064ffffffffff1681565b60405164ffffffffff9091168152602001610138565b6101ec6101e7366004611189565b6105c7565b005b3480156101fa57600080fd5b506101ec610209366004611213565b6107eb565b34801561021a57600080fd5b506102256203330281565b6040516001600160a01b039091168152602001610138565b34801561024957600080fd5b5061016161025836600461124f565b60408051336020808301919091528183019390935281518082038301815260609091018252805190830120600090815260019092529081902054600160401b9004901b67ffffffffffffffff1916151590565b3480156102b757600080fd5b506102cb6102c6366004611268565b610a23565b60405161013891906112e4565b3480156102e457600080fd5b5061012e7f000000000000000000000000000000000000000000000000000000000000000081565b34801561031857600080fd5b506102256203330581565b34801561032f57600080fd5b506101ec61033e36600461124f565b610b58565b34801561034f57600080fd5b5061012e7f000000000000000000000000000000000000000000000000000000000000100081565b34801561038357600080fd5b5061012e7f000000000000000000000000000000000000000000000000000000000000000081565b3480156103b757600080fd5b5061012e6103c636600461124f565b6040805133602080830191909152818301939093528151808203830181526060909101825280519083012060009081526001909252902054600160281b900462ffffff1690565b34801561041957600080fd5b5061012e7f000000000000000000000000000000000000000000000000000000000000100081565b34801561044d57600080fd5b506102256203330181565b34801561046457600080fd5b506102256203330381565b34801561047b57600080fd5b506102256203330481565b600061049142610b65565b905090565b60408051336020820152908101839052600090819060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff19169284018390529350036105545760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b60448201526064015b60405180910390fd5b8351816020015162ffffff1614610570576000925050506105c1565b600061059c857f0000000000000000000000000000000000000000000000000000000000001000610bba565b90508067ffffffffffffffff1916826040015167ffffffffffffffff19161493505050505b92915050565b7f0000000000000000000000000000000000000000000000000000000000001000815111156106295760405162461bcd60e51b815260206004820152600e60248201526d6461746120746f6f206c6172676560901b604482015260640161054b565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff81168652600160281b810462ffffff1693860193909352600160401b909204831b67ffffffffffffffff191692840183905293500361073e576106b1610486565b3410156106f55760405162461bcd60e51b81526020600482015260126024820152711b9bdd08195b9bdd59da081c185e5b595b9d60721b604482015260640161054b565b6000805464ffffffffff908116808452825260026020526040822084905590546107219116600161130d565b6000805464ffffffffff191664ffffffffff929092169190911790555b825162ffffff166020820152610774837f0000000000000000000000000000000000000000000000000000000000001000610bba565b67ffffffffffffffff199081166040808401918252600085815260016020908152908290208551815492870151945190931c600160401b0262ffffff909416600160281b029190941664ffffffffff9092169182171767ffffffffffffffff16919091179091556107e59084610dec565b50505050565b6040805133602082015290810183905260009060600160408051808303601f1901815282825280516020918201206000818152600183528381206060860185525464ffffffffff8116808752600160281b820462ffffff1694870194909452600160401b9004841b67ffffffffffffffff1916938501849052909450909190036108a65760405162461bcd60e51b815260206004820152600c60248201526b1add881b9bdd08195e1a5cdd60a21b604482015260640161054b565b6040805160608101825260008082526020808301828152838501838152888452600192839052858420945185549251915190961c600160401b0262ffffff91909116600160281b0267ffffffffffffffff199290921664ffffffffff968716179190911767ffffffffffffffff161790925580549092600292849261092b9216611332565b64ffffffffff908116825260208083019390935260409182016000908120548683168083526002808752858420839055828452600196879052948320805464ffffffffff191690911790558154909550909384926109899216611332565b64ffffffffff9081168252602082019290925260400160009081209290925590546109b79160019116611332565b6000805464ffffffffff191664ffffffffff9283169081179091556109dd918416610eb3565b846001600160a01b03166108fc6109f2610486565b6040518115909202916000818181858888f19350505050158015610a1a573d6000803e3d6000fd5b50505050505050565b606081600003610a425750604080516000815260208101909152610b51565b6040805133602082015290810185905260009060600160408051808303601f1901815282825280516020918201206000818152600183528390206060850184525464ffffffffff81168552600160281b810462ffffff16928501839052600160401b9004831b67ffffffffffffffff1916928401929092529092508510610adb5750506040805160008152602081019091529050610b51565b602081015162ffffff16610aef8686611350565b1115610b0d5784816020015162ffffff16610b0a9190611363565b93505b6000610b35826040015167ffffffffffffffff1916836000015164ffffffffff168888610f72565b905080806020019051810190610b4b9190611376565b93505050505b9392505050565b610b6281336107eb565b50565b60006105c17f0000000000000000000000000000000000000000000000000000000000000000610bb57f000000000000000000000000000000000000000000000000000000000000000085611363565b611049565b60008251600003610bcd575060006105c1565b6000826001848651610bdf9190611350565b610be99190611363565b610bf391906113ed565b905060006001821115610c0e57610c098261108a565b610c11565b60015b905060008167ffffffffffffffff811115610c2e57610c2e61111a565b604051908082528060200260200182016040528015610c57578160200160208202803683370190505b50905060005b82811015610cdd57600080610c72888461140f565b905088518110610c83575050610cdd565b6000818a51610c929190611363565b9050888110610c9e5750875b808260208c010120925082858581518110610cbb57610cbb611426565b6020026020010181815250505050508080610cd59061143c565b915050610c5d565b508192505b82600114610dc65760005b610cf86002856113ed565b811015610db35781610d0b82600261140f565b81518110610d1b57610d1b611426565b602002602001015182826002610d31919061140f565b610d3c906001611350565b81518110610d4c57610d4c611426565b6020026020010151604051602001610d6e929190918252602082015260400190565b60405160208183030381529060405280519060200120828281518110610d9657610d96611426565b602090810291909101015280610dab8161143c565b915050610ced565b50610dbf6002846113ed565b9250610ce2565b80600081518110610dd957610dd9611426565b6020026020010151935050505092915050565b6000620333026001600160a01b03168383604051602001610e0e929190611455565b60408051601f1981840301815290829052610e2891611476565b6000604051808303816000865af19150503d8060008114610e65576040519150601f19603f3d011682016040523d82523d6000602084013e610e6a565b606091505b5050905080610eae5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2070757452617760801b604482015260640161054b565b505050565b6040805160208101849052908101829052600090620333059060600160408051601f1981840301815290829052610ee991611476565b6000604051808303816000865af19150503d8060008114610f26576040519150601f19603f3d011682016040523d82523d6000602084013e610f2b565b606091505b5050905080610eae5760405162461bcd60e51b81526020600482015260136024820152726661696c656420746f2072656d6f766552617760681b604482015260640161054b565b6040805160208101869052908101849052606081810184905260808201839052906000908190620333039060a00160408051601f1981840301815290829052610fba91611476565b600060405180830381855afa9150503d8060008114610ff5576040519150601f19603f3d011682016040523d82523d6000602084013e610ffa565b606091505b50915091508161103f5760405162461bcd60e51b815260206004820152601060248201526f6661696c656420746f2067657452617760801b604482015260640161054b565b9695505050505050565b600060806110777f0000000000000000000000000000000000000000000000000000000000000000846110c7565b611081908561140f565b901c9392505050565b6000611097600183611363565b91505b6110a5600183611363565b8216156110c0576110b7600183611363565b8216915061109a565b5060011b90565b6000610b5183836000600160801b5b8215610b5157826001166001036110f85760806110f3858361140f565b901c90505b6080611104858061140f565b901c93506111136002846113ed565b92506110d6565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f1916810167ffffffffffffffff811182821017156111595761115961111a565b604052919050565b600067ffffffffffffffff82111561117b5761117b61111a565b50601f01601f191660200190565b6000806040838503121561119c57600080fd5b82359150602083013567ffffffffffffffff8111156111ba57600080fd5b8301601f810185136111cb57600080fd5b80356111de6111d982611161565b611130565b8181528660208385010111156111f357600080fd5b816020840160208301376000602083830101528093505050509250929050565b6000806040838503121561122657600080fd5b8235915060208301356001600160a01b038116811461124457600080fd5b809150509250929050565b60006020828403121561126157600080fd5b5035919050565b60008060006060848603121561127d57600080fd5b505081359360208301359350604090920135919050565b60005b838110156112af578181015183820152602001611297565b50506000910152565b600081518084526112d0816020860160208601611294565b601f01601f19169290920160200192915050565b602081526000610b5160208301846112b8565b634e487b7160e01b600052601160045260246000fd5b64ffffffffff81811683821601908082111561132b5761132b6112f7565b5092915050565b64ffffffffff82811682821603908082111561132b5761132b6112f7565b808201808211156105c1576105c16112f7565b818103818111156105c1576105c16112f7565b60006020828403121561138857600080fd5b815167ffffffffffffffff81111561139f57600080fd5b8201601f810184136113b057600080fd5b80516113be6111d982611161565b8181528560208385010111156113d357600080fd5b6113e4826020830160208601611294565b95945050505050565b60008261140a57634e487b7160e01b600052601260045260246000fd5b500490565b80820281158282048414176105c1576105c16112f7565b634e487b7160e01b600052603260045260246000fd5b60006001820161144e5761144e6112f7565b5060010190565b82815260406020820152600061146e60408301846112b8565b949350505050565b60008251611488818460208701611294565b919091019291505056fea2646970667358221220125c08d0109202481f64acb9739ff06df3912ffe4e84bf751f6e68ee5e8d098464736f6c63430008110033"),
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
	dataPtr := new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
	if dataPtr > uint64(len(input)) {
		return nil, errors.New("dataptr too large")
	}
	putLen := new(big.Int).SetBytes(getData(input, dataPtr, 32)).Uint64()

	if putLen > maxKVSize {
		return nil, errors.New("put len too large")
	}
	evm.StateDB.SstorageWrite(caller, kvIdx, getData(input, dataPtr+32, putLen))
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
	maxKVSize := evm.StateDB.SstorageMaxKVSize(caller)
	if maxKVSize == 0 {
		return nil, errors.New("invalid caller")
	}

	if !evm.Config.IsJsonRpc {
		return nil, errors.New("getRaw() must be called in JSON RPC")
	}
	// TODO: check hash correctness
	hash := common.BytesToHash(getData(input, 0, 32))
	kvIdx := new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
	kvOff := new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	kvLen := new(big.Int).SetBytes(getData(input, 96, 32)).Uint64()
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
	evm := env.evm
	caller := env.caller.Address()
	maxKVSize := evm.StateDB.SstorageMaxKVSize(caller)
	if maxKVSize == 0 {
		return nil, errors.New("invalid caller")
	}

	values, err := unmaskDaggerDataInputAbi.Unpack(input[:])
	if err != nil {
		return nil, fmt.Errorf("Arguments.Unpack failed:%v", err)
	}
	var decoded unmaskDaggerDataInput
	err = unmaskDaggerDataInputAbi.Copy(&decoded, values)
	if err != nil {
		return nil, fmt.Errorf("Arguments.Copy failed:%v", err)
	}

	return unmaskDaggerDataImpl(caller, decoded)

}

// TODO: remove is not supported yet
type sstoragePisaRemoveRaw struct {
}

func unmaskDaggerDataImpl(caller common.Address, decoded unmaskDaggerDataInput) ([]byte, error) {
	if uint64(len(decoded.MaskedChunk)) > sstorage.CHUNK_SIZE {
		return nil, fmt.Errorf("invalid chunk size")
	}

	epoch := decoded.Epoch.Uint64()
	cache := pora.Cache(epoch)

	size := ethash.DatasetSizeForEpoch(epoch)

	shardMgr := sstorage.ContractToShardManager[caller]
	if shardMgr == nil {
		return nil, fmt.Errorf("invalid caller")
	}
	realHash := make([]byte, len(decoded.Hash)+8)
	copy(realHash, decoded.Hash[:])

	// in order to not touch the input buffer
	copyBytes := make([]byte, len(decoded.MaskedChunk))
	copy(copyBytes, decoded.MaskedChunk)
	decoded.MaskedChunk = copyBytes

	for i := 0; i < len(decoded.MaskedChunk)/ethash.GetMixBytes(); i++ {
		pora.ToRealHash(decoded.Hash, shardMgr.MaxKvSize(), uint64(i), realHash, false)
		mask := ethash.HashimotoForMaskLight(size, cache.Cache, realHash)
		if len(mask) != ethash.GetMixBytes() {
			panic("#mask != MixBytes")
		}
		for j := 0; j < ethash.GetMixBytes(); j++ {
			decoded.MaskedChunk[i*ethash.GetMixBytes()+j] ^= mask[j]
		}
	}
	tailBytes := len(decoded.MaskedChunk) % ethash.GetMixBytes()
	if tailBytes > 0 {
		i := len(decoded.MaskedChunk) / ethash.GetMixBytes()
		pora.ToRealHash(decoded.Hash, shardMgr.MaxKvSize(), uint64(i), realHash, false)
		mask := ethash.HashimotoForMaskLight(size, cache.Cache, realHash)
		if len(mask) != ethash.GetMixBytes() {
			panic("#mask != MixBytes")
		}
		for j := 0; j < tailBytes; j++ {
			decoded.MaskedChunk[i*ethash.GetMixBytes()+j] ^= mask[j]
		}
	}

	return unmaskDaggerDataOutputAbi.Pack(decoded.MaskedChunk)
}

var (
	unmaskDaggerDataInputAbi, unmaskDaggerDataOutputAbi abi.Arguments
)

type unmaskDaggerDataInput struct {
	Epoch       *big.Int
	Hash        common.Hash
	MaskedChunk []byte
}

func init() {
	BytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		panic(err)
	}
	Bytes32Ty, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		panic(err)
	}
	IntTy, err := abi.NewType("uint256", "", nil)
	if err != nil {
		panic(err)
	}

	unmaskDaggerDataInputAbi = abi.Arguments{
		{Type: IntTy, Name: "epoch"},
		{Type: Bytes32Ty, Name: "hash"},
		{Type: BytesTy, Name: "maskedChunk"},
	}

	unmaskDaggerDataOutputAbi = abi.Arguments{
		{Type: BytesTy, Name: "unmaskedChunk"},
	}
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

	if env.evm.MRContext.ReplayMindReading {
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
		Success: err != nil,
		GasUsed: gasUsed,
	}
	env.evm.appendCCCOutput(crossChainCallOutput)
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

	if maxDataLen > MaxDataLenLimitation {
		return nil, 0, ErrMaxDataLenOutOfLimit, nil
	}

	// Ensure that the number of confirmations meets the minimum requirement which is defined by chainConfig
	if confirms < env.evm.MRContext.MinimumConfirms {
		return nil, 0, ErrUserDefinedConfirmsTooSmall, nil
	}

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

	packedLogData, err := logData.ABIPack()
	// TODO: will the error happen?
	if err != nil {
		return nil, 0, nil, err
	}

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
