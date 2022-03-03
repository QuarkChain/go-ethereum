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

// Package tendermint implements the proof-of-stake consensus engine.
package tendermint

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"time"

	pbftconsensus "github.com/QuarkChain/go-minimal-pbft/consensus"
	libp2p "github.com/QuarkChain/go-minimal-pbft/p2p"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/tendermint/adapter"
	"github.com/ethereum/go-ethereum/consensus/tendermint/gov"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
)

// Clique proof-of-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	nonceDefault = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")
)

// Clique is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Tendermint struct {
	config        *params.TendermintConfig // Consensus engine configuration parameters
	rootCtxCancel context.CancelFunc
	rootCtx       context.Context
	governance    *gov.Governance
	chain         *core.BlockChain
}

// New creates a Clique proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.TendermintConfig) *Tendermint {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}

	return &Tendermint{
		config: &conf,
	}
}

func (c *Tendermint) SetBlockChain(chain *core.BlockChain) {
	// governance
	governance := gov.New(c.config.Epoch, chain)
	c.governance = governance
	c.chain = chain
}

func (c *Tendermint) Init(makeBlock func(chan *types.Block)) (err error) {
	chain := c.chain
	// Outbound gossip message queue
	sendC := make(chan pbftconsensus.Message, 1000)

	// Inbound observations
	obsvC := make(chan pbftconsensus.MsgInfo, 1000)

	// Node's main lifecycle context.
	rootCtx, rootCtxCancel := context.WithCancel(context.Background())
	c.rootCtxCancel = rootCtxCancel
	c.rootCtx = rootCtx

	makeFullBlock := func() *types.FullBlock {
		resultCh := make(chan *types.Block, 1)
		makeBlock(resultCh)
		select {
		case block := <-resultCh:
			if block == nil {
				return nil
			}
			parent := chain.GetHeaderByHash(block.ParentHash())
			if parent == nil {
				return nil
			}
			return &types.FullBlock{Block: block, LastCommit: parent.Commit}
		case <-rootCtx.Done():
			return nil
		}
	}
	// datastore
	store := adapter.NewStore(chain, c.governance, c.VerifyHeader, makeFullBlock)

	// validator key
	valKey, err := loadValidatorKey(c.config.ValKeyPath)
	if err != nil {
		return
	}

	var privVal pbftconsensus.PrivValidator
	privVal = pbftconsensus.NewPrivValidatorLocal(valKey)

	// p2p key
	p2pPriv, err := loadP2pKey(c.config.NodeKeyPath)
	if err != nil {
		return
	}

	// p2p server
	p2pserver, err := libp2p.NewP2PServer(rootCtx, store, obsvC, sendC, p2pPriv, c.config.P2pPort, c.config.NetworkID, c.config.P2pBootstrap, c.config.NodeName, rootCtxCancel)
	if err != nil {
		return
	}

	go func() {
		err := p2pserver.Run(rootCtx)
		if err != nil {
			log.Warn("p2pserver.Run", "err", err)
		}
	}()

	genesis := chain.GetHeaderByNumber(0)
	gcs := pbftconsensus.MakeGenesisChainState(c.config.NetworkID, genesis.Time, genesis.NextValidators, c.config.Epoch)

	// consensus
	consensusState := pbftconsensus.NewConsensusState(
		rootCtx,
		pbftconsensus.NewDefaultConsesusConfig(),
		*gcs,
		store,
		store,
		obsvC,
		sendC,
	)

	consensusState.SetPrivValidator(privVal)

	err = consensusState.Start(rootCtx)
	if err != nil {
		log.Warn("consensusState.Start", "err", err)
	}

	return
}

func loadP2pKey(filename string) (key p2pcrypto.PrivKey, err error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		err = fmt.Errorf("failed to read node key: %w", err)
		return
	}
	key, err = p2pcrypto.UnmarshalPrivateKey(b)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal node key: %w", err)
		return
	}
	return
}

// loadValidatorKey loads a serialized guardian key from disk.
func loadValidatorKey(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	gk, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize raw key data: %w", err)
	}

	return gk, nil
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *Tendermint) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Tendermint) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil, seal)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Tendermint) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i], seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Tendermint) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header, seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}

	nextValidators := c.governance.NextValidators(number)
	if !reflect.DeepEqual(nextValidators, header.NextValidators) {
		return errors.New("invalid NextValidators")
	}
	if !bytes.Equal(header.Nonce[:], nonceDefault) {
		return errors.New("invalid nonce")
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(big.NewInt(0)) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify signatures fields
	if !seal {
		return nil
	}

	epochHeader := c.getEpochHeader(chain, header)
	if epochHeader == nil {
		return fmt.Errorf("epochHeader not found, height:%d", number)
	}

	vs := types.NewValidatorSet(epochHeader.NextValidators)
	return vs.VerifyCommit(c.config.NetworkID, header.Hash(), number, header.Commit)
}

func (c *Tendermint) getEpochHeader(chain consensus.ChainHeaderReader, header *types.Header) *types.Header {
	number := header.Number.Uint64()
	checkpoint := (number % c.config.Epoch) == 0
	var epochHeight uint64
	if checkpoint {
		epochHeight -= c.config.Epoch
	} else {
		epochHeight = number - (number % c.config.Epoch)
	}
	return chain.GetHeaderByNumber(epochHeight)

}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Tendermint) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Tendermint) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	number := header.Number.Uint64()
	epochHeader := c.getEpochHeader(chain, header)
	if epochHeader == nil {
		return fmt.Errorf("epochHeader not found, height:%d", number)
	}
	parentHeader := chain.GetHeaderByHash(header.ParentHash)
	if epochHeader == nil {
		return fmt.Errorf("parentHeader not found, height:%d", number)
	}

	header.LastCommitHash = parentHeader.Commit.Hash()
	var timestamp uint64
	if number == 1 {
		timestamp = parentHeader.TimeMs // genesis time
	} else {
		timestamp = pbftconsensus.MedianTime(parentHeader.Commit, types.NewValidatorSet(epochHeader.NextValidators))
	}

	header.TimeMs = timestamp
	header.Time = timestamp / 1000

	header.NextValidators = c.governance.NextValidators(number)
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (c *Tendermint) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// No block rewards at the moment, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (c *Tendermint) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Finalize block
	c.Finalize(chain, header, state, txs, uncles)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Tendermint) Seal(chain consensus.ChainHeaderReader, block *types.Block, resultCh chan<- *types.Block, stop <-chan struct{}) error {
	// resultCh is generated by makeFullBlock
	select {
	case resultCh <- block:
	case <-c.rootCtx.Done():
	}
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
func (c *Tendermint) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	// TOOD: no diff is required
	return big.NewInt(0)
}

// SealHash returns the hash of a block prior to it being sealed.
func (c *Tendermint) SealHash(header *types.Header) common.Hash {
	return header.Hash()
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (c *Tendermint) Close() error {
	if c.rootCtxCancel != nil {
		c.rootCtxCancel()
	}

	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Tendermint) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{}}
}
