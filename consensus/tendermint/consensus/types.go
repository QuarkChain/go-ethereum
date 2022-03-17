package consensus

import (
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type (
	Vote          = types.Vote
	VoteMessage   = types.VoteMessage
	Validator     = types.Validator
	ValidatorSet  = types.ValidatorSet
	VoteSet       = types.VoteSet
	HeightVoteSet = types.HeightVoteSet
	FullBlock     = types.FullBlock
	Commit        = types.Commit
	// BlockIDFlag indicates which BlockID the signature is for.
	BlockIDFlag     = types.BlockIDFlag
	CommitSig       = types.CommitSig
	Proposal        = types.Proposal
	ProposalMessage = types.ProposalMessage
	ConsensusConfig = params.ConsensusConfig

	Header = types.Header

	ErrVoteConflictingVotes = types.ErrVoteConflictingVotes
)

var (
	NewVoteSet                       = types.NewVoteSet
	NewValidatorSet                  = types.NewValidatorSet
	VerifyCommit                     = types.VerifyCommit
	NewHeightVoteSet                 = types.NewHeightVoteSet
	ErrVoteNonDeterministicSignature = types.ErrVoteNonDeterministicSignature
	// BlockIDFlagAbsent - no vote was received from a validator.
	BlockIDFlagAbsent BlockIDFlag = types.BlockIDFlagAbsent
	// BlockIDFlagCommit - voted for the Commit.BlockID.
	BlockIDFlagCommit = types.BlockIDFlagCommit
	// BlockIDFlagNil - voted for nil.
	BlockIDFlagNil = types.BlockIDFlagAbsent

	NewCommit          = types.NewCommit
	CommitToVoteSet    = types.CommitToVoteSet
	NewProposal        = types.NewProposal
	NewCommitSigAbsent = types.NewCommitSigAbsent
)

// func NewBlock(header *types.Header, body *types.Body, lastCommit *Commit) *Block {
// 	header.LastCommitHash = lastCommit.Hash()
// 	return &Block{Header: header, Body: body, LastCommit: lastCommit}
// }

var MaxSignatureSize = 65

// Now returns the current time in UTC with no monotonic component.
func CanonicalNow() time.Time {
	return Canonical(time.Now())
}

func CanonicalNowMs() int64 {
	return time.Now().UnixMilli()
}

// Canonical returns UTC time with no monotonic component.
// Stripping the monotonic component is for time equality.
// See https://github.com/tendermint/tendermint/pull/2203#discussion_r215064334
func Canonical(t time.Time) time.Time {
	return t.Round(0).UTC()
}

// Ask for consensus sync to another peer
// The consensus will response with a list of votes and possible proposal
type ConsensusSyncRequest struct {
	Height           uint64
	Round            uint32
	HasProposal      uint8 // whether the proposal is received
	PrevotesBitmap   []uint64
	PrecommitsBitmap []uint64
}

// Internal struct to request async
type consensusSyncRequestAsync struct {
	req      *ConsensusSyncRequest
	respChan chan []interface{}
}

type ConsensusSyncResponse struct {
	IsCommited  uint8 // whether return a commited block or proposal/vote messages
	MessageData [][]byte
}

func (csr *ConsensusSyncRequest) ValidateBasic() error {
	return nil
}
