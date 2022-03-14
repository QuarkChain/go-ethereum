package consensus

import (
	"time"
)

// RoundState defines the internal consensus state.
// NOTE: Not thread safe. Should only be manipulated by functions downstream
// of the cs.receiveRoutine
type RoundState struct {
	Height    uint64        `json:"height"` // Height we are working on
	Round     int32         `json:"round"`
	Step      RoundStepType `json:"step"`
	StartTime time.Time     `json:"start_time"`

	// Subjective time when +2/3 precommits for Block at Round were found
	CommitTime    time.Time     `json:"commit_time"`
	Validators    *ValidatorSet `json:"validators"`
	Proposal      *Proposal     `json:"proposal"`
	ProposalBlock *FullBlock    `json:"proposal_block"`
	LockedRound   int32         `json:"locked_round"`
	LockedBlock   *FullBlock    `json:"locked_block"`

	// Last known round with POL for non-nil valid block.
	ValidRound int32      `json:"valid_round"`
	ValidBlock *FullBlock `json:"valid_block"` // Last known block of POL mentioned above.

	// Last known block parts of POL mentioned above.
	Votes                     *HeightVoteSet `json:"votes"`
	CommitRound               int32          `json:"commit_round"` //
	LastCommit                *VoteSet       `json:"last_commit"`  // Last precommits at Height-1
	LastValidators            *ValidatorSet  `json:"last_validators"`
	TriggeredTimeoutPrecommit bool           `json:"triggered_timeout_precommit"`
}

// NOTE: This goes into the replay WAL
type EventDataRoundState struct {
	Height uint64 `json:"height"`
	Round  int32  `json:"round"`
	Step   string `json:"step"`
}

// RoundStateEvent returns the H/R/S of the RoundState as an event.
func (rs *RoundState) RoundStateEvent() EventDataRoundState {
	return EventDataRoundState{
		Height: rs.Height,
		Round:  rs.Round,
		Step:   rs.Step.String(),
	}
}

//-----------------------------------------------------------------------------
// RoundStepType enum type

// RoundStepType enumerates the state of the consensus state machine
type RoundStepType uint8 // These must be numeric, ordered.

// RoundStepType
const (
	RoundStepNewHeight     = RoundStepType(0x01) // Wait til CommitTime + timeoutCommit
	RoundStepNewRound      = RoundStepType(0x02) // Setup new round and go to RoundStepPropose
	RoundStepPropose       = RoundStepType(0x03) // Did propose, gossip proposal
	RoundStepPrevote       = RoundStepType(0x04) // Did prevote, gossip prevotes
	RoundStepPrevoteWait   = RoundStepType(0x05) // Did receive any +2/3 prevotes, start timeout
	RoundStepPrecommit     = RoundStepType(0x06) // Did precommit, gossip precommits
	RoundStepPrecommitWait = RoundStepType(0x07) // Did receive any +2/3 precommits, start timeout
	RoundStepCommit        = RoundStepType(0x08) // Entered commit state machine
	// NOTE: RoundStepNewHeight acts as RoundStepCommitWait.

	// NOTE: Update IsValid method if you change this!
)

// IsValid returns true if the step is valid, false if unknown/undefined.
func (rs RoundStepType) IsValid() bool {
	return uint8(rs) >= 0x01 && uint8(rs) <= 0x08
}

// String returns a string
func (rs RoundStepType) String() string {
	switch rs {
	case RoundStepNewHeight:
		return "RoundStepNewHeight"
	case RoundStepNewRound:
		return "RoundStepNewRound"
	case RoundStepPropose:
		return "RoundStepPropose"
	case RoundStepPrevote:
		return "RoundStepPrevote"
	case RoundStepPrevoteWait:
		return "RoundStepPrevoteWait"
	case RoundStepPrecommit:
		return "RoundStepPrecommit"
	case RoundStepPrecommitWait:
		return "RoundStepPrecommitWait"
	case RoundStepCommit:
		return "RoundStepCommit"
	default:
		return "RoundStepUnknown" // Cannot panic.
	}
}
