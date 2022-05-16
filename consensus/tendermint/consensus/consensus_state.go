package consensus

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// Message defines an interface that the consensus domain types implement. When
// a proto message is received on a consensus p2p Channel, it is wrapped and then
// converted to a Message via MsgFromProto.
type Message interface {
	ValidateBasic() error
}

// msgs from the reactor which may update the state
type MsgInfo struct {
	Msg    Message `json:"msg"`
	PeerID string  `json:"peer_key"`
}

// SignedMsgType is a type of signed message in the consensus.
type SignedMsgType = types.SignedMsgType

const (
	UnknownType SignedMsgType = types.UnknownType
	// Votes
	PrevoteType   SignedMsgType = types.PrevoteType
	PrecommitType SignedMsgType = types.PrecommitType
	// Proposals
	ProposalType SignedMsgType = types.ProposalType
)

// IsVoteTypeValid returns true if t is a valid vote type.
func IsVoteTypeValid(t SignedMsgType) bool {
	switch t {
	case PrevoteType, PrecommitType:
		return true
	default:
		return false
	}
}

type BlockStore interface {
	Base() uint64   // first known contiguous block height
	Height() uint64 // last known contiguous block height
	Size() uint64   // return number of blocks in the store

	LoadBlock(height uint64) *FullBlock
	LoadBlockCommit(height uint64) *Commit
	LoadSeenCommit() *Commit

	SaveBlock(*FullBlock, *Commit)
}

type BlockExecutor interface {
	ValidateBlock(ChainState, *FullBlock, bool) error                       // validate the block by tentatively executing it
	ApplyBlock(context.Context, ChainState, *FullBlock) (ChainState, error) // apply the block
	MakeBlock(chainState *ChainState, height uint64, commit *Commit, proposerAddress common.Address) *FullBlock
}

// Consensus sentinel errors
var (
	ErrInvalidProposalSignature   = errors.New("error invalid proposal signature")
	ErrInvalidProposalPOLRound    = errors.New("error invalid proposal POL round")
	ErrAddingVote                 = errors.New("error adding vote")
	ErrSignatureFoundInPastBlocks = errors.New("found signature from the same key")

	errPubKeyIsNotSet = errors.New("pubkey is not set. Look for \"Can't get private validator pubkey\" errors")
)

var msgQueueSize = 1000

// State handles execution of the consensus algorithm.
// It processes votes and proposals, and upon reaching agreement,
// commits blocks to the chain and executes them against the application.
// The internal state machine receives input from peers, the internal validator, and from a timer.
type ConsensusState struct {
	BaseService

	// config details
	config            *ConsensusConfig
	privValidator     PrivValidator // for signing votes
	privValidatorType PrivValidatorType

	// store blocks and commits
	blockStore BlockStore

	// create and execute blocks
	blockExec BlockExecutor

	// add evidence to the pool
	// when it's detected
	// evpool evidencePool

	// internal state
	mtx sync.RWMutex
	RoundState
	chainState ChainState // State until height-1.
	// privValidator pubkey, memoized for the duration of one block
	// to avoid extra requests to HSM
	privValidatorPubKey PubKey

	// state changes may be triggered by: msgs from peers,
	// msgs from ourself, or by timeouts
	peerInMsgQueue   chan MsgInfo
	internalMsgQueue chan MsgInfo
	timeoutTicker    TimeoutTicker
	peerOutMsgQueue  chan Message

	// a Write-Ahead Log ensures we can recover from any kind of crash
	// and helps us avoid signing conflicting votes
	// wal          WAL
	replayMode   bool // so we don't log signing errors during replay
	doWALCatchup bool // determines if we even try to do the catchup

	// for tests where we want to limit the number of transitions the state makes
	nSteps int

	// some functions can be overwritten for testing
	decideProposal          func(height uint64, round int32)
	doPrevote               func(ctx context.Context, height uint64, round int32)
	setProposal             func(ctx context.Context, proposal *Proposal) (bool, error)
	createProposalBlockFunc func(
		height uint64,
		commit *Commit,
		proposerAddr common.Address,
	) *FullBlock

	// closed when we finish shutting down
	done chan struct{}

	// wait the channel event happening for shutting down the state gracefully
	onStopCh chan *RoundState

	consensusSyncRequestAsyncChan chan *consensusSyncRequestAsync
	committedBlockChan            chan *FullBlock
}

// NewState returns a new State.
func NewConsensusState(
	ctx context.Context,
	cfg *ConsensusConfig,
	state ChainState,
	blockExec BlockExecutor,
	blockStore BlockStore,
	peerInMsgQueue chan MsgInfo,
	peerOutMsgQueue chan Message,
	// txNotifier txNotifier,
	// evpool evidencePool,
	// options ...StateOption,
) *ConsensusState {
	cs := &ConsensusState{
		config:                        cfg,
		blockExec:                     blockExec,
		blockStore:                    blockStore,
		peerInMsgQueue:                peerInMsgQueue,
		peerOutMsgQueue:               peerOutMsgQueue,
		internalMsgQueue:              make(chan MsgInfo, msgQueueSize),
		timeoutTicker:                 NewTimeoutTicker(),
		consensusSyncRequestAsyncChan: make(chan *consensusSyncRequestAsync, msgQueueSize),
		committedBlockChan:            make(chan *FullBlock, msgQueueSize),
		done:                          make(chan struct{}),
		doWALCatchup:                  true,
		// wal:              nilWAL{},
		// evpool:   evpool,
		onStopCh: make(chan *RoundState),
	}

	// set function defaults (may be overwritten before calling Start)
	cs.decideProposal = cs.defaultDecideProposal
	cs.doPrevote = cs.defaultDoPrevote
	cs.setProposal = cs.defaultSetProposal
	cs.createProposalBlockFunc = cs.defaultCreateBlock

	// We have no votes, so reconstruct LastCommit from SeenCommit.
	if state.LastBlockHeight > 0 {
		cs.reconstructLastCommit(state)
	}

	cs.updateToState(ctx, state)

	// NOTE: we do not call scheduleRound0 yet, we do that upon Start()

	cs.BaseService = *NewBaseService("State", cs)

	return cs
}

func (cs *ConsensusState) defaultCreateBlock(height uint64, commit *Commit, proposerAddr common.Address) *FullBlock {
	return cs.blockExec.MakeBlock(&cs.chainState, height, commit, proposerAddr)
}

// String returns a string.
func (cs *ConsensusState) String() string {
	// better not to access shared variables
	return "ConsensusState"
}

// GetState returns a copy of the chain state.
// func (cs *SimpleState) GetState() sm.State {
// 	cs.mtx.RLock()
// 	defer cs.mtx.RUnlock()
// 	return cs.state.Copy()
// }

// GetLastHeight returns the last height committed.
// If there were no blocks, returns 0.
func (cs *ConsensusState) GetLastHeight() uint64 {
	cs.mtx.RLock()
	defer cs.mtx.RUnlock()
	return cs.RoundState.Height - 1
}

// GetRoundState returns a shallow copy of the internal consensus state.
func (cs *ConsensusState) GetRoundState() *RoundState {
	cs.mtx.RLock()
	defer cs.mtx.RUnlock()

	// NOTE: this might be dodgy, as RoundState itself isn't thread
	// safe as it contains a number of pointers and is explicitly
	// not thread safe.
	rs := cs.RoundState // copy
	return &rs
}

// GetRoundStateJSON returns a json of RoundState.
// func (cs *SimpleState) GetRoundStateJSON() ([]byte, error) {
// 	cs.mtx.RLock()
// 	defer cs.mtx.RUnlock()
// 	return tmjson.Marshal(cs.RoundState)
// }

// GetValidators returns a copy of the current validators.
// func (cs *SimpleState) GetValidators() (int64, []*Validator) {
// 	cs.mtx.RLock()
// 	defer cs.mtx.RUnlock()
// 	return cs.state.LastBlockHeight, cs.state.Validators.Copy().Validators
// }

// SetPrivValidator sets the private validator account for signing votes. It
// immediately requests pubkey and caches it.
func (cs *ConsensusState) SetPrivValidator(priv PrivValidator) {
	cs.mtx.Lock()
	defer cs.mtx.Unlock()

	// Set type
	cs.privValidator = priv

	if priv != nil {
		// TODO: validate privValidator
	}

	if err := cs.updatePrivValidatorPubKey(); err != nil {
		log.Error("failed to get private validator pubkey", "err", err)
	}
}

// SetTimeoutTicker sets the local timer. It may be useful to overwrite for
// testing.
func (cs *ConsensusState) SetTimeoutTicker(timeoutTicker TimeoutTicker) {
	cs.mtx.Lock()
	cs.timeoutTicker = timeoutTicker
	cs.mtx.Unlock()
}

// LoadCommit loads the commit for a given height.
func (cs *ConsensusState) LoadCommit(height uint64) *Commit {
	cs.mtx.RLock()
	defer cs.mtx.RUnlock()

	if height == cs.blockStore.Height() {
		commit := cs.blockStore.LoadSeenCommit()
		// NOTE: Retrieving the height of the most recent block and retrieving
		// the most recent commit does not currently occur as an atomic
		// operation. We check the height and commit here in case a more recent
		// commit has arrived since retrieving the latest height.
		if commit != nil && commit.Height == height {
			return commit
		}
	}

	return cs.blockStore.LoadBlockCommit(height)
}

// OnStart loads the latest state via the WAL, and starts the timeout and
// receive routines.
func (cs *ConsensusState) OnStart(ctx context.Context) error {
	// // We may set the WAL in testing before calling Start, so only OpenWAL if its
	// // still the nilWAL.
	// if _, ok := cs.wal.(nilWAL); ok {
	// 	if err := cs.loadWalFile(ctx); err != nil {
	// 		return err
	// 	}
	// }

	// // We may have lost some votes if the process crashed reload from consensus
	// // log to catchup.
	// if cs.doWALCatchup {
	// 	repairAttempted := false

	// LOOP:
	// 	for {
	// 		err := cs.catchupReplay(ctx, cs.Height)
	// 		switch {
	// 		case err == nil:
	// 			break LOOP

	// 		case !IsDataCorruptionError(err):
	// 			log.Error("error on catchup replay; proceeding to start state anyway", "err", err)
	// 			break LOOP

	// 		case repairAttempted:
	// 			return err
	// 		}

	// 		log.Error("the WAL file is corrupted; attempting repair", "err", err)

	// 		// 1) prep work
	// 		if err := cs.wal.Stop(); err != nil {

	// 			return err
	// 		}

	// 		repairAttempted = true

	// 		// 2) backup original WAL file
	// 		corruptedFile := fmt.Sprintf("%s.CORRUPTED", cs.config.WalFile())
	// 		if err := tmos.CopyFile(cs.config.WalFile(), corruptedFile); err != nil {
	// 			return err
	// 		}

	// 		log.Debug("backed up WAL file", "src", cs.config.WalFile(), "dst", corruptedFile)

	// 		// 3) try to repair (WAL file will be overwritten!)
	// 		if err := repairWalFile(corruptedFile, cs.config.WalFile()); err != nil {
	// 			log.Error("the WAL repair failed", "err", err)
	// 			return err
	// 		}

	// 		log.Info("successful WAL repair")

	// 		// reload WAL file
	// 		if err := cs.loadWalFile(ctx); err != nil {
	// 			return err
	// 		}
	// 	}
	// }

	// we need the timeoutRoutine for replay so
	// we don't block on the tick chan.
	// NOTE: we will get a build up of garbage go routines
	// firing on the tockChan until the receiveRoutine is started
	// to deal with them (by that point, at most one will be valid)
	if err := cs.timeoutTicker.Start(ctx); err != nil {
		return err
	}

	// Double Signing Risk Reduction
	if err := cs.checkDoubleSigningRisk(cs.Height); err != nil {
		return err
	}

	// now start the receiveRoutine
	go cs.receiveRoutine(ctx, 0)

	// schedule the first round!
	// use GetRoundState so we don't race the receiveRoutine for access
	cs.scheduleRound0(cs.GetRoundState())

	return nil
}

// timeoutRoutine: receive requests for timeouts on tickChan and fire timeouts on tockChan
// receiveRoutine: serializes processing of proposoals, block parts, votes; coordinates state transitions
//
// this is only used in tests.
func (cs *ConsensusState) startRoutines(ctx context.Context, maxSteps int) {
	err := cs.timeoutTicker.Start(ctx)
	if err != nil {
		log.Error("failed to start timeout ticker", "err", err)
		return
	}

	go cs.receiveRoutine(ctx, maxSteps)
}

// loadWalFile loads WAL data from file. It overwrites cs.wal.
// func (cs *SimpleState) loadWalFile(ctx context.Context) error {
// 	wal, err := cs.OpenWAL(ctx, cs.config.WalFile)
// 	if err != nil {
// 		log.Error("failed to load state WAL", "err", err)
// 		return err
// 	}

// 	cs.wal = wal
// 	return nil
// }

// OnStop implements service.Service.
func (cs *ConsensusState) OnStop() {
	// If the node is committing a new block, wait until it is finished!
	if cs.GetRoundState().Step == RoundStepCommit {
		select {
		case <-cs.onStopCh:
		case <-time.After(cs.config.TimeoutCommit):
			log.Error("OnStop: timeout waiting for commit to finish", "time", cs.config.TimeoutCommit)
		}
	}

	close(cs.onStopCh)

	if cs.timeoutTicker.IsRunning() {
		if err := cs.timeoutTicker.Stop(); err != nil {
			// if !errors.Is(err, service.ErrAlreadyStopped) {
			log.Error("failed trying to stop timeoutTicket", "error", err)
			// }
		}
	}
	// WAL is stopped in receiveRoutine.
}

// Wait waits for the the main routine to return.
// NOTE: be sure to Stop() the event switch and drain
// any event channels or this may deadlock
func (cs *ConsensusState) Wait() {
	<-cs.done
}

// OpenWAL opens a file to log all consensus messages and timeouts for
// deterministic accountability.
// func (cs *SimpleState) OpenWAL(ctx context.Context, walFile string) (WAL, error) {
// 	wal, err := NewWAL(log.With("wal", walFile), walFile)
// 	if err != nil {
// 		log.Error("failed to open WAL", "file", walFile, "err", err)
// 		return nil, err
// 	}

// 	if err := wal.Start(ctx); err != nil {
// 		log.Error("failed to start WAL", "err", err)
// 		return nil, err
// 	}

// 	return wal, nil
// }

//------------------------------------------------------------
// internal functions for managing the state

func (cs *ConsensusState) updateHeight(height uint64) {
	cs.Height = height
}

func (cs *ConsensusState) updateRoundStep(round int32, step RoundStepType) {
	cs.Round = round
	cs.Step = step
}

// enterNewRound(height, 0) at cs.StartTime.
func (cs *ConsensusState) scheduleRound0(rs *RoundState) {
	// log.Info("scheduleRound0", "now", tmtime.Now(), "startTime", cs.StartTime)
	sleepDuration := rs.StartTime.Sub(CanonicalNow())
	cs.scheduleTimeout(sleepDuration, rs.Height, 0, RoundStepNewHeight)
}

// Attempt to schedule a timeout (by sending timeoutInfo on the tickChan)
func (cs *ConsensusState) scheduleTimeout(duration time.Duration, height uint64, round int32, step RoundStepType) {
	cs.timeoutTicker.ScheduleTimeout(timeoutInfo{duration, height, round, step})
}

// send a msg into the receiveRoutine regarding our own proposal, block part, or vote
func (cs *ConsensusState) sendInternalMessage(ctx context.Context, mi MsgInfo) {
	select {
	case <-ctx.Done():
	case cs.internalMsgQueue <- mi:
	default:
		// NOTE: using the go-routine means our votes can
		// be processed out of order.
		// TODO: use CList here for strict determinism and
		// attempt push to internalMsgQueue in receiveRoutine
		log.Debug("internal msg queue is full; using a go-routine")
		go func() {
			select {
			case <-ctx.Done():
			case cs.internalMsgQueue <- mi:
			}
		}()
	}
}

func (cs *ConsensusState) createSyncRequest() *ConsensusSyncRequest {
	round := cs.Round
	if cs.Proposal != nil && cs.Proposal.POLRound != -1 && !cs.isProposalComplete() {
		// make sure we collect enough prevotes for POLRound
		// so that we could vote in this round
		round = cs.LockedRound
	}

	hasProposal := uint8(0)
	if cs.Proposal != nil {
		hasProposal = 1
	}

	return &ConsensusSyncRequest{
		Height:           cs.Height,
		Round:            uint32(round),
		HasProposal:      hasProposal,
		PrevotesBitmap:   cs.Votes.Prevotes(round).BitArray().Copy().Elems,
		PrecommitsBitmap: cs.Votes.Precommits(round).BitArray().Copy().Elems,
	}
}

func (cs *ConsensusState) ProcessCommittedBlock(fb *FullBlock) {
	cs.committedBlockChan <- fb
}

func (cs *ConsensusState) processCommitedBlock(ctx context.Context, block *FullBlock) {
	height := block.NumberU64()
	if block.NumberU64() != cs.Height {
		return
	}

	// fast-path for commit
	if err := cs.blockExec.ValidateBlock(cs.chainState, block, true); err != nil {
		log.Warn("processCommitBlock verify err", "err", err)
	}

	cs.updateRoundStep(cs.Round, RoundStepCommit)

	// calculate last commit vote set directly
	// note that updateToState() will check existing cs.LastCommit if CommitRound is -1.
	cs.CommitRound = -1 // no votes
	cs.LastCommit = CommitToVoteSet(cs.chainState.ChainID, block.Commit(), cs.chainState.Validators)
	cs.CommitTime = CanonicalNow()

	log.Info(
		"Finalizing commit of block",
		"height", block.NumberU64(),
		"hash", block.Hash(),
		// "root", block.AppHash,
		// "num_txs", len(block.Txs),
	)

	log.Debug(fmt.Sprintf("%v", block), "height", block.NumberU64())

	// Save to blockStore.
	if cs.blockStore.Height() < block.NumberU64() {
		// NOTE: the seenCommit is local justification to commit this block,
		// but may differ from the LastCommit included in the next block
		cs.blockStore.SaveBlock(block, block.Commit())
	} else {
		// Happens during replay if we already saved the block but didn't commit
		log.Debug("calling finalizeCommit on already stored block", "height", block.Number)
	}

	// Create a copy of the state for staging and an event cache for txs.
	stateCopy := cs.chainState.Copy()

	// Execute and commit the block, update and save the state, and update the mempool.
	// NOTE The block.AppHash wont reflect these txs until the next block.
	stateCopy, err := cs.blockExec.ApplyBlock(ctx, stateCopy, block)
	if err != nil {
		log.Error("failed to apply block", "height", height, "err", err)
		return
	}

	// NewHeightStep!
	cs.updateToState(ctx, stateCopy)

	// Private validator might have changed it's key pair => refetch pubkey.
	if err := cs.updatePrivValidatorPubKey(); err != nil {
		log.Error("failed to get private validator pubkey", "height", height, "err", err)
	}

	// if we can skip timeoutCommit and have all the votes now,
	if cs.config.SkipTimeoutCommit && cs.LastCommit.HasAll() {
		// go straight to new round (skip timeout commit)
		// cs.scheduleTimeout(time.Duration(0), cs.Height, 0, RoundStepNewHeight)
		cs.enterNewRound(ctx, cs.Height, 0)
	} else {
		// cs.StartTime is already set.
		// Schedule Round0 to start soon.
		cs.scheduleRound0(&cs.RoundState)
	}

	// By here,
	// * cs.Height has been increment to height+1
	// * cs.Step is now RoundStepNewHeight
	// * cs.StartTime is set to when we will start round0.
}

func (cs *ConsensusState) ProcessSyncRequest(csq *ConsensusSyncRequest) ([]interface{}, error) {
	log.Debug("Processing sync req", "req", csq)
	respChan := make(chan []interface{})

	reqAsync := &consensusSyncRequestAsync{
		req:      csq,
		respChan: respChan,
	}

	cs.consensusSyncRequestAsyncChan <- reqAsync

	// TODO: cancel
	select {
	case msgs := <-respChan:
		log.Debug("Processed req", "msgs", msgs)

		return msgs, nil
	}
}

func appendDiffVotes(vs *VoteSet, bm []uint64, msgs []interface{}) []interface{} {
	if len(bm) != 0 {
		votesBA, err := types.NewBitArrayFromUint64(vs.Size(), bm)
		if err != nil {
			// somewrong with bitmap size
			return msgs
		}
		for i := 0; i < votesBA.Size(); i++ {
			if votesBA.GetIndex(i) {
				continue
			}

			if !vs.BitArray().GetIndex(i) {
				continue
			}

			msgs = append(msgs, &types.VoteMessage{Vote: vs.GetByIndex(int32(i))})
		}
	}
	return msgs
}

func (cs *ConsensusState) processSyncRequest(csq *ConsensusSyncRequest) []interface{} {
	var msgs []interface{}
	if csq.Height < cs.chainState.InitialHeight {
		// nothing to have
		return msgs
	} else if csq.Height < cs.Height {
		// return commit
		if csq.HasProposal == 0 {
			// return block and commit directly
			fb := cs.blockStore.LoadBlock(csq.Height)
			return []interface{}{fb}
		} else {
			// we are ahead and the peer has proposal, only return precommits
			commit := cs.blockStore.LoadBlockCommit(csq.Height)
			for i := 0; i < commit.Size(); i++ {
				if commit.BitArray().GetIndex(i) {
					msgs = append(msgs, &types.VoteMessage{Vote: commit.GetVote(int32(i))})
				}
			}
			return msgs
		}
	} else if csq.Height > cs.Height || csq.Round > uint32(cs.Round) {
		return []interface{}{}
	}

	// now csq.height == cs.height and csq.round <= cs.round
	if csq.HasProposal == 0 && cs.Proposal != nil {
		msgs = append(msgs, &types.ProposalMessage{Proposal: cs.Proposal})
	}
	msgs = appendDiffVotes(cs.Votes.Prevotes(int32(csq.Round)), csq.PrevotesBitmap, msgs)
	msgs = appendDiffVotes(cs.Votes.Precommits(int32(csq.Round)), csq.PrecommitsBitmap, msgs)

	return msgs
}

func (cs *ConsensusState) broadcastMessageToPeers(ctx context.Context, msg Message) {
	select {
	case <-ctx.Done():
	case cs.peerOutMsgQueue <- msg:
	default:
		log.Debug("broadcast msg queue is full; using a go-routine")
		go func() {
			select {
			case <-ctx.Done():
			case cs.peerOutMsgQueue <- msg:
			}
		}()
	}
}

// Reconstruct LastCommit from SeenCommit, which we saved along with the block,
// (which happens even before saving the state)
func (cs *ConsensusState) reconstructLastCommit(state ChainState) {
	commit := cs.blockStore.LoadSeenCommit()
	if commit == nil || commit.Height != state.LastBlockHeight {
		commit = cs.blockStore.LoadBlockCommit(state.LastBlockHeight)
	}

	if commit == nil {
		panic(fmt.Sprintf(
			"failed to reconstruct last commit; commit for height %v not found",
			state.LastBlockHeight,
		))
	}

	// TODO: read from state
	// lastPrecommits := &VoteSet{}
	lastPrecommits := CommitToVoteSet(state.ChainID, commit, state.LastValidators)
	// if !lastPrecommits.HasTwoThirdsMajority() {
	// 	panic("failed to reconstruct last commit; does not have +2/3 maj")
	// }

	cs.LastCommit = lastPrecommits
}

// Updates State and increments height to match that of state.
// The round becomes 0 and cs.Step becomes RoundStepNewHeight.
func (cs *ConsensusState) updateToState(ctx context.Context, state ChainState) {
	if cs.CommitRound > -1 && 0 < cs.Height && cs.Height != state.LastBlockHeight {
		panic(fmt.Sprintf(
			"updateToState() expected state height of %v but found %v",
			cs.Height, state.LastBlockHeight,
		))
	}

	if !cs.chainState.IsEmpty() {
		if cs.chainState.LastBlockHeight > 0 && cs.chainState.LastBlockHeight+1 != cs.Height {
			// This might happen when someone else is mutating cs.state.
			// Someone forgot to pass in state.Copy() somewhere?!
			panic(fmt.Sprintf(
				"inconsistent cs.state.LastBlockHeight+1 %v vs cs.Height %v",
				cs.chainState.LastBlockHeight+1, cs.Height,
			))
		}
		if cs.chainState.LastBlockHeight > 0 && cs.Height == cs.chainState.InitialHeight {
			panic(fmt.Sprintf(
				"inconsistent cs.state.LastBlockHeight %v, expected 0 for initial height %v",
				cs.chainState.LastBlockHeight, cs.chainState.InitialHeight,
			))
		}

		// If state isn't further out than cs.state, just ignore.
		// This happens when SwitchToConsensus() is called in the reactor.
		// We don't want to reset e.g. the Votes, but we still want to
		// signal the new round step, because other services (eg. txNotifier)
		// depend on having an up-to-date peer state!
		if state.LastBlockHeight <= cs.chainState.LastBlockHeight {
			log.Debug(
				"ignoring updateToState()",
				"new_height", state.LastBlockHeight+1,
				"old_height", cs.chainState.LastBlockHeight+1,
			)
			cs.newStep(ctx)
			return
		}
	}

	// Reset fields based on state.
	validators := state.Validators

	switch {
	case state.LastBlockHeight == 0: // Very first commit should be empty.
		cs.LastCommit = (*VoteSet)(nil)
	case cs.CommitRound > -1 && cs.Votes != nil: // Otherwise, use cs.Votes
		if !cs.Votes.Precommits(cs.CommitRound).HasTwoThirdsMajority() {
			panic(fmt.Sprintf(
				"wanted to form a commit, but precommits (H/R: %d/%d) didn't have 2/3+: %v",
				state.LastBlockHeight, cs.CommitRound, cs.Votes.Precommits(cs.CommitRound),
			))
		}

		cs.LastCommit = cs.Votes.Precommits(cs.CommitRound)

	case cs.LastCommit == nil:
		// NOTE: when Tendermint starts, it has no votes. reconstructLastCommit
		// must be called to reconstruct LastCommit from SeenCommit.
		panic(fmt.Sprintf(
			"last commit cannot be empty after initial block (H:%d)",
			state.LastBlockHeight+1,
		))
	}

	// Next desired block height
	height := state.LastBlockHeight + 1
	if height == 1 {
		height = state.InitialHeight
	}

	// RoundState fields
	cs.updateHeight(height)
	cs.updateRoundStep(0, RoundStepNewHeight)

	if cs.CommitTime.IsZero() {
		// "Now" makes it easier to sync up dev nodes.
		// We add timeoutCommit to allow transactions
		// to be gathered for the first block.
		// And alternative solution that relies on clocks:
		// cs.StartTime = state.LastBlockTime.Add(timeoutCommit)
		cs.StartTime = cs.config.Commit(CanonicalNow())
	} else {
		cs.StartTime = cs.config.Commit(cs.CommitTime)
	}

	cs.Validators = validators
	cs.Proposal = nil
	cs.ProposalBlock = nil
	cs.LockedRound = -1
	cs.LockedBlock = nil
	cs.ValidRound = -1
	cs.ValidBlock = nil
	cs.Votes = NewHeightVoteSet(state.ChainID, height, validators)
	cs.CommitRound = -1
	cs.LastValidators = state.LastValidators
	cs.TriggeredTimeoutPrecommit = false

	cs.chainState = state

	// Finally, broadcast RoundState
	cs.newStep(ctx)
}

func (cs *ConsensusState) newStep(ctx context.Context) {
	// rs := cs.RoundStateEvent()
	// if err := cs.wal.Write(rs); err != nil {
	// 	log.Error("failed writing to WAL", "err", err)
	// }

	cs.nSteps++
}

//-----------------------------------------
// the main go routines

// receiveRoutine handles messages which may cause state transitions.
// it's argument (n) is the number of messages to process before exiting - use 0 to run forever
// It keeps the RoundState and is the only thing that updates it.
// Updates (state transitions) happen on timeouts, complete proposals, and 2/3 majorities.
// State must be locked before any internal state is updated.
func (cs *ConsensusState) receiveRoutine(ctx context.Context, maxSteps int) {
	onExit := func(cs *ConsensusState) {
		// NOTE: the internalMsgQueue may have signed messages from our
		// priv_val that haven't hit the WAL, but its ok because
		// priv_val tracks LastSig

		// close wal now that we're done writing to it
		// if err := cs.wal.Stop(); err != nil {
		// 	// if !errors.Is(err, service.ErrAlreadyStopped) {
		// 	log.Error("failed trying to stop WAL", "error", err)
		// 	// }
		// }

		// cs.wal.Wait()
		close(cs.done)
	}

	defer func() {
		if r := recover(); r != nil {
			log.Error("CONSENSUS FAILURE!!!", "err", r, "stack", string(debug.Stack()))
			// stop gracefully
			//
			// NOTE: We most probably shouldn't be running any further when there is
			// some unexpected panic. Some unknown error happened, and so we don't
			// know if that will result in the validator signing an invalid thing. It
			// might be worthwhile to explore a mechanism for manual resuming via
			// some console or secure RPC system, but for now, halting the chain upon
			// unexpected consensus bugs sounds like the better option.
			onExit(cs)
		}
	}()

	consensusSyncRequestTimer := time.NewTimer(cs.config.ConsensusSyncRequestDuration)
	defer consensusSyncRequestTimer.Stop()

	for {
		if maxSteps > 0 {
			if cs.nSteps >= maxSteps {
				log.Debug("reached max steps; exiting receive routine")
				cs.nSteps = 0
				return
			}
		}

		rs := cs.RoundState
		var mi MsgInfo

		select {

		case mi = <-cs.peerInMsgQueue:
			// if err := cs.wal.Write(mi); err != nil {
			// 	log.Error("failed writing to WAL", "err", err)
			// }

			// handles proposals, block parts, votes
			// may generate internal events (votes, complete proposals, 2/3 majorities)
			cs.handleMsg(ctx, mi)

		case mi = <-cs.internalMsgQueue:
			// err := cs.wal.WriteSync(mi) // NOTE: fsync
			// if err != nil {
			// 	panic(fmt.Sprintf(
			// 		"failed to write %v msg to consensus WAL due to %v; check your file system and restart the node",
			// 		mi, err,
			// 	))
			// }

			// if _, ok := mi.Msg.(*VoteMessage); ok {
			// we actually want to simulate failing during
			// the previous WriteSync, but this isn't easy to do.
			// Equivalent would be to fail here and manually remove
			// some bytes from the end of the wal.
			// fail.Fail() // XXX
			// }

			// handles proposals, block parts, votes
			cs.handleMsg(ctx, mi)

		case ti := <-cs.timeoutTicker.Chan(): // tockChan:
			// if err := cs.wal.Write(ti); err != nil {
			// 	log.Error("failed writing to WAL", "err", err)
			// }

			// if the timeout is relevant to the rs
			// go to the next step
			cs.handleTimeout(ctx, ti, rs)

		case <-consensusSyncRequestTimer.C:
			msg := cs.createSyncRequest()
			cs.broadcastMessageToPeers(ctx, msg)

			consensusSyncRequestTimer.Reset(cs.config.ConsensusSyncRequestDuration)
		case syncReqAsync := <-cs.consensusSyncRequestAsyncChan:
			// respChan is supposed to be non-blocking
			syncReqAsync.respChan <- cs.processSyncRequest(syncReqAsync.req)
		case commitedBlock := <-cs.committedBlockChan:
			cs.processCommitedBlock(ctx, commitedBlock)
		case <-ctx.Done():
			onExit(cs)
			return

		}
		// TODO should we handle context cancels here?
	}
}

// state transitions on complete-proposal, 2/3-any, 2/3-one
func (cs *ConsensusState) handleMsg(ctx context.Context, mi MsgInfo) {
	cs.mtx.Lock()
	defer cs.mtx.Unlock()

	var (
		added bool
		err   error
	)

	msg, peerID := mi.Msg, mi.PeerID

	switch msg := msg.(type) {
	case *ProposalMessage:
		// will not cause transition.
		// once proposal is set, we can receive block parts
		added, err = cs.setProposal(ctx, msg.Proposal)

		if added {
			// broadcast the proposal to peer
			cs.broadcastMessageToPeers(ctx, msg)
		}

	case *VoteMessage:
		// attempt to add the vote and dupeout the validator if its a duplicate signature
		// if the vote gives us a 2/3-any or 2/3-one, we transition
		added, err = cs.tryAddVote(ctx, msg.Vote, string(peerID))
		if added {
			// broadcast the vote to peer
			cs.broadcastMessageToPeers(ctx, msg)
		}

	// if err == ErrAddingVote {
	// TODO: punish peer
	// We probably don't want to stop the peer here. The vote does not
	// necessarily comes from a malicious peer but can be just broadcasted by
	// a typical peer.
	// https://github.com/tendermint/tendermint/issues/1281
	// }

	// NOTE: the vote is broadcast to peers by the reactor listening
	// for vote events

	// TODO: If rs.Height == vote.Height && rs.Round < vote.Round,
	// the peer is sending us CatchupCommit precommits.
	// We could make note of this and help filter in broadcastHasVoteMessage().

	default:
		log.Error("unknown msg type", "type", fmt.Sprintf("%T", msg))
		return
	}

	if err != nil {
		log.Error(
			"failed to process message",
			"height", cs.Height,
			"round", cs.Round,
			"peer", peerID,
			"msg_type", fmt.Sprintf("%T", msg),
			"err", err,
		)
	}
}

func (cs *ConsensusState) handleTimeout(
	ctx context.Context,
	ti timeoutInfo,
	rs RoundState,
) {
	log.Debug("received tock", "timeout", ti.Duration, "height", ti.Height, "round", ti.Round, "step", ti.Step)

	// timeouts must be for current height, round, step
	if ti.Height != rs.Height || ti.Round < rs.Round || (ti.Round == rs.Round && RoundStepType(ti.Step) < rs.Step) {
		log.Debug("ignoring tock because we are ahead", "height", rs.Height, "round", rs.Round, "step", rs.Step)
		return
	}

	// the timeout will now cause a state transition
	cs.mtx.Lock()
	defer cs.mtx.Unlock()

	switch RoundStepType(ti.Step) {
	case RoundStepNewHeight:
		// NewRound event fired from enterNewRound.
		// XXX: should we fire timeout here (for timeout commit)?
		cs.enterNewRound(ctx, ti.Height, 0)

	case RoundStepNewRound:
		cs.enterPropose(ctx, ti.Height, 0)

	case RoundStepPropose:
		cs.enterPrevote(ctx, ti.Height, ti.Round)

	case RoundStepPrevoteWait:
		cs.enterPrecommit(ctx, ti.Height, ti.Round)

	case RoundStepPrecommitWait:
		cs.enterPrecommit(ctx, ti.Height, ti.Round)
		cs.enterNewRound(ctx, ti.Height, ti.Round+1)

	default:
		panic(fmt.Sprintf("invalid timeout step: %v", ti.Step))
	}

}

//-----------------------------------------------------------------------------
// State functions
// Used internally by handleTimeout and handleMsg to make state transitions

// Enter: `timeoutNewHeight` by startTime (commitTime+timeoutCommit),
//	or, if SkipTimeoutCommit==true, after receiving all precommits from (height,round-1)
// Enter: `timeoutPrecommits` after any +2/3 precommits from (height,round-1)
// Enter: +2/3 precommits for nil at (height,round-1)
// Enter: +2/3 prevotes any or +2/3 precommits for block or any from (height, round)
// NOTE: cs.StartTime was already set for height.
func (cs *ConsensusState) enterNewRound(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && cs.Step != RoundStepNewHeight) {
		log.Debug(
			"entering new round with invalid args",
			"height", height, "round", round,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	if now := CanonicalNow(); cs.StartTime.After(now) {
		log.Debug("need to set a buffer and log message here for sanity", "start_time", "height", height, "round", round, cs.StartTime, "now", now)
	}

	log.Debug("entering new round", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	// increment validators if necessary
	validators := cs.Validators
	if cs.Round < round {
		validators = validators.Copy()
		for i := uint64(0); i < uint64(validators.ProposerReptition); i++ {
			validators.IncrementProposerPriority(SafeSubInt32(round, cs.Round))
		}
	}

	// Setup new round
	// we don't fire newStep for this step,
	// but we fire an event, so update the round step first
	cs.updateRoundStep(round, RoundStepNewRound)
	cs.Validators = validators
	if round == 0 {
		// We've already reset these upon new height,
		// and meanwhile we might have received a proposal
		// for round 0.
	} else {
		log.Debug("resetting proposal info", "height", height, "round", round)
		cs.Proposal = nil
		cs.ProposalBlock = nil
	}

	cs.Votes.SetRound(SafeAddInt32(round, 1)) // also track next round (round+1) to allow round-skipping
	cs.TriggeredTimeoutPrecommit = false

	cs.enterPropose(ctx, height, round)
}

// Enter (CreateEmptyBlocks): from enterNewRound(height,round)
// Enter (CreateEmptyBlocks, CreateEmptyBlocksInterval > 0 ):
//		after enterNewRound(height,round), after timeout of CreateEmptyBlocksInterval
// Enter (!CreateEmptyBlocks) : after enterNewRound(height,round), once txs are in the mempool
func (cs *ConsensusState) enterPropose(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && RoundStepPropose <= cs.Step) {
		log.Debug(
			"entering propose step with invalid args",
			"height", height, "round", round,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	log.Debug("entering propose step", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	defer func() {
		// Done enterPropose:
		cs.updateRoundStep(round, RoundStepPropose)
		cs.newStep(ctx)

		// If we have the whole proposal + POL, then goto Prevote now.
		// else, we'll enterPrevote when the rest of the proposal is received (in AddProposalBlockPart),
		// or else after timeoutPropose
		if cs.isProposalComplete() {
			cs.enterPrevote(ctx, height, cs.Round)
		}
	}()

	// If we don't get the proposal and all block parts quick enough, enterPrevote
	cs.scheduleTimeout(cs.config.Propose(round), height, round, RoundStepPropose)

	// Nothing more to do if we're not a validator
	if cs.privValidator == nil {
		log.Debug("node is not a validator", "height", height, "round", round)
		return
	}

	log.Debug("node is a validator", "height", height, "round", round)

	if cs.privValidatorPubKey == nil {
		// If this node is a validator & proposer in the current round, it will
		// miss the opportunity to create a block.
		log.Error("propose step; empty priv validator public key", "err", errPubKeyIsNotSet, "height", height, "round", round)
		return
	}

	address := cs.privValidatorPubKey.Address()

	// if not a validator, we're done
	if !cs.Validators.HasAddress(address) {
		log.Debug("node is not a validator", "height", height, "round", round, "addr", address, "vals", cs.Validators)
		return
	}

	if cs.isProposer(address) {
		log.Debug(
			"propose step; our turn to propose",
			"height", height, "round", round,
			"proposer", address,
		)

		cs.decideProposal(height, round)
	} else {
		log.Debug(
			"propose step; not our turn to propose",
			"height", height, "round", round,
			"proposer", cs.Validators.GetProposer().Address,
		)
	}
}

func (cs *ConsensusState) isProposer(address common.Address) bool {
	return cs.Validators.GetProposer().Address == address
}

func (cs *ConsensusState) defaultDecideProposal(height uint64, round int32) {
	var block *FullBlock

	// Decide on block
	if cs.ValidBlock != nil {
		// If there is valid block, choose that.
		block = cs.ValidBlock
	} else {
		// Create a new proposal block from state/txs from the mempool.
		block = cs.createProposalBlock()
		if block == nil {
			return
		}
	}

	// Flush the WAL. Otherwise, we may not recompute the same proposal to sign,
	// and the privValidator will refuse to sign anything.
	// if err := cs.wal.FlushAndSync(); err != nil {
	// 	log.Error("failed flushing WAL to disk")
	// }

	// Make proposal
	proposal := NewProposal(height, round, cs.ValidRound, block)

	// wait the max amount we would wait for a proposal
	ctx, cancel := context.WithTimeout(context.TODO(), cs.config.TimeoutPropose)
	defer cancel()
	if err := cs.privValidator.SignProposal(ctx, cs.chainState.ChainID, proposal); err == nil {
		// send proposal and block parts on internal msg queue
		cs.sendInternalMessage(ctx, MsgInfo{&ProposalMessage{proposal}, ""})

		log.Debug("signed proposal", "height", height, "round", round, "proposal", proposal)
	} else if !cs.replayMode {
		log.Error("propose step; failed signing proposal", "height", height, "round", round, "err", err)
	}
}

// Returns true if the proposal block is complete &&
// (if POLRound was proposed, we have +2/3 prevotes from there).
func (cs *ConsensusState) isProposalComplete() bool {
	if cs.Proposal == nil || cs.ProposalBlock == nil {
		return false
	}
	// we have the proposal. if there's a POLRound,
	// make sure we have the prevotes from it too
	if cs.Proposal.POLRound < 0 {
		return true
	}
	// if this is false the proposer is lying or we haven't received the POL yet
	return cs.Votes.Prevotes(cs.Proposal.POLRound).HasTwoThirdsMajority()
}

// Create the next block to propose and return it. Returns nil block upon error.
//
// We really only need to return the parts, but the block is returned for
// convenience so we can log the proposal block.
//
// NOTE: keep it side-effect free for clarity.
// CONTRACT: cs.privValidator is not nil.
func (cs *ConsensusState) createProposalBlock() (block *FullBlock) {
	if cs.privValidator == nil {
		panic("entered createProposalBlock with privValidator being nil")
	}

	var commit *Commit
	switch {
	case cs.Height == cs.chainState.InitialHeight:
		// We're creating a proposal for the first block.
		// The commit is empty, but not nil.
		commit = NewCommit(0, 0, common.Hash{}, nil)

	case cs.LastCommit.HasTwoThirdsMajority():
		// Make the commit from LastCommit
		commit = cs.LastCommit.MakeCommit()

	default: // This shouldn't happen.
		log.Error("propose step; cannot propose anything without commit for the previous block")
		return
	}

	if cs.privValidatorPubKey == nil {
		// If this node is a validator & proposer in the current round, it will
		// miss the opportunity to create a block.
		log.Error("propose step; empty priv validator public key", "err", errPubKeyIsNotSet)
		return
	}

	proposerAddr := cs.privValidatorPubKey.Address()

	return cs.createProposalBlockFunc(cs.Height, commit, proposerAddr)
}

// Enter: `timeoutPropose` after entering Propose.
// Enter: proposal block and POL is ready.
// Prevote for LockedBlock if we're locked, or ProposalBlock if valid.
// Otherwise vote nil.
func (cs *ConsensusState) enterPrevote(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && RoundStepPrevote <= cs.Step) {
		log.Debug(
			"entering prevote step with invalid args",
			"height", height, "round", round,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	defer func() {
		// Done enterPrevote:
		cs.updateRoundStep(round, RoundStepPrevote)
		cs.newStep(ctx)
	}()

	log.Debug("entering prevote step", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	// Sign and broadcast vote as necessary
	cs.doPrevote(ctx, height, round)

	// Once `addVote` hits any +2/3 prevotes, we will go to PrevoteWait
	// (so we have more time to try and collect +2/3 prevotes for a single block)
}

func (cs *ConsensusState) defaultDoPrevote(ctx context.Context, height uint64, round int32) {
	// If a block is locked, prevote that.
	if cs.LockedBlock != nil {
		log.Debug("prevote step; already locked on a block; prevoting locked block", "height", height, "round", round)
		cs.signAddVote(ctx, PrevoteType, cs.LockedBlock.Hash())
		return
	}

	// If ProposalBlock is nil, prevote nil.
	if cs.ProposalBlock == nil {
		log.Debug("prevote step: ProposalBlock is nil", "height", height, "round", round)
		cs.signAddVote(ctx, PrevoteType, common.Hash{})
		return
	}

	// Validate proposal block
	err := cs.blockExec.ValidateBlock(cs.chainState, cs.ProposalBlock, false)
	if err != nil {
		// ProposalBlock is invalid, prevote nil.
		log.Error("prevote step: ProposalBlock is invalid", "height", height, "round", round, "err", err)
		cs.signAddVote(ctx, PrevoteType, common.Hash{})
		return
	}

	// Prevote cs.ProposalBlock
	// NOTE: the proposal signature is validated when it is received,
	// and the proposal block parts are validated as they are received (against the merkle hash in the proposal)
	log.Debug("prevote step: ProposalBlock is valid", "height", height, "round", round)
	cs.signAddVote(ctx, PrevoteType, cs.ProposalBlock.Hash())
}

// Enter: any +2/3 prevotes at next round.
func (cs *ConsensusState) enterPrevoteWait(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && RoundStepPrevoteWait <= cs.Step) {
		log.Debug(
			"entering prevote wait step with invalid args",
			"height", height, "round", round,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	if !cs.Votes.Prevotes(round).HasTwoThirdsAny() {
		panic(fmt.Sprintf(
			"entering prevote wait step (%v/%v), but prevotes does not have any +2/3 votes",
			height, round,
		))
	}

	log.Debug("entering prevote wait step", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	defer func() {
		// Done enterPrevoteWait:
		cs.updateRoundStep(round, RoundStepPrevoteWait)
		cs.newStep(ctx)
	}()

	// Wait for some more prevotes; enterPrecommit
	cs.scheduleTimeout(cs.config.Prevote(round), height, round, RoundStepPrevoteWait)
}

// Enter: `timeoutPrevote` after any +2/3 prevotes.
// Enter: `timeoutPrecommit` after any +2/3 precommits.
// Enter: +2/3 precomits for block or nil.
// Lock & precommit the ProposalBlock if we have enough prevotes for it (a POL in this round)
// else, unlock an existing lock and precommit nil if +2/3 of prevotes were nil,
// else, precommit nil otherwise.
func (cs *ConsensusState) enterPrecommit(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && RoundStepPrecommit <= cs.Step) {
		log.Debug(
			"entering precommit step with invalid args",
			"height", height, "round", round,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	log.Debug("entering precommit step", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	defer func() {
		// Done enterPrecommit:
		cs.updateRoundStep(round, RoundStepPrecommit)
		cs.newStep(ctx)
	}()

	// check for a polka
	blockID, ok := cs.Votes.Prevotes(round).TwoThirdsMajority()

	// If we don't have a polka, we must precommit nil.
	if !ok {
		if cs.LockedBlock != nil {
			log.Debug("precommit step; no +2/3 prevotes during enterPrecommit while we are locked; precommitting nil", "height", height, "round", round)
		} else {
			log.Debug("precommit step; no +2/3 prevotes during enterPrecommit; precommitting nil", "height", height, "round", round)
		}

		cs.signAddVote(ctx, PrecommitType, common.Hash{})
		return
	}

	// the latest POLRound should be this round.
	polRound, _ := cs.Votes.POLInfo()
	if polRound < round {
		panic(fmt.Sprintf("this POLRound should be %v but got %v", round, polRound))
	}

	// +2/3 prevoted nil. Unlock and precommit nil.
	if (blockID == common.Hash{}) {
		if cs.LockedBlock == nil {
			log.Debug("precommit step; +2/3 prevoted for nil", "height", height, "round", round)
		} else {
			log.Debug("precommit step; +2/3 prevoted for nil; unlocking", "height", height, "round", round)
			cs.LockedRound = -1
			cs.LockedBlock = nil
		}

		cs.signAddVote(ctx, PrecommitType, common.Hash{})
		return
	}

	// At this point, +2/3 prevoted for a particular block.

	// If we're already locked on that block, precommit it, and update the LockedRound
	if cs.LockedBlock.HashTo(blockID) {
		log.Debug("precommit step; +2/3 prevoted locked block; relocking", "height", height, "round", round)
		cs.LockedRound = round

		cs.signAddVote(ctx, PrecommitType, blockID)
		return
	}

	// If +2/3 prevoted for proposal block, stage and precommit it
	if cs.ProposalBlock.HashTo(blockID) {
		log.Debug("precommit step; +2/3 prevoted proposal block; locking", "height", height, "round", round, "hash", blockID)

		// Validate the block.
		if err := cs.blockExec.ValidateBlock(cs.chainState, cs.ProposalBlock, false); err != nil {
			panic(fmt.Sprintf("precommit step; +2/3 prevoted for an invalid block: %v", err))
		}

		cs.LockedRound = round
		cs.LockedBlock = cs.ProposalBlock

		cs.signAddVote(ctx, PrecommitType, blockID)
		return
	}

	// There was a polka in this round for a block we don't have.
	// Fetch that block, unlock, and precommit nil.
	// The +2/3 prevotes for this round is the POL for our unlock.
	log.Debug("precommit step; +2/3 prevotes for a block we do not have; voting nil", "height", height, "round", round, "block_id", blockID)

	cs.LockedRound = -1
	cs.LockedBlock = nil

	cs.signAddVote(ctx, PrecommitType, common.Hash{})
}

// Enter: any +2/3 precommits for next round.
func (cs *ConsensusState) enterPrecommitWait(ctx context.Context, height uint64, round int32) {
	if cs.Height != height || round < cs.Round || (cs.Round == round && cs.TriggeredTimeoutPrecommit) {
		log.Debug(
			"entering precommit wait step with invalid args",
			"height", height, "round", round,
			"triggered_timeout", cs.TriggeredTimeoutPrecommit,
			"current", fmt.Sprintf("%v/%v", cs.Height, cs.Round),
		)
		return
	}

	if !cs.Votes.Precommits(round).HasTwoThirdsAny() {
		panic(fmt.Sprintf(
			"entering precommit wait step (%v/%v), but precommits does not have any +2/3 votes",
			height, round,
		))
	}

	log.Debug("entering precommit wait step", "height", height, "round", round, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	defer func() {
		// Done enterPrecommitWait:
		cs.TriggeredTimeoutPrecommit = true
		cs.newStep(ctx)
	}()

	// wait for some more precommits; enterNewRound
	cs.scheduleTimeout(cs.config.Precommit(round), height, round, RoundStepPrecommitWait)
}

// Enter: +2/3 precommits for block
func (cs *ConsensusState) enterCommit(ctx context.Context, height uint64, commitRound int32) {
	if cs.Height != height || RoundStepCommit <= cs.Step {
		log.Debug(
			"entering commit step with invalid args",
			"height", height, "commit_round", commitRound,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	log.Debug("entering commit step", "height", height, "commit_round", commitRound, "current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step))

	defer func() {
		// Done enterCommit:
		// keep cs.Round the same, commitRound points to the right Precommits set.
		cs.updateRoundStep(cs.Round, RoundStepCommit)
		cs.CommitRound = commitRound
		cs.CommitTime = CanonicalNow()
		cs.newStep(ctx)

		// Maybe finalize immediately.
		cs.tryFinalizeCommit(ctx, height)
	}()

	blockID, ok := cs.Votes.Precommits(commitRound).TwoThirdsMajority()
	if !ok {
		panic("RunActionCommit() expects +2/3 precommits")
	}

	// The Locked* fields no longer matter.
	// Move them over to ProposalBlock if they match the commit hash,
	// otherwise they'll be cleared in updateToState.
	if cs.LockedBlock.HashTo(blockID) {
		log.Debug("commit is for a locked block; set ProposalBlock=LockedBlock", "height", height, "commit_round", commitRound, "block_hash", blockID)
		cs.ProposalBlock = cs.LockedBlock
	}

	// If we don't have the block being committed, set up to get it.
	if !cs.ProposalBlock.HashTo(blockID) {
		log.Info(
			"commit is for a block we do not know about; set ProposalBlock=nil",
			"height", height, "commit_round", commitRound,
			"proposal", cs.ProposalBlock.NilableHash(),
			"commit", blockID[:],
		)

		// We're getting the wrong block.
		// Set up ProposalBlockParts and keep waiting.
		cs.ProposalBlock = nil
	}
}

// If we have the block AND +2/3 commits for it, finalize.
func (cs *ConsensusState) tryFinalizeCommit(ctx context.Context, height uint64) {
	if cs.Height != height {
		panic(fmt.Sprintf("tryFinalizeCommit() cs.Height: %v vs height: %v", cs.Height, height))
	}

	blockID, ok := cs.Votes.Precommits(cs.CommitRound).TwoThirdsMajority()
	if (!ok || blockID == common.Hash{}) {
		log.Error("failed attempt to finalize commit; there was no +2/3 majority or +2/3 was for nil", "height", height)
		return
	}

	if !cs.ProposalBlock.HashTo(blockID) {
		// TODO: this happens every time if we're not a validator (ugly logs)
		// TODO: ^^ wait, why does it matter that we're a validator?
		log.Debug(
			"failed attempt to finalize commit; we do not have the commit block",
			"height", height,
			"proposal_block", cs.ProposalBlock.NilableHash(),
			"commit_block", blockID,
		)
		return
	}

	cs.finalizeCommit(ctx, height)
}

// Increment height and goto RoundStepNewHeight
func (cs *ConsensusState) finalizeCommit(ctx context.Context, height uint64) {
	if cs.Height != height || cs.Step != RoundStepCommit {
		log.Debug(
			"entering finalize commit step",
			"height", height,
			"current", fmt.Sprintf("%v/%v/%v", cs.Height, cs.Round, cs.Step),
		)
		return
	}

	blockID, ok := cs.Votes.Precommits(cs.CommitRound).TwoThirdsMajority()
	block := cs.ProposalBlock

	if !ok {
		panic("cannot finalize commit; commit does not have 2/3 majority")
	}
	if !block.HashTo(blockID) {
		panic("cannot finalize commit; proposal block does not hash to commit hash")
	}

	if err := cs.blockExec.ValidateBlock(cs.chainState, block, false); err != nil {
		panic(fmt.Errorf("+2/3 committed an invalid block: %w", err))
	}

	log.Info(
		"Finalizing commit of block",
		"height", height,
		"hash", block.Hash(),
		// "root", block.AppHash,
		// "num_txs", len(block.Txs),
	)

	log.Debug(fmt.Sprintf("%v", block), "height", height)

	// fail.Fail() // XXX

	// Save to blockStore.
	if cs.blockStore.Height() < block.NumberU64() {
		// NOTE: the seenCommit is local justification to commit this block,
		// but may differ from the LastCommit included in the next block
		precommits := cs.Votes.Precommits(cs.CommitRound)
		seenCommit := precommits.MakeCommit()
		cs.blockStore.SaveBlock(block, seenCommit)
	} else {
		// Happens during replay if we already saved the block but didn't commit
		log.Debug("calling finalizeCommit on already stored block", "height", block.Number)
	}

	// fail.Fail() // XXX

	// Write EndHeightMessage{} for this height, implying that the blockstore
	// has saved the block.
	//
	// If we crash before writing this EndHeightMessage{}, we will recover by
	// running ApplyBlock during the ABCI handshake when we restart.  If we
	// didn't save the block to the blockstore before writing
	// EndHeightMessage{}, we'd have to change WAL replay -- currently it
	// complains about replaying for heights where an #ENDHEIGHT entry already
	// exists.
	//
	// Either way, the State should not be resumed until we
	// successfully call ApplyBlock (ie. later here, or in Handshake after
	// restart).
	// endMsg := EndHeightMessage{height}
	// if err := cs.wal.WriteSync(endMsg); err != nil { // NOTE: fsync
	// 	panic(fmt.Sprintf(
	// 		"failed to write %v msg to consensus WAL due to %v; check your file system and restart the node",
	// 		endMsg, err,
	// 	))
	// }

	// fail.Fail() // XXX

	// Create a copy of the state for staging and an event cache for txs.
	stateCopy := cs.chainState.Copy()

	// Execute and commit the block, update and save the state, and update the mempool.
	// NOTE The block.AppHash wont reflect these txs until the next block.
	stateCopy, err := cs.blockExec.ApplyBlock(ctx, stateCopy, block)
	if err != nil {
		log.Error("failed to apply block", "height", height, "err", err)
		return
	}

	// fail.Fail() // XXX

	// NewHeightStep!
	cs.updateToState(ctx, stateCopy)

	// fail.Fail() // XXX

	// Private validator might have changed it's key pair => refetch pubkey.
	if err := cs.updatePrivValidatorPubKey(); err != nil {
		log.Error("failed to get private validator pubkey", "height", height, "err", err)
	}

	// cs.StartTime is already set.
	// Schedule Round0 to start soon.
	cs.scheduleRound0(&cs.RoundState)

	// By here,
	// * cs.Height has been increment to height+1
	// * cs.Step is now RoundStepNewHeight
	// * cs.StartTime is set to when we will start round0.
}

//-----------------------------------------------------------------------------

func (cs *ConsensusState) defaultSetProposal(ctx context.Context, proposal *Proposal) (bool, error) {
	// Already have one
	// TODO: possibly catch double proposals
	if cs.Proposal != nil {
		return false, nil
	}

	// Does not apply
	if proposal.Height != cs.Height || proposal.Round != cs.Round {
		return false, nil
	}

	// Verify POLRound, which must be -1 or in range [0, proposal.Round).
	if proposal.POLRound < -1 ||
		(proposal.POLRound >= 0 && proposal.POLRound >= proposal.Round) {
		return false, ErrInvalidProposalPOLRound
	}

	// Verify signature
	if !cs.Validators.GetProposer().PubKey.VerifySignature(proposal.ProposalSignBytes(cs.chainState.ChainID), proposal.Signature) {
		return false, ErrInvalidProposalSignature
	}

	cs.Proposal = proposal
	cs.ProposalBlock = proposal.Block
	log.Info("Received proposal", "height", cs.Height, "round", cs.Round, "from", cs.Validators.GetProposer().Address)

	// Update Valid* if we can.
	prevotes := cs.Votes.Prevotes(cs.Round)
	blockID, hasTwoThirds := prevotes.TwoThirdsMajority()
	if hasTwoThirds && (blockID != common.Hash{}) && (cs.ValidRound < cs.Round) {
		if cs.ProposalBlock.HashTo(blockID) {
			log.Debug(
				"updating valid block to new proposal block",
				"valid_round", cs.Round,
				"valid_block_hash", cs.ProposalBlock.Hash(),
			)

			cs.ValidRound = cs.Round
			cs.ValidBlock = cs.ProposalBlock
		}
		// TODO: In case there is +2/3 majority in Prevotes set for some
		// block and cs.ProposalBlock contains different block, either
		// proposer is faulty or voting power of faulty processes is more
		// than 1/3. We should trigger in the future accountability
		// procedure at this point.
	}

	if cs.Step <= RoundStepPropose && cs.isProposalComplete() {
		// Move onto the next step
		cs.enterPrevote(ctx, cs.Height, cs.Round)
		if hasTwoThirds { // this is optimisation as this will be triggered when prevote is added
			cs.enterPrecommit(ctx, cs.Height, cs.Round)
		}
	} else if cs.Step == RoundStepCommit {
		// If we're waiting on the proposal block...
		cs.tryFinalizeCommit(ctx, cs.Height)
	}

	return true, nil
}

// Attempt to add the vote. if its a duplicate signature, dupeout the validator
func (cs *ConsensusState) tryAddVote(ctx context.Context, vote *Vote, peerID string) (bool, error) {
	added, err := cs.addVote(ctx, vote, peerID)
	if err != nil {
		// If the vote height is off, we'll just ignore it,
		// But if it's a conflicting sig, add it to the cs.evpool.
		// If it's otherwise invalid, punish peer.
		// nolint: gocritic
		if voteErr, ok := err.(*ErrVoteConflictingVotes); ok {
			if cs.privValidatorPubKey == nil {
				return false, errPubKeyIsNotSet
			}

			if vote.ValidatorAddress == cs.privValidatorPubKey.Address() {
				log.Error(
					"found conflicting vote from ourselves; did you unsafe_reset a validator?",
					"height", vote.Height,
					"round", vote.Round,
					"type", vote.Type,
				)

				return added, err
			}

			// TODO: report conflicting votes to the evidence pool
			// cs.evpool.ReportConflictingVotes(voteErr.VoteA, voteErr.VoteB)
			log.Debug(
				"found and sent conflicting votes to the evidence pool",
				"vote_a", voteErr.VoteA,
				"vote_b", voteErr.VoteB,
			)

			return added, err
		} else if errors.Is(err, ErrVoteNonDeterministicSignature) {
			log.Debug("vote has non-deterministic signature", "err", err)
		} else {
			// Either
			// 1) bad peer OR
			// 2) not a bad peer? this can also err sometimes with "Unexpected step" OR
			// 3) tmkms use with multiple validators connecting to a single tmkms instance
			//		(https://github.com/tendermint/tendermint/issues/3839).
			log.Info("failed attempting to add vote", "err", err)
			return added, ErrAddingVote
		}
	}

	return added, nil
}

func (cs *ConsensusState) addVote(
	ctx context.Context,
	vote *Vote,
	peerID string,
) (added bool, err error) {
	log.Debug(
		"adding vote",
		"vote_height", vote.Height,
		"vote_type", vote.Type,
		"val_index", vote.ValidatorIndex,
		"cs_height", cs.Height,
	)

	// A precommit for the previous height?
	// These come in while we wait timeoutCommit
	if vote.Height+1 == cs.Height && vote.Type == PrecommitType {
		if cs.Step != RoundStepNewHeight {
			// Late precommit at prior height is ignored
			log.Debug("precommit vote came in after commit timeout and has been ignored", "vote", vote)
			return
		}

		added, err = cs.LastCommit.AddVote(vote)
		if !added {
			return
		}

		// if we can skip timeoutCommit and have all the votes now,
		if cs.config.SkipTimeoutCommit && cs.LastCommit.HasAll() {
			// go straight to new round (skip timeout commit)
			// cs.scheduleTimeout(time.Duration(0), cs.Height, 0, RoundStepNewHeight)
			cs.enterNewRound(ctx, cs.Height, 0)
		}

		return
	}

	// Height mismatch is ignored.
	// Not necessarily a bad peer, but not favorable behavior.
	if vote.Height != cs.Height {
		log.Debug("vote ignored and not added", "vote_height", vote.Height, "cs_height", cs.Height, "peer", peerID)
		return
	}

	height := cs.Height
	added, err = cs.Votes.AddVote(vote, peerID)
	if !added {
		// Either duplicate, or error upon cs.Votes.AddByIndex()
		return
	}

	switch vote.Type {
	case PrevoteType:
		prevotes := cs.Votes.Prevotes(vote.Round)
		log.Debug("added vote to prevote", "vote", vote, "prevotes", prevotes.StringShort())

		// If +2/3 prevotes for a block or nil for *any* round:
		if blockID, ok := prevotes.TwoThirdsMajority(); ok {
			// There was a polka!
			// If we're locked but this is a recent polka, unlock.
			// If it matches our ProposalBlock, update the ValidBlock

			// Unlock if `cs.LockedRound < vote.Round <= cs.Round`
			// NOTE: If vote.Round > cs.Round, we'll deal with it when we get to vote.Round
			if (cs.LockedBlock != nil) &&
				(cs.LockedRound < vote.Round) &&
				(vote.Round <= cs.Round) &&
				!cs.LockedBlock.HashTo(blockID) {

				log.Debug("unlocking because of POL", "locked_round", cs.LockedRound, "pol_round", vote.Round)

				cs.LockedRound = -1
				cs.LockedBlock = nil
			}

			// Update Valid* if we can.
			// NOTE: our proposal block may be nil or not what received a polka..
			if (blockID != common.Hash{}) && (cs.ValidRound < vote.Round) && (vote.Round == cs.Round) {
				if cs.ProposalBlock.HashTo(blockID) {
					log.Debug("updating valid block because of POL", "valid_round", cs.ValidRound, "pol_round", vote.Round)
					cs.ValidRound = vote.Round
					cs.ValidBlock = cs.ProposalBlock
				} else {
					log.Debug(
						"valid block we do not know about; set ProposalBlock=nil",
						"proposal", cs.ProposalBlock,
						"block_id", blockID,
					)

					// we're getting the wrong block
					cs.ProposalBlock = nil
				}
			}
		}

		// If +2/3 prevotes for *anything* for future round:
		switch {
		case cs.Round < vote.Round && prevotes.HasTwoThirdsAny():
			// Round-skip if there is any 2/3+ of votes ahead of us
			cs.enterNewRound(ctx, height, vote.Round)

		case cs.Round == vote.Round && RoundStepPrevote <= cs.Step: // current round
			blockID, ok := prevotes.TwoThirdsMajority()
			if ok && (cs.isProposalComplete() || blockID == common.Hash{}) {
				cs.enterPrecommit(ctx, height, vote.Round)
			} else if prevotes.HasTwoThirdsAny() {
				cs.enterPrevoteWait(ctx, height, vote.Round)
			}

		case cs.Proposal != nil && 0 <= cs.Proposal.POLRound && cs.Proposal.POLRound == vote.Round:
			// If the proposal is now complete, enter prevote of cs.Round.
			if cs.isProposalComplete() {
				cs.enterPrevote(ctx, height, cs.Round)
			}
		}

	case PrecommitType:
		precommits := cs.Votes.Precommits(vote.Round)
		log.Debug("added vote to precommit",
			"height", vote.Height,
			"round", vote.Round,
			"validator", vote.ValidatorAddress.String(),
			"vote_timestamp", vote.TimestampMs,
			"data", precommits.LogString())

		blockID, ok := precommits.TwoThirdsMajority()
		if ok {
			// Executed as TwoThirdsMajority could be from a higher round
			cs.enterNewRound(ctx, height, vote.Round)
			cs.enterPrecommit(ctx, height, vote.Round)

			if (blockID != common.Hash{}) {
				cs.enterCommit(ctx, height, vote.Round)
				if cs.config.SkipTimeoutCommit && precommits.HasAll() {
					cs.enterNewRound(ctx, cs.Height, 0)
				}
			} else {
				cs.enterPrecommitWait(ctx, height, vote.Round)
			}
		} else if cs.Round <= vote.Round && precommits.HasTwoThirdsAny() {
			cs.enterNewRound(ctx, height, vote.Round)
			cs.enterPrecommitWait(ctx, height, vote.Round)
		}

	default:
		panic(fmt.Sprintf("unexpected vote type %v", vote.Type))
	}

	return added, err
}

// CONTRACT: cs.privValidator is not nil.
func (cs *ConsensusState) signVote(
	msgType SignedMsgType,
	blockID common.Hash,
) (*Vote, error) {
	// Flush the WAL. Otherwise, we may not recompute the same vote to sign,
	// and the privValidator will refuse to sign anything.
	// if err := cs.wal.FlushAndSync(); err != nil {
	// 	return nil, err
	// }

	if cs.privValidatorPubKey == nil {
		return nil, errPubKeyIsNotSet
	}

	addr := cs.privValidatorPubKey.Address()
	valIdx, _ := cs.Validators.GetByAddress(addr)

	vote := &Vote{
		ValidatorAddress: addr,
		ValidatorIndex:   valIdx,
		Height:           cs.Height,
		Round:            cs.Round,
		TimestampMs:      cs.voteTime(),
		Type:             msgType,
		BlockID:          blockID,
	}

	// If the signedMessageType is for precommit,
	// use our local precommit Timeout as the max wait time for getting a singed commit. The same goes for prevote.
	var timeout time.Duration

	switch msgType {
	case PrecommitType:
		timeout = cs.config.TimeoutPrecommit
	case PrevoteType:
		timeout = cs.config.TimeoutPrevote
	default:
		timeout = time.Second
	}

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	err := cs.privValidator.SignVote(ctx, cs.chainState.ChainID, vote)

	return vote, err
}

// voteTime ensures monotonicity of the time a validator votes on.
// It ensures that for a prior block with a BFT-timestamp of T,
// any vote from this validator will have time at least time T + 1ms.
// This is needed, as monotonicity of time is a guarantee that BFT time provides.
func (cs *ConsensusState) voteTime() uint64 {
	now := uint64(CanonicalNowMs())
	minVoteTime := now
	// Minimum time increment between blocks
	timeIota := uint64(1) // in milli
	// TODO: We should remove next line in case we don't vote for v in case cs.ProposalBlock == nil,
	// even if cs.LockedBlock != nil. See https://docs.tendermint.com/master/spec/.
	if cs.LockedBlock != nil {
		// See the BFT time spec https://docs.tendermint.com/master/spec/consensus/bft-time.html
		minVoteTime = cs.LockedBlock.TimeMs() + timeIota
	} else if cs.ProposalBlock != nil {
		minVoteTime = cs.ProposalBlock.TimeMs() + timeIota
	}

	if now > minVoteTime {
		return now
	}
	return minVoteTime
}

// sign the vote and publish on internalMsgQueue
func (cs *ConsensusState) signAddVote(ctx context.Context, msgType SignedMsgType, blockID common.Hash) *Vote {
	if cs.privValidator == nil { // the node does not have a key
		return nil
	}

	if cs.privValidatorPubKey == nil {
		// Vote won't be signed, but it's not critical.
		log.Error(fmt.Sprintf("signAddVote: %v", errPubKeyIsNotSet))
		return nil
	}

	// If the node not in the validator set, do nothing.
	if !cs.Validators.HasAddress(cs.privValidatorPubKey.Address()) {
		return nil
	}

	// TODO: pass pubKey to signVote
	vote, err := cs.signVote(msgType, blockID)
	if err == nil {
		cs.sendInternalMessage(ctx, MsgInfo{&VoteMessage{Vote: vote}, ""})
		log.Debug("signed and pushed vote", "height", cs.Height, "round", cs.Round, "vote", vote)
		return vote
	}

	log.Error("failed signing vote", "height", cs.Height, "round", cs.Round, "vote", vote, "err", err)
	return nil
}

// updatePrivValidatorPubKey get's the private validator public key and
// memoizes it. This func returns an error if the private validator is not
// responding or responds with an error.
func (cs *ConsensusState) updatePrivValidatorPubKey() error {
	if cs.privValidator == nil {
		return nil
	}

	var timeout time.Duration
	if cs.config.TimeoutPrecommit > cs.config.TimeoutPrevote {
		timeout = cs.config.TimeoutPrecommit
	} else {
		timeout = cs.config.TimeoutPrevote
	}

	// no GetPubKey retry beyond the proposal/voting in RetrySignerClient
	if cs.Step >= RoundStepPrecommit && cs.privValidatorType == RetrySignerClient {
		timeout = 0
	}

	// set context timeout depending on the configuration and the State step,
	// this helps in avoiding blocking of the remote signer connection.
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	pubKey, err := cs.privValidator.GetPubKey(ctx)
	if err != nil {
		return err
	}
	cs.privValidatorPubKey = pubKey
	return nil
}

// look back to check existence of the node's consensus votes before joining consensus
func (cs *ConsensusState) checkDoubleSigningRisk(height uint64) error {
	if cs.privValidator != nil && cs.privValidatorPubKey != nil && cs.config.DoubleSignCheckHeight > 0 && height > 0 {
		valAddr := cs.privValidatorPubKey.Address()
		doubleSignCheckHeight := cs.config.DoubleSignCheckHeight
		if doubleSignCheckHeight > height {
			doubleSignCheckHeight = height
		}

		for i := uint64(1); i < doubleSignCheckHeight; i++ {
			lastCommit := cs.LoadCommit(height - i)
			if lastCommit != nil {
				for sigIdx, s := range lastCommit.Signatures {
					if s.BlockIDFlag == BlockIDFlagCommit && s.ValidatorAddress == valAddr {
						log.Info("found signature from the same key", "sig", s, "idx", sigIdx, "height", height-i)
						return ErrSignatureFoundInPastBlocks
					}
				}
			}
		}
	}

	return nil
}
