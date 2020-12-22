package core

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"sync/atomic"
)

var (
	rootAddr = make(map[common.Address]common.Address, 0)
)

func Find(x common.Address) common.Address {
	if rootAddr[x] != x {
		rootAddr[x] = Find(rootAddr[x])
	}
	return rootAddr[x]
}

func Union(x common.Address, y *common.Address) {
	if _, ok := rootAddr[x]; !ok {
		rootAddr[x] = x
	}
	if y == nil {
		return
	}
	if _, ok := rootAddr[*y]; !ok {
		rootAddr[*y] = *y
	}
	fx := Find(x)
	fy := Find(*y)
	if fx != fy {
		rootAddr[fy] = fx
	}
}

func grouping(from []common.Address, to []*common.Address) (map[int][]int, map[int]int) {
	rootAddr = make(map[common.Address]common.Address, 0)
	for index, sender := range from {
		Union(sender, to[index])
	}

	groupList := make(map[int][]int, 0)
	addrToID := make(map[common.Address]int, 0)
	indexToID := make(map[int]int, 0)

	for index, sender := range from {
		rootAddr := Find(sender)
		id, exist := addrToID[rootAddr]
		if !exist {
			id = len(groupList)
			addrToID[rootAddr] = id

		}
		groupList[id] = append(groupList[id], index)
		indexToID[index] = id
	}
	return groupList, indexToID

}

type groupInfo struct {
	nextTxInGroup  map[int]int
	preTxInGroup   map[int]int
	indexToGroupID map[int]int
}

func newGroupInfo(from []common.Address, to []*common.Address) (*groupInfo, []int, int) {
	groupList, indexToID := grouping(from, to)

	nextTxIndexInGroup := make(map[int]int)
	preTxIndexInGroup := make(map[int]int)
	heapList := make([]int, 0)
	for _, list := range groupList {
		for index := 0; index < len(list); index++ {
			if index+1 <= len(list)-1 {
				nextTxIndexInGroup[list[index]] = list[index+1]
			}
			if index-1 >= 0 {
				preTxIndexInGroup[list[index]] = list[index-1]
			}
		}
		heapList = append(heapList, list[0])
	}

	return &groupInfo{
		nextTxInGroup:  nextTxIndexInGroup,
		preTxInGroup:   preTxIndexInGroup,
		indexToGroupID: indexToID,
	}, heapList, len(groupList)
}

func (s *pallTxManager) push(txIndex int) {
	if !atomic.CompareAndSwapInt32(&s.pending[txIndex], 0, 1) {
		return
	}

	if !s.ended && s.txResults[txIndex] == nil {
		s.txQueue <- txIndex
	} else {
		s.setPending(txIndex, false)
	}
}

type pallTxManager struct {
	resultID int32

	pending    []int32
	needFailed []bool

	blocks *types.Block

	txLen int
	bc    *BlockChain

	baseStateDB    *state.StateDB
	mergedReceipts []*types.Receipt
	ch             chan struct{}
	ended          bool

	groupInfo *groupInfo

	txQueue chan int
	//mergedQueue chan struct{}
	resultQueue chan struct{}
	txResults   []*txResult
	gp          uint64
}

type txResult struct {
	preID   int32
	ID      int32
	st      *state.StateDB
	index   int
	receipt *types.Receipt
}

func NewPallTxManage(block *types.Block, st *state.StateDB, bc *BlockChain) *pallTxManager {
	fmt.Println("pall", "from", block.NumberU64())
	errCnt = 0
	txLen := 0
	gp := uint64(0)

	fromList := make([]common.Address, 0)
	toList := make([]*common.Address, 0)

	signer := types.MakeSigner(bc.chainConfig, block.Number())
	for _, tx := range block.Transactions() {
		sender, _ := types.Sender(signer, tx)
		fromList = append(fromList, sender)
		toList = append(toList, tx.To())

	}
	txLen += len(block.Transactions())
	gp += block.GasLimit()

	groupInfo, headTxInGroup, groupLen := newGroupInfo(fromList, toList)
	p := &pallTxManager{
		//pending:        make([]bool, txLen, txLen),
		pending:    make([]int32, txLen, txLen),
		needFailed: make([]bool, txLen, txLen),
		blocks:     block,

		txLen: txLen,
		bc:    bc,

		groupInfo:      groupInfo,
		baseStateDB:    st,
		mergedReceipts: make([]*types.Receipt, txLen, txLen),
		ch:             make(chan struct{}, 1),

		txQueue:     make(chan int, txLen),
		resultQueue: make(chan struct{}, txLen),
		txResults:   make([]*txResult, txLen, txLen),
		gp:          gp,
	}

	for _, txIndex := range headTxInGroup {
		p.txQueue <- txIndex
	}

	if len(block.Transactions()) == 0 {
		p.calReward(0)
	}

	if txLen == 0 {
		p.baseStateDB.FinalUpdateObjs()
		return p
	}

	thread := groupLen
	if thread > 32 {
		thread = 32
	}

	for index := 0; index < thread; index++ {
		go p.txLoop()
	}
	go p.mergeLoop()
	return p
}

func (p *pallTxManager) isPending(index int) bool {
	return atomic.LoadInt32(&p.pending[index]) == 1
}

func (p *pallTxManager) setPending(index int, stats bool) {
	if stats {
		atomic.StoreInt32(&p.pending[index], 1)
	} else {
		atomic.StoreInt32(&p.pending[index], 0)
	}

}

func (p *pallTxManager) getResultID() int32 {
	atomic.AddInt32(&p.resultID, 1)
	return p.resultID
}

func (p *pallTxManager) calReward(txIndex int) {
	p.blockFinalize(txIndex)
}

func (p *pallTxManager) blockFinalize(txIndex int) {
	block := p.blocks
	p.bc.engine.Finalize(p.bc, block.Header(), p.baseStateDB, block.Transactions(), block.Uncles())
	if block.NumberU64() == p.bc.Config().DAOForkBlock.Uint64()-1 {
		misc.ApplyDAOHardFork(p.baseStateDB)
	}

	p.baseStateDB.MergeReward(txIndex)
}

func (p *pallTxManager) AddReceiptToQueue(re *txResult) bool {
	if re == nil {
		return false
	}
	if p.needFailed[re.index] {
		p.needFailed[re.index] = false
		return false
	}

	if p.txResults[re.index] == nil {
		p.markNextFailed(re.index)
		re.ID = p.getResultID()
		p.txResults[re.index] = re
		if nextTxIndex, ok := p.groupInfo.nextTxInGroup[re.index]; ok {
			p.push(nextTxIndex)
		}
		if len(p.resultQueue) != p.txLen {
			p.resultQueue <- struct{}{}
		}
		return true
	} else {
		return true
	}

}

func (p *pallTxManager) txLoop() {
	for !p.ended {
		txIndex, ok := <-p.txQueue
		if !ok {
			break
		}
		if p.txResults[txIndex] != nil {
			p.setPending(txIndex, false)
			continue
		}
		re := p.handleTx(txIndex)
		p.setPending(txIndex, false)
		stats := p.AddReceiptToQueue(re)
		if stats {
		} else {
			if txIndex > p.baseStateDB.MergedIndex {
				p.push(txIndex)
			}

		}
	}
}

func (p *pallTxManager) mergeLoop() {
	for !p.ended {
		_, ok := <-p.resultQueue
		if !ok {
			break
		}
		//handled := false

		nextTx := p.baseStateDB.MergedIndex + 1
		for nextTx < p.txLen && p.txResults[nextTx] != nil {
			rr := p.txResults[nextTx]

			//handled = true
			if succ := p.handleReceipt(rr); !succ {
				p.txResults[rr.index] = nil
				p.markNextFailed(rr.index)
				break
			}
			p.baseStateDB.MergedIndex = nextTx
			nextTx = p.baseStateDB.MergedIndex + 1
		}

		if p.baseStateDB.MergedIndex+1 == p.txLen && !p.ended {
			p.calReward(p.baseStateDB.MergedIndex)
			p.ended = true
			p.baseStateDB.FinalUpdateObjs()
			close(p.txQueue)
			p.ch <- struct{}{}
			return
		}
		p.push(p.baseStateDB.MergedIndex + 1)
	}
}

func (p *pallTxManager) markNextFailed(next int) {
	for true {
		var ok bool
		next, ok = p.groupInfo.nextTxInGroup[next]
		if !ok {
			break
		}
		if p.txResults[next] != nil {
			p.txResults[next] = nil
		} else {
			if p.isPending(next) {
				p.needFailed[next] = true
			}
			break
		}
	}
}
func (p *pallTxManager) handleReceipt(rr *txResult) bool {
	if rr.preID != -1 && rr.preID != p.txResults[rr.st.MergedIndex].ID {
		return false
	}

	block := p.blocks
	if rr.receipt != nil && !rr.st.Conflict(p.baseStateDB, block.Coinbase(), rr.preID != -1, p.groupInfo.indexToGroupID) {
		txFee := new(big.Int).Mul(new(big.Int).SetUint64(rr.receipt.GasUsed), block.Transactions()[rr.index].GasPrice())
		rr.st.Merge(p.baseStateDB, block.Coinbase(), txFee)
		p.gp -= rr.receipt.GasUsed
		p.mergedReceipts[rr.index] = rr.receipt
		return true
	}
	return false
}

var (
	errCnt = 0
)

func (p *pallTxManager) handleTx(index int) *txResult {
	block := p.blocks
	tx := block.Transactions()[index]

	var st *state.StateDB

	preResultID := int32(-1)
	preIndex, existPre := p.groupInfo.preTxInGroup[index]

	preResult := p.txResults[preIndex]
	if existPre && preResult != nil && preIndex > p.baseStateDB.MergedIndex {
		st = preResult.st.Copy()
		st.MergedIndex = preIndex
		preResultID = preResult.ID

	} else {
		st, _ = state.New(common.Hash{}, p.bc.stateCache, p.bc.snaps)
		st.MergedIndex = p.baseStateDB.MergedIndex
	}

	st.MergedSts = p.baseStateDB.MergedSts
	gas := p.gp

	st.Prepare(tx.Hash(), block.Hash(), index)
	if p.txResults[index] != nil || index <= p.baseStateDB.MergedIndex {
		return nil
	}

	receipt, err := ApplyTransaction(p.bc.chainConfig, p.bc, nil, new(GasPool).AddGas(gas), st, block.Header(), tx, nil, p.bc.vmConfig)

	if index <= p.baseStateDB.MergedIndex {
		return nil
	}
	if err != nil && st.MergedIndex+1 == index && st.MergedIndex == p.baseStateDB.MergedIndex && preResultID == -1 {
		errCnt++
		if errCnt > 100 {
			fmt.Println("?????????", st.MergedIndex, index, p.baseStateDB.MergedIndex, preResultID)
			fmt.Println("sbbbbbbbbbbbb", "useFake", preResultID, "执行", index, "基于", st.MergedIndex, "当前base", p.baseStateDB.MergedIndex, "realIndex", index)
			panic(err)
		}
	}

	return &txResult{
		preID:   preResultID,
		st:      st,
		index:   index,
		receipt: receipt,
	}
}

func (p *pallTxManager) GetReceiptsAndLogs() (types.Receipts, []*types.Log, uint64) {
	block := p.blocks
	cumulativeGasUsed := uint64(0)
	log := make([]*types.Log, 0)
	rs := make(types.Receipts, 0)
	ll := len(block.Transactions())

	for i := 0; i < ll; i++ {
		cumulativeGasUsed = cumulativeGasUsed + p.mergedReceipts[i].GasUsed
		p.mergedReceipts[i].CumulativeGasUsed = cumulativeGasUsed
		log = append(log, p.mergedReceipts[i].Logs...)
		rs = append(rs, p.mergedReceipts[i])
	}

	return rs, log, cumulativeGasUsed
}
