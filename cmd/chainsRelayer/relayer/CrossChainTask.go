package relayer

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"time"
)

func SendMintNativeTxToWeb3Q(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator, ethTxHappened uint64) *CrossChainCallTask {
	return NewCrossChainCallTask(w3qChainOperator.Ctx, ethChainOperator, w3qChainOperator, true, make(chan struct{}), ethChainOperator.waitingExpectHeight, ethTxHappened+10)
}

func SendTxToEthereum(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator) *CrossChainCallTask {
	return NewCrossChainCallTask(ethChainOperator.Ctx, w3qChainOperator, ethChainOperator, false, nil, nil, 0)
}

func SendTxToWeb3q(ethChainOperator *ChainOperator, w3qChainOperator *ChainOperator) *CrossChainCallTask {
	return NewCrossChainCallTask(ethChainOperator.Ctx, ethChainOperator, w3qChainOperator, false, nil, nil, 0)
}

// 是否需要一个在监听到某个区块之后去执行的taskPool
// 将mintNative的执行过程封装成另外一种task
// 这种task有一下特性
// 1. 它是要到另一条chain上去执行的
// 2. 它需要在本链达成额外的一些条件，在dstChain 才能执行成功
// 3. 所以它应该属于一种delpayTask
// 4. 因此我需要一些flag来标识这种task

type CrossChainCallTask struct {
	ctx               context.Context
	srcChainOperator  *ChainOperator
	dstChainOperator  *ChainOperator
	delay             bool
	delayChan         chan struct{}
	delayFunc         func(chan struct{}, uint64) error
	ExpectHeightOnETH uint64
}

func NewCrossChainCallTask(ctx context.Context, srcChainOperator *ChainOperator, dstChainOperator *ChainOperator, delay bool, delayChan chan struct{}, delayFunc func(chan struct{}, uint64) error, ethTxHappened uint64) *CrossChainCallTask {
	return &CrossChainCallTask{ctx: ctx, srcChainOperator: srcChainOperator, dstChainOperator: dstChainOperator, delay: delay, delayChan: delayChan, delayFunc: delayFunc, ExpectHeightOnETH: ethTxHappened + 10}
}

func (c *CrossChainCallTask) Doing(tx *txArg) error {
	if c.delay {
		go c.delayFunc(c.delayChan, c.ExpectHeightOnETH)
		<-c.delayChan
		c.dstChainOperator.SendTxArg(tx)
	} else {
		c.dstChainOperator.SendTxArg(tx)
	}

	return nil
}

func (c *ChainOperator) waitingExpectHeight(delay chan struct{}, expectHeight uint64) error {
	for {
		number, err := c.Executor.BlockNumber(c.Ctx)
		if err != nil {
			return err
		}

		if number < expectHeight {
			fmt.Println("交易等待中")
			var delayNumber int64 = int64(expectHeight-number) * 15
			st := int64(delayNumber) * int64(time.Second)
			time.Sleep(time.Duration(st))
		} else {
			log.Info("发送交易条件已经达成")
			delay <- struct{}{}
			break
		}
	}
	return nil
}
