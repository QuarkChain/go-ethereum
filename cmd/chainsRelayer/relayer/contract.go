package relayer

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

/**
 * Contract Listener
**/
type Contract struct {
	// Addr is the contract address
	Addr        common.Address
	ContractAbi abi.ABI
	// HandleEventList record the association of an eventId to the taskIndex which generates by launching a listen task to monitor the event
	HandleEventList map[common.Hash]int
}

func NewContract(addr common.Address, contractAbi abi.ABI) *Contract {
	return &Contract{Addr: addr, ContractAbi: contractAbi, HandleEventList: make(map[common.Hash]int)}
}

func (c *Contract) getEventId(name string) common.Hash {
	return c.ContractAbi.Events[name].ID
}

func (c *Contract) insertTaskIndex(taskIndex int, eventName string) {
	eventId := c.getEventId(eventName)
	c.HandleEventList[eventId] = taskIndex
}

func (c *Contract) getTaskIndex(eventName string) int {
	eventId := c.getEventId(eventName)
	return c.HandleEventList[eventId]
}
