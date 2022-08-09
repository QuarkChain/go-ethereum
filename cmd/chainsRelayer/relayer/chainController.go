package relayer

type ChainController struct {
	ChainOperators    []*ChainOperator
	ChainIdToOperator map[int]int
}

func NewChainCrontroller() *ChainController {
	c := &ChainController{}
	c.ChainOperators = make([]*ChainOperator, 0)
	c.ChainIdToOperator = make(map[int]int)
	return c
}

func (c *ChainController) getChainOperatorByChainId(chainId int) *ChainOperator {
	index, ok := c.ChainIdToOperator[chainId]
	if !ok {
		return nil
	}

	return c.ChainOperators[index]
}

func (c *ChainController) AddChainOperator(chainId int, op *ChainOperator) {
	index := len(c.ChainOperators)
	c.ChainOperators = append(c.ChainOperators, op)
	c.ChainIdToOperator[chainId] = index
}
