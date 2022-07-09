package types

import (
	"github.com/ethereum/go-ethereum/common"
)

type TxWithExternalCall struct {
	TxData
	ExternalCallResult []byte
}

func NewTxWithExternalCall(txData TxData, externalCallResult []byte) *TxWithExternalCall {
	return &TxWithExternalCall{TxData: txData, ExternalCallResult: externalCallResult}
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *TxWithExternalCall) copy() TxData {
	cpyInner := tx.TxData.copy()
	cpy := &TxWithExternalCall{
		TxData: cpyInner,
	}

	if len(tx.ExternalCallResult) != 0 {
		cpy.ExternalCallResult = common.CopyBytes(tx.ExternalCallResult)
	}

	return cpy
}

func (tx *TxWithExternalCall) externalCallResult() []byte {
	return tx.ExternalCallResult
}

func (tx *TxWithExternalCall) setExternalCallResult(callRes []byte) {
	tx.ExternalCallResult = callRes
}

func (tx *TxWithExternalCall) ExternalCallWrapTx() byte {
	return ExternalCallWrapTxType
}
