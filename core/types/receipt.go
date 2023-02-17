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

package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec@latest -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	receiptStatusFailedRLP     = []byte{}
	receiptStatusSuccessfulRLP = []byte{0x01}
)

// This error is returned when a typed receipt is decoded, but the string is empty.
var errEmptyTypedReceipt = errors.New("empty typed receipt bytes")

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

type ReceiptComplete Receipt

func ConvertReceipts(old []*ReceiptComplete) (new Receipts) {
	new = make(Receipts, 0, len(old))
	for _, r := range old {
		new = append(new, (*Receipt)(r))
	}
	return
}

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields: These fields are defined by the Yellow Paper
	Type              uint8  `json:"type,omitempty"`
	PostState         []byte `json:"root"`
	Status            uint64 `json:"status"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"`
	Bloom             Bloom  `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log `json:"logs"              gencodec:"required"`

	// Implementation fields: These fields are added by geth when processing a transaction.
	// They are stored in the chain database.
	TxHash          common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress common.Address `json:"contractAddress"`
	GasUsed         uint64         `json:"gasUsed" gencodec:"required"`

	// Inclusion information: These fields provide information about the inclusion of the
	// transaction corresponding to this receipt.
	BlockHash        common.Hash `json:"blockHash,omitempty"`
	BlockNumber      *big.Int    `json:"blockNumber,omitempty"`
	TransactionIndex uint        `json:"transactionIndex"`
}

type receiptMarshaling struct {
	Type              hexutil.Uint64
	PostState         hexutil.Bytes
	Status            hexutil.Uint64
	CumulativeGasUsed hexutil.Uint64
	GasUsed           hexutil.Uint64
	BlockNumber       *hexutil.Big
	TransactionIndex  hexutil.Uint
}

// receiptRLP is the consensus encoding of a receipt.
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// receiptRLPComplete is the p2p encoding of a receipt
type receiptRLPComplete struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
	Type              uint8
	TxHash            common.Hash
	ContractAddress   *common.Address `rlp:"nil"`
}

// storedReceiptRLPComplete is the complete storage encoding of a receipt.
type storedReceiptRLPComplete struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Logs              []*Log
	Type              uint8
	TxHash            common.Hash
	ContractAddress   *common.Address `rlp:"nil"`
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
// Deprecated: create receipts using a struct literal instead.
func NewReceipt(root []byte, failed bool, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{
		Type:              LegacyTxType,
		PostState:         common.CopyBytes(root),
		CumulativeGasUsed: cumulativeGasUsed,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

func (r *ReceiptComplete) EncodeRLP(w io.Writer) error {

	var contract *common.Address
	if r.ContractAddress != (common.Address{}) {
		contract = &r.ContractAddress
	}
	data := &receiptRLPComplete{(*Receipt)(r).statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs, r.Type, r.TxHash, contract}

	if r.Type == LegacyTxType {
		return rlp.Encode(w, data)
	}

	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	buf.WriteByte(r.Type)
	err := rlp.Encode(buf, data)
	if err != nil {
		return err
	}

	return rlp.Encode(w, buf.Bytes())
}

// EncodeRLP implements rlp.Encoder, and flattens the consensus fields of a receipt
// into an RLP stream. If no post state is present, byzantium fork is assumed.
func (r *Receipt) EncodeRLP(w io.Writer) error {
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		return rlp.Encode(w, data)
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := r.encodeTyped(data, buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed receipt to w.
func (r *Receipt) encodeTyped(data *receiptRLP, w *bytes.Buffer) error {
	w.WriteByte(r.Type)
	return rlp.Encode(w, data)
}

// MarshalBinary returns the consensus encoding of the receipt.
func (r *Receipt) MarshalBinary() ([]byte, error) {
	if r.Type == LegacyTxType {
		return rlp.EncodeToBytes(r)
	}
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	var buf bytes.Buffer
	err := r.encodeTyped(data, &buf)
	return buf.Bytes(), err
}

func (r *ReceiptComplete) DecodeRLP(_s *rlp.Stream) error {
	blob, err := _s.Raw()
	if err != nil {
		return err
	}

	s := rlp.NewStream(bytes.NewReader(blob), uint64(len(blob)))
	kind, _, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy receipt.
		r.Type = LegacyTxType

		var dec receiptRLPComplete
		if err := s.Decode(&dec); err != nil {
			var dec receiptRLP
			if err = rlp.DecodeBytes(blob, &dec); err != nil {
				return err
			}
			return (*Receipt)(r).setFromRLP(dec)
		}

		return (*Receipt)(r).setFromRLPComplete(dec)
	case kind == rlp.String:
		// It's an EIP-2718 typed tx receipt.
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errEmptyTypedReceipt
		}
		r.Type = b[0]
		if r.Type == AccessListTxType || r.Type == DynamicFeeTxType {
			var dec receiptRLPComplete
			if err := rlp.DecodeBytes(b[1:], &dec); err != nil {
				var dec receiptRLP
				if err := rlp.DecodeBytes(b[1:], &dec); err != nil {
					return err
				}
				return (*Receipt)(r).setFromRLP(dec)
			}
			return (*Receipt)(r).setFromRLPComplete(dec)
		}
		return ErrTxTypeNotSupported
	default:
		return rlp.ErrExpectedList
	}
}

// DecodeRLP implements rlp.Decoder, and loads the consensus fields of a receipt
// from an RLP stream.
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	kind, _, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy receipt.
		var dec receiptRLP
		if err := s.Decode(&dec); err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(dec)
	case kind == rlp.String:
		// It's an EIP-2718 typed tx receipt.
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return errEmptyTypedReceipt
		}
		r.Type = b[0]
		if r.Type == AccessListTxType || r.Type == DynamicFeeTxType {
			var dec receiptRLP
			if err := rlp.DecodeBytes(b[1:], &dec); err != nil {
				return err
			}
			return r.setFromRLP(dec)
		}
		return ErrTxTypeNotSupported
	default:
		return rlp.ErrExpectedList
	}
}

// UnmarshalBinary decodes the consensus encoding of receipts.
// It supports legacy RLP receipts and EIP-2718 typed receipts.
func (r *Receipt) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		// It's a legacy receipt decode the RLP
		var data receiptRLP
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(data)
	}
	// It's an EIP2718 typed transaction envelope.
	return r.decodeTyped(b)
}

// decodeTyped decodes a typed receipt from the canonical format.
func (r *Receipt) decodeTyped(b []byte) error {
	if len(b) == 0 {
		return errEmptyTypedReceipt
	}
	switch b[0] {
	case DynamicFeeTxType, AccessListTxType:
		var data receiptRLP
		err := rlp.DecodeBytes(b[1:], &data)
		if err != nil {
			return err
		}
		r.Type = b[0]
		return r.setFromRLP(data)
	default:
		return ErrTxTypeNotSupported
	}
}

func (r *Receipt) setFromRLP(data receiptRLP) error {
	r.CumulativeGasUsed, r.Bloom, r.Logs = data.CumulativeGasUsed, data.Bloom, data.Logs
	return r.setStatus(data.PostStateOrStatus)
}

func (r *Receipt) setFromRLPComplete(data receiptRLPComplete) error {
	r.CumulativeGasUsed, r.Bloom, r.Logs, r.Type, r.TxHash = data.CumulativeGasUsed, data.Bloom, data.Logs, data.Type, data.TxHash
	if data.ContractAddress != nil {
		r.ContractAddress = *data.ContractAddress
	}
	return r.setStatus(data.PostStateOrStatus)
}

func (r *Receipt) setStatus(postStateOrStatus []byte) error {
	switch {
	case bytes.Equal(postStateOrStatus, receiptStatusSuccessfulRLP):
		r.Status = ReceiptStatusSuccessful
	case bytes.Equal(postStateOrStatus, receiptStatusFailedRLP):
		r.Status = ReceiptStatusFailed
	case len(postStateOrStatus) == len(common.Hash{}):
		r.PostState = postStateOrStatus
	default:
		return fmt.Errorf("invalid receipt status %x", postStateOrStatus)
	}
	return nil
}

func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 {
		if r.Status == ReceiptStatusFailed {
			return receiptStatusFailedRLP
		}
		return receiptStatusSuccessfulRLP
	}
	return r.PostState
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (r *Receipt) Size() common.StorageSize {
	size := common.StorageSize(unsafe.Sizeof(*r)) + common.StorageSize(len(r.PostState))
	size += common.StorageSize(len(r.Logs)) * common.StorageSize(unsafe.Sizeof(Log{}))
	for _, log := range r.Logs {
		size += common.StorageSize(len(log.Topics)*common.HashLength + len(log.Data))
	}
	return size
}

// ReceiptForStorage is a wrapper around a Receipt that flattens and parses the
// entire content of a receipt, as opposed to only the consensus fields originally.
type ReceiptForStorage Receipt

// EncodeRLP implements rlp.Encoder, and flattens all content fields of a receipt
// into an RLP stream.
func (r *ReceiptForStorage) EncodeRLP(_w io.Writer) error {
	// Encode the receipt using storedReceiptRLPComplete format
	// This is the encoding version of decodeStoredReceiptRLPComplete()
	w := rlp.NewEncoderBuffer(_w)
	outerList := w.List()
	w.WriteBytes((*Receipt)(r).statusEncoding())
	w.WriteUint64(r.CumulativeGasUsed)
	logList := w.List()
	for _, log := range r.Logs {
		if err := rlp.Encode(w, log); err != nil {
			return err
		}
	}
	w.ListEnd(logList)

	if err := rlp.Encode(w, r.Type); err != nil {
		return err
	}
	if err := rlp.Encode(w, r.TxHash); err != nil {
		return err
	}
	var contract *common.Address
	addr := r.ContractAddress
	if addr != (common.Address{}) {
		contract = &addr
	}
	if err := rlp.Encode(w, contract); err != nil {
		return err
	}

	w.ListEnd(outerList)
	return w.Flush()
}

// DecodeRLP implements rlp.Decoder, and loads both consensus and implementation
// fields of a receipt from an RLP stream.
func (r *ReceiptForStorage) DecodeRLP(s *rlp.Stream) error {
	// Retrieve the entire receipt blob as we need to try multiple decoders
	blob, err := s.Raw()
	if err != nil {
		return err
	}
	return decodeStoredReceiptRLPComplete(r, blob)
}

func decodeStoredReceiptRLPComplete(r *ReceiptForStorage, blob []byte) error {
	var stored storedReceiptRLPComplete
	if err := rlp.DecodeBytes(blob, &stored); err != nil {
		return err
	}
	r.Type = stored.Type
	r.TxHash = stored.TxHash
	if stored.ContractAddress != nil {
		r.ContractAddress = *stored.ContractAddress
	}
	if err := (*Receipt)(r).setStatus(stored.PostStateOrStatus); err != nil {
		return err
	}
	r.CumulativeGasUsed = stored.CumulativeGasUsed
	r.Logs = make([]*Log, len(stored.Logs))
	for i, log := range stored.Logs {
		r.Logs[i] = (*Log)(log)
	}
	r.Bloom = CreateBloom(Receipts{(*Receipt)(r)})

	return nil
}

// Receipts implements DerivableList for receipts.
type Receipts []*Receipt

// Len returns the number of receipts in this list.
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex encodes the i'th receipt to w.
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	switch r.Type {
	case LegacyTxType:
		rlp.Encode(w, data)
	case AccessListTxType:
		w.WriteByte(AccessListTxType)
		rlp.Encode(w, data)
	case DynamicFeeTxType:
		w.WriteByte(DynamicFeeTxType)
		rlp.Encode(w, data)
	default:
		// For unsupported types, write nothing. Since this is for
		// DeriveSha, the error will be caught matching the derived hash
		// to the block.
	}
}

func (rs Receipts) DeriveFieldsNoBody(hash common.Hash, number uint64) error {
	logIndex := uint(0)
	for i := 0; i < len(rs); i++ {
		if rs[i].TxHash == (common.Hash{}) {
			return fmt.Errorf("receipt is not complete")
		}

		// block location fields
		rs[i].BlockHash = hash
		rs[i].BlockNumber = new(big.Int).SetUint64(number)
		rs[i].TransactionIndex = uint(i)

		// The used gas can be calculated based on previous r
		if i == 0 {
			rs[i].GasUsed = rs[i].CumulativeGasUsed
		} else {
			rs[i].GasUsed = rs[i].CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}
		// The derived log fields can simply be set from the block and transaction
		for j := 0; j < len(rs[i].Logs); j++ {
			rs[i].Logs[j].BlockNumber = number
			rs[i].Logs[j].BlockHash = hash
			rs[i].Logs[j].TxHash = rs[i].TxHash
			rs[i].Logs[j].TxIndex = uint(i)
			rs[i].Logs[j].Index = logIndex
			logIndex++
		}
	}
	return nil
}

// DeriveFields fills the receipts with their computed fields based on consensus
// data and contextual infos like containing block and transactions.
func (rs Receipts) DeriveFields(config *params.ChainConfig, hash common.Hash, number uint64, txs Transactions) error {
	signer := MakeSigner(config, new(big.Int).SetUint64(number))

	logIndex := uint(0)
	if len(txs) != len(rs) {
		return fmt.Errorf("transaction and receipt count mismatch, %d vs %d", len(txs), len(rs))
	}
	for i := 0; i < len(rs); i++ {
		// The transaction type and hash can be retrieved from the transaction itself
		rs[i].Type = txs[i].Type()
		rs[i].TxHash = txs[i].Hash()

		// block location fields
		rs[i].BlockHash = hash
		rs[i].BlockNumber = new(big.Int).SetUint64(number)
		rs[i].TransactionIndex = uint(i)

		// The contract address can be derived from the transaction itself
		if txs[i].To() == nil {
			// Deriving the signer is expensive, only do if it's actually needed
			from, _ := Sender(signer, txs[i])
			rs[i].ContractAddress = crypto.CreateAddress(from, txs[i].Nonce())
		}
		// The used gas can be calculated based on previous r
		if i == 0 {
			rs[i].GasUsed = rs[i].CumulativeGasUsed
		} else {
			rs[i].GasUsed = rs[i].CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}
		// The derived log fields can simply be set from the block and transaction
		for j := 0; j < len(rs[i].Logs); j++ {
			rs[i].Logs[j].BlockNumber = number
			rs[i].Logs[j].BlockHash = hash
			rs[i].Logs[j].TxHash = rs[i].TxHash
			rs[i].Logs[j].TxIndex = uint(i)
			rs[i].Logs[j].Index = logIndex
			logIndex++
		}
	}
	return nil
}
