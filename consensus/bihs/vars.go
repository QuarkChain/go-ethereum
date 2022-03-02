package bihs

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
)

var (
	errUnknownBlock                    = errors.New("unknown block")
	errInvalidNonce                    = errors.New("invalid nonce")
	errInvalidDigest                   = errors.New("invalid digest")
	errInvalidTime                     = errors.New("invalid time")
	errInvalidUncleHash                = errors.New("invalid uncleHash")
	errInvalidDifficulty               = errors.New("invalid difficulty")
	errUnclesNotAllowed                = errors.New("uncles not allowed")
	errInvalidGasLimitForEmptyBlock    = errors.New("invalid gas limit for empty block")
	errInvalidTimeForEmptyBlock        = errors.New("invalid time for empty block")
	errInvalidRootForEmptyBlock        = errors.New("invalid root for empty block")
	errInvalidTxHashForEmptyBlock      = errors.New("invalid txhash for empty block")
	errInvalidReceiptHashForEmptyBlock = errors.New("invalid receipt hash for empty block")
)

var (
	defaultDifficulty = big.NewInt(1)
	deltaSeconds      = int64(5)
	defaultNonce      = types.BlockNonce{}
)
