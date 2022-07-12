package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var (
	prefix       = []byte("HeaderNumber")
	ctx          = context.Background()
	state        = make(map[common.Address]uint32)
	validatorSet []common.Address
	client       *ethclient.Client

	rpc           *string
	startEpochIdx *uint64
	endEpochIdx   *uint64
	epoch         *uint64
	verbosity     *int
)

var CheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run the check proposed block state server",
	Run:   runCheckProposedState,
}

func init() {
	rpc = CheckCmd.Flags().String("rpc", "", "rpc to get web3q block")
	startEpochIdx = CheckCmd.Flags().Uint64("startEpoch", 0, "epoch start to check proposed block state")
	endEpochIdx = CheckCmd.Flags().Uint64("endEpoch", 60, "epoch end to check proposed block state")
	epoch = CheckCmd.Flags().Uint64("epoch", 1000, "epoch length to vote new validator")
	verbosity = CheckCmd.Flags().Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail")
}

func runCheckProposedState(cmd *cobra.Command, args []string) {
	setLog(*verbosity)

	if *rpc == "" {
		log.Error("Please specify --rpc")
		return
	}

	var err error
	client, err = ethclient.Dial(*rpc)
	if err != nil {
		log.Error("Failed to dial rpc", "err", err)
		return
	}

	startBlock := *startEpochIdx * *epoch
	endBlock := (*endEpochIdx + 1) * *epoch

	initBlock, err := client.BlockByNumber(ctx, new(big.Int).SetUint64(startBlock))
	if err != nil {
		log.Error(err.Error())
		return
	}
	validatorSet = initBlock.NextValidators()

	for i := startBlock; i < endBlock; i++ {
		block, err := client.BlockByNumber(ctx, new(big.Int).SetUint64(i))
		if err != nil {
			log.Error(err.Error())
			return
		}

		if i > startBlock && i%*epoch == 0 {
			err = verifyState(block)
			if err != nil {
				log.Error(err.Error())
				return
			}

			log.Info("Proposed state", "epoch", i / *epoch - 1, "state", state)
			state = make(map[common.Address]uint32)
		}

		updateState(block.Coinbase())
	}
}

func setLog(verbosity int) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(verbosity))
	log.Root().SetHandler(glogger)

	// setup logger
	var ostream log.Handler
	output := io.Writer(os.Stderr)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))
	glogger.SetHandler(ostream)
}

func verifyState(block *types.Block) error {
	extraData := block.Extra()
	l := len(prefix)
	if len(extraData) > l && bytes.Compare(prefix, extraData[:l]) == 0 {
		extraData = extraData[l+8+32:]
	}
	rs := make([]uint32, 0)
	rlp.DecodeBytes(extraData, &rs)
	for i, addr := range validatorSet {
		if state[addr] != rs[i] {
			return fmt.Errorf("address %s; state %d; block state: %d", common.Bytes2Hex(addr.Bytes()), state[addr], rs[i])
		}
	}

	log.Info("verify state pass", "epoch", block.Number().Uint64() / *epoch - 1)
	validatorSet = block.Header().NextValidators
	return nil
}

func updateState(coinbase common.Address) {
	if _, ok := state[coinbase]; !ok {
		state[coinbase] = uint32(0)
	}

	state[coinbase] = state[coinbase] + 1
}
