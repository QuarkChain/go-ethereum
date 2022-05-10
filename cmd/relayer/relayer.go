package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const (
	ABI                    = `[{"inputs": [],"name": "getNextEpochHeight","outputs": [{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "bytes","name": "_epochHeaderBytes","type": "bytes"},{"internalType": "bytes","name": "commitBytes","type": "bytes"}],"name": "submitHead","outputs": [],"stateMutability": "nonpayable","type": "function"}]`
	SubmitHeaderFunc       = "submitHead"
	GetNextEpochHeightFunc = "getNextEpochHeight"
	gas                    = uint64(math.MaxUint64 / 2)
	comfirmCount           = 50 // 10 * 60 / 12
)

var (
	ethRpc      *string
	contractStr *string
	web3qRpc    *string
	valKeyPath  *string
	verbosity   *int
	ethCli      *ethclient.Client
	web3qCli    *ethclient.Client
	contract    common.Address
	rootCtx     context.Context
)

var RelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Run the relay server",
	Run:   runRelay,
}

func init() {
	ethRpc = RelayCmd.Flags().String("ethRpc", "", "rpc for relayer to submit header")
	contractStr = RelayCmd.Flags().String("contract", "", "the contract for relayer to submit header to")
	web3qRpc = RelayCmd.Flags().String("web3qRpc", "", "rpc for relayer to get web3q header")

	valKeyPath = RelayCmd.Flags().String("valKey", "", "Path to validator key (empty if not a validator)")
	verbosity = RelayCmd.Flags().Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail")
}

func runRelay(cmd *cobra.Command, args []string) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
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

	// Node's main lifecycle context.
	rootCtx, rootCtxCancel := context.WithCancel(context.Background())
	defer rootCtxCancel()

	if *ethRpc == "" {
		log.Error("Please specify --ethRpc")
		return
	}

	var err error
	ethCli, err = ethclient.Dial(*ethRpc)
	if err != nil {
		log.Error("Failed to dial eth rpc", "err", err)
		return
	}

	ethChainId, err := ethCli.ChainID(rootCtx)
	if err != nil {
		log.Error("Failed to get eth chainId", "err", err)
		return
	}

	if *contractStr == "" {
		log.Error("Please specify --contract")
		return
	}
	contract = common.HexToAddress(*contractStr)

	if *web3qRpc == "" {
		log.Error("Please specify --web3qRpc")
		return
	}

	web3qCli, err = ethclient.Dial(*web3qRpc)
	if err != nil {
		log.Error("Failed to dial web3q rpc", "err", err)
		return
	}

	cid, err := web3qCli.ChainID(rootCtx)
	if err != nil {
		log.Error("Failed to dial web3q rpc", "err", err)
		return
	}
	log.Info("web3q chain id", "chainid", cid)

	if *valKeyPath == "" {
		log.Error("Please specify --valKeyPath")
		return
	}

	valKey, err := loadValidatorKey(*valKeyPath)
	if err != nil {
		log.Error("Failed to load validator key", "err", err)
		return
	}

	vABI, _ := abi.JSON(strings.NewReader(ABI))

	relayer := relayer{
		ethClient:   ethCli,
		web3qClient: web3qCli,
		signer:      types.NewEIP2930Signer(ethChainId),
		privKey:     valKey,
		contract:    contract,
		valABI:      vABI,
		ctx:         rootCtx,
	}

	// loop
	// 0. get eth chain current height
	// 1. get web3q next epoch header from eth chain contract
	// 2. get fetch epoch header from web3q chain
	// 3. submit web3q header to eth chain if required header exist, otherwise sleep 5 minutes
	go func() {
		log.Info("start loop")
		i := 0
		for true {
			log.Info("round", "i", i)
			i++
			var (
				header      *types.Header
				blockNumber uint64
			)
			curNumber, err := relayer.ethClient.BlockNumber(relayer.ctx)
			if err != nil {
				log.Error("get ethClient block number failed", "err", err.Error())
				goto sleep
			}

			blockNumber, err = relayer.GetNextEpochHeight(curNumber - comfirmCount)
			if err != nil {
				log.Error("GetNextEpochHeight failed", "err", err.Error())
				goto sleep
			}

			if blockNumber == 0 {
				goto sleep
			}

			header, err = relayer.web3qClient.HeaderByNumber(relayer.ctx, new(big.Int).SetUint64(blockNumber))
			if err != nil {
				log.Error("FetchWeb3qHeader failed", "err", err.Error())
				goto sleep
			}

			if header == nil {
				goto sleep
			}

			err = relayer.SubmitHeaderToContract(header)
			if err == nil {
				time.Sleep(10 * time.Second)
				continue
			}
			log.Error("SubmitHeaderToContract failed", "err", err.Error())

		sleep:
			time.Sleep(5 * time.Minute)
		}
	}()

	<-rootCtx.Done()
}

// loadValidatorKey loads a serialized guardian key from disk.
func loadValidatorKey(filename string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	gk, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize raw key data: %w", err)
	}

	return gk, nil
}

type relayer struct {
	ethClient   *ethclient.Client
	web3qClient *ethclient.Client
	signer      types.Signer
	contract    common.Address
	privKey     *ecdsa.PrivateKey
	ctx         context.Context
	valABI      abi.ABI
}

func (r *relayer) SubmitHeaderToContract(header *types.Header) error {
	cph := types.CopyHeader(header)
	cph.Commit = nil
	eHeader, err := rlp.EncodeToBytes(cph)
	if err != nil {
		return err
	}

	eCommit, err := rlp.EncodeToBytes(header.Commit)
	if err != nil {
		return err
	}

	data, err := r.valABI.Pack(SubmitHeaderFunc, eHeader, eCommit)
	if err != nil {
		return err
	}

	gasPrice, err := r.ethClient.SuggestGasPrice(r.ctx)
	if err != nil {
		return err
	}

	nonce, err := r.ethClient.PendingNonceAt(r.ctx, crypto.PubkeyToAddress(r.privKey.PublicKey))
	if err != nil {
		return err
	}

	baseTx := &types.LegacyTx{
		To:       &contract,
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		Value:    new(big.Int).SetInt64(0),
		Data:     data,
	}

	signedTx, err := types.SignTx(types.NewTx(baseTx), r.signer, r.privKey)
	if err != nil {
		return err
	}

	return ethCli.SendTransaction(r.ctx, signedTx)
}

func (r *relayer) GetNextEpochHeight(blockNumber uint64) (uint64, error) {
	data, err := r.valABI.Pack(GetNextEpochHeightFunc)
	if err != nil {
		return 0, err
	}

	msgData := (hexutil.Bytes)(data)
	msg := ethereum.CallMsg{
		To:   &r.contract,
		Gas:  gas,
		Data: msgData,
	}
	result, err := r.ethClient.CallContract(r.ctx, msg, new(big.Int).SetUint64(blockNumber))
	if err != nil {
		return 0, err
	}

	type t struct {
		Value *big.Int
	}

	var rh t

	//	var rh = new(big.Int).SetInt64(0)

	if err := r.valABI.UnpackIntoInterface(&rh, GetNextEpochHeightFunc, result); err != nil {
		return 0, err
	}

	return rh.Value.Uint64(), nil
}
