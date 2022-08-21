package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/relayer"
	"github.com/ethereum/go-ethereum/common"
	"strings"
	"sync"
)

const cabi = "[\n\t{\n\t\t\"inputs\": [],\n\t\t\"name\": \"happen\",\n\t\t\"outputs\": [],\n\t\t\"stateMutability\": \"nonpayable\",\n\t\t\"type\": \"function\"\n\t},\n\t{\n\t\t\"anonymous\": false,\n\t\t\"inputs\": [\n\t\t\t{\n\t\t\t\t\"indexed\": true,\n\t\t\t\t\"internalType\": \"address\",\n\t\t\t\t\"name\": \"addr\",\n\t\t\t\t\"type\": \"address\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"indexed\": false,\n\t\t\t\t\"internalType\": \"uint256\",\n\t\t\t\t\"name\": \"value\",\n\t\t\t\t\"type\": \"uint256\"\n\t\t\t}\n\t\t],\n\t\t\"name\": \"myemit\",\n\t\t\"type\": \"event\"\n\t},\n\t{\n\t\t\"inputs\": [],\n\t\t\"name\": \"value\",\n\t\t\"outputs\": [\n\t\t\t{\n\t\t\t\t\"internalType\": \"uint256\",\n\t\t\t\t\"name\": \"\",\n\t\t\t\t\"type\": \"uint256\"\n\t\t\t}\n\t\t],\n\t\t\"stateMutability\": \"view\",\n\t\t\"type\": \"function\"\n\t}\n]"

const rinkebyRpcUrl = "https://rinkeby.infura.io/v3/4e3e18f80d8d4ad5959b7404e85e0143"
const rinkebyRpcWsUrl = "wss://rinkeby.infura.io/ws/v3/4e3e18f80d8d4ad5959b7404e85e0143"

var w3qERC20Addr = common.HexToAddress("0x5Af53d5a4282AC2e0B0e9eF55e20327C8E5d584f")
var LightClientAddr = common.HexToAddress("0x04A31f431c3d284C433F5E71bB2f2082B754422C")

const web3QRPCUrl = "http://127.0.0.1:8545"
const web3QWSUrl = "ws://127.0.0.1:8546"
const web3QValKetStoreFilePath = "/Users/chenyanlong/Work/go-ethereum/cmd/geth/data_val_0/keystore/UTC--2022-06-07T04-15-42.696295000Z--96f22a48dcd4dfb99a11560b24bee02f374ca77d"
const passwd = "123"

var w3qNativeContractAddr = common.HexToAddress("0x0000000000000000000000000000000003330002")

func main() {
	// initialize rinkeby chainOperator
	rinkebyConfig := relayer.NewChainConfig(rinkebyRpcUrl, rinkebyRpcWsUrl, 5, "/Users/chenyanlong/Work/go-ethereum/cmd/chainsRelayer/db_data/ethOperator")
	relayerIn, err := relayer.NewRelayerByKeyStore(web3QValKetStoreFilePath, passwd)
	if err != nil {
		panic(err)
	}
	rinkebyOperator, err := relayer.NewChainOperator(rinkebyConfig, relayerIn, context.Background())
	if err != nil {
		panic(err)
	}

	json, err := abi.JSON(strings.NewReader(relayer.W3qERC20ABI))
	if err != nil {
		panic(err)
	}

	lightClientJson, err := abi.JSON(strings.NewReader(relayer.ILightClientABI))
	if err != nil {
		panic(err)
	}
	rinkebyOperator.RegisterContract(w3qERC20Addr, json)
	rinkebyOperator.RegisterContract(LightClientAddr, lightClientJson)

	// initialize web3q chainOperator
	web3qRelayer, err := relayer.NewRelayerByKeyStore(web3QValKetStoreFilePath, passwd)
	if err != nil {
		panic(err)
	}
	web3QConfig := relayer.NewChainConfig(web3QRPCUrl, web3QWSUrl, 3, "/Users/chenyanlong/Work/go-ethereum/cmd/chainsRelayer/db_data/web3qOperator")
	web3QOperator, err := relayer.NewChainOperator(web3QConfig, web3qRelayer, context.Background())
	if err != nil {
		panic(err)
	}
	web3qNativeJson, err := abi.JSON(strings.NewReader(relayer.W3qNativeTestABI))
	if err != nil {
		panic(err)
	}
	ILightClientJson, err := abi.JSON(strings.NewReader(relayer.ILightClientABI))
	if err != nil {
		panic(err)
	}
	web3QOperator.RegisterContract(w3qNativeContractAddr, web3qNativeJson)
	web3QOperator.RegisterContract(LightClientAddr, ILightClientJson)

	// ==================rinkebyChainOperator_Listen_Task================
	//mintTaskIndex, err := rinkebyOperator.SubscribeEvent(w3qERC20Addr, "mintToken", nil)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("mintTaskIndex:", mintTaskIndex)
	//
	//burnTaskIndex, err := rinkebyOperator.SubscribeEvent(w3qERC20Addr, "burnToken", web3QOperator.SendMintNativeTx(w3qNativeContractAddr, rinkebyOperator))
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("burnTaskIndex:", burnTaskIndex)

	//=================web3QChainOperatorListen Task====================
	//task, err := relayer.CreateListeningW3qLatestBlockTask(web3QOperator, rinkebyOperator, LightClientAddr, web3QOperator.Ctx)
	//if err != nil {
	//	panic(err)
	//}
	//submitHeaderIndex := web3QOperator.AddListenTask(task)
	//fmt.Println("submitHeaderIndex:", submitHeaderIndex)

	//web3qChainOperator subscribe events
	w3qBurnIndex, err := web3QOperator.SubscribeEvent(w3qNativeContractAddr, "burnNativeToken", web3QOperator.SendMintW3qErc20TxAndSubmitHeadTx(w3qERC20Addr, rinkebyOperator, LightClientAddr))
	if err != nil {
		panic(err)
	}
	fmt.Println("w3qBurnIndex:", w3qBurnIndex)

	var pwg sync.WaitGroup
	pwg.Add(1)
	go func() {
		rinkebyOperator.StartListening()
		defer pwg.Done()
	}()
	pwg.Add(1)
	go func() {
		web3QOperator.StartListening()
		defer pwg.Done()
	}()
	pwg.Wait()
}
