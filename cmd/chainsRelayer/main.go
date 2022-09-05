package main

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/config"
	"github.com/ethereum/go-ethereum/cmd/chainsRelayer/relayer"
	"strings"
	"sync"
)

//const rinkebyRpcUrl = "https://rinkeby.infura.io/v3/4e3e18f80d8d4ad5959b7404e85e0143"
//const rinkebyRpcWsUrl = "wss://rinkeby.infura.io/ws/v3/4e3e18f80d8d4ad5959b7404e85e0143"
//
//var w3qERC20Addr = common.HexToAddress("0x7EA6206543bB4E1EC251061Dd346b5D96DacB4Ed")
//var LightClientAddr = common.HexToAddress("0xF2C3BcFB4873f2BcA6fC5622612a5521fF788272")
//
//const web3QRPCUrl = "http://127.0.0.1:8545"
//const web3QWSUrl = "ws://127.0.0.1:8546"
//const web3QValKetStoreFilePath = "/Users/chenyanlong/Work/go-ethereum/cmd/geth/data_val_0/keystore/UTC--2022-06-07T04-15-42.696295000Z--96f22a48dcd4dfb99a11560b24bee02f374ca77d"
//const passwd = "123"
//
//var w3qNativeContractAddr = common.HexToAddress("0x0000000000000000000000000000000003330002")

func main() {
	// initialize rinkeby chainOperator
	//relayerIn, err := relayer.NewRelayerByKeyStore(web3QValKetStoreFilePath, passwd)
	relayerIn, err := relayer.NewRelayer(config.Config().Ethereum)
	if err != nil {
		panic(err)
	}
	rinkebyOperator, err := relayer.NewChainOperator(config.Config().Ethereum, relayerIn, context.Background())
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

	rinkebyOperator.RegisterContract(config.Config().Contract.W3qERC20Contract, json)
	rinkebyOperator.RegisterContract(config.Config().Contract.LightClientContract, lightClientJson)

	// initialize web3q chainOperator
	//web3qRelayer, err := relayer.NewRelayerByKeyStore(web3QValKetStoreFilePath, passwd)
	web3qRelayer, err := relayer.NewRelayer(config.Config().Web3q)
	if err != nil {
		panic(err)
	}
	//web3QConfig := relayer.NewChainConfig(web3QRPCUrl, web3QWSUrl, 3, "/Users/chenyanlong/Work/go-ethereum/cmd/chainsRelayer/db_data/web3qOperator")
	web3QOperator, err := relayer.NewChainOperator(config.Config().Web3q, web3qRelayer, context.Background())
	if err != nil {
		panic(err)
	}
	web3qNativeJson, err := abi.JSON(strings.NewReader(relayer.W3qNativeTestABI))
	if err != nil {
		panic(err)
	}
	web3QOperator.RegisterContract(config.Config().Contract.W3qNativeContract, web3qNativeJson)

	// ==================rinkebyChainOperator_Listen_Task================
	mintTaskIndex, err := rinkebyOperator.SubscribeEvent(config.Config().Contract.W3qERC20Contract, "mintToken", nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("mintTaskIndex:", mintTaskIndex)

	burnTaskIndex, err := rinkebyOperator.SubscribeEvent(config.Config().Contract.W3qERC20Contract, "burnToken", web3QOperator.SendMintNativeTx(config.Config().Contract.W3qNativeContract, rinkebyOperator))
	if err != nil {
		panic(err)
	}
	fmt.Println("burnTaskIndex:", burnTaskIndex)

	//=================web3QChainOperatorListen Task====================
	task, err := relayer.CreateListeningW3qLatestBlockTask(web3QOperator, rinkebyOperator, config.Config().Contract.LightClientContract, config.Config().Contract.W3qNativeContract, config.Config().Contract.W3qERC20Contract, web3QOperator.Ctx)
	if err != nil {
		panic(err)
	}
	submitHeaderIndex := web3QOperator.InsertListenTask(task)
	fmt.Println("submitHeaderIndex:", submitHeaderIndex)

	//web3qChainOperator subscribe events
	//w3qBurnIndex, err := web3QOperator.SubscribeEvent(w3qNativeContractAddr, "burnNativeToken", web3QOperator.SendMintW3qErc20TxAndSubmitHeadTx(w3qERC20Addr, rinkebyOperator, LightClientAddr))
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("w3qBurnIndex:", w3qBurnIndex)

	var pwg sync.WaitGroup
	pwg.Add(1)
	go func() {
		web3QOperator.StartSubmitting()
		defer pwg.Done()
	}()
	pwg.Add(1)
	go func() {
		rinkebyOperator.StartSubmitting()
		defer pwg.Done()
	}()
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
