package config

import (
	"bufio"
	"github.com/ethereum/go-ethereum/common"
	toml "github.com/pelletier/go-toml/v2"
	"math/big"
	"os"
	"sync"
)

var (
	cfg  *TomlConfig
	once sync.Once
)

type TomlConfig struct {
	Title    string
	Web3q    ChainConfig
	Ethereum ChainConfig
	Contract ContractConfig
	Log      LogConfig
}

type ChainConfig struct {
	chainId          int64
	KeyStoreFilePath string
	Passwd           string
	RpcUrl           string
	WsUrl            string
	BlockTime        uint
	DbFile           string
}

func (this *ChainConfig) ChainId() int64 {
	return this.chainId
}

func (this *ChainConfig) SetChainId(cid *big.Int) {
	this.chainId = cid.Int64()
}

type ContractConfig struct {
	W3qNativeContract   common.Address
	LightClientContract common.Address
	W3qERC20Contract    common.Address
}

type LogConfig struct {
	LogFile  string
	LogLevel int
	UseColor bool
}

func Config() *TomlConfig {
	once.Do(initConfig)
	return cfg
}

func initConfig() {
	file, err := os.Open("/Users/chenyanlong/Work/go-ethereum/cmd/chainsRelayer/config/conf.toml")
	if err != nil {
		panic(err)
	}

	decoder := toml.NewDecoder(bufio.NewReader(file))
	err = decoder.Decode(&cfg)
	if err != nil {
		panic(err)
	}
}
