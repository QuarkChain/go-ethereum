package tests

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"log"
	"math/big"
	"strings"
	"testing"
)

func newMuskBlockChainForExternalCall() (*types.Receipt, *WrapClient, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	chainId := big.NewInt(1337)
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainId)

	balance := new(big.Int)
	balance.SetString("100000000000000000000", 10) // 100 eth in wei

	triggerEventContract := common.HexToAddress("0000000000000000000000000000000000000aaa")
	address := auth.From
	genesisAlloc := map[common.Address]core.GenesisAccount{
		address: {
			Balance: balance,
		},
		triggerEventContract: {
			Balance: balance,
			Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100575760003560e01c8063209652551461005c578063552410771461007a57806381045ead146100965780638ff2dc7e146100b4578063a1611e0e146100be575b600080fd5b6100646100da565b604051610071919061037b565b60405180910390f35b610094600480360381019061008f9190610288565b6100e3565b005b61009e61011a565b6040516100ab919061037b565b60405180910390f35b6100bc610123565b005b6100d860048036038101906100d391906102b5565b610151565b005b60008054905090565b807f44166b8e7efa954701ff28cba73852e3bbb791ac94a02de05fba64d11492fe9f60405160405180910390a28060008190555050565b60008054905090565b7f8e397a038a34466ac8069165f69d2f28bde665accf96372b7e665ee069dd00d260405160405180910390a1565b6002600081819054906101000a900467ffffffffffffffff1680929190610177906104d7565b91906101000a81548167ffffffffffffffff021916908367ffffffffffffffff16021790555050827fdce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca983600260009054906101000a900467ffffffffffffffff16846040516101e893929190610396565b60405180910390a28160008190555082600181905550505050565b6000610216610211846103f9565b6103d4565b9050828152602081018484840111156102325761023161056b565b5b61023d848285610464565b509392505050565b600082601f83011261025a57610259610566565b5b813561026a848260208601610203565b91505092915050565b6000813590506102828161058b565b92915050565b60006020828403121561029e5761029d610575565b5b60006102ac84828501610273565b91505092915050565b6000806000606084860312156102ce576102cd610575565b5b60006102dc86828701610273565b93505060206102ed86828701610273565b925050604084013567ffffffffffffffff81111561030e5761030d610570565b5b61031a86828701610245565b9150509250925092565b600061032f8261042a565b6103398185610435565b9350610349818560208601610473565b6103528161057a565b840191505092915050565b61036681610446565b82525050565b61037581610450565b82525050565b6000602082019050610390600083018461035d565b92915050565b60006060820190506103ab600083018661035d565b6103b8602083018561036c565b81810360408301526103ca8184610324565b9050949350505050565b60006103de6103ef565b90506103ea82826104a6565b919050565b6000604051905090565b600067ffffffffffffffff82111561041457610413610537565b5b61041d8261057a565b9050602081019050919050565b600081519050919050565b600082825260208201905092915050565b6000819050919050565b600067ffffffffffffffff82169050919050565b82818337600083830152505050565b60005b83811015610491578082015181840152602081019050610476565b838111156104a0576000848401525b50505050565b6104af8261057a565b810181811067ffffffffffffffff821117156104ce576104cd610537565b5b80604052505050565b60006104e282610450565b915067ffffffffffffffff8214156104fd576104fc610508565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b61059481610446565b811461059f57600080fd5b5056fea26469706673582212205a08eea3634f7d27082237722f79299192f3e5c5cd229afea0339c3943dfa0bf64736f6c63430008070033"),
		},
	}

	blockGasLimit := uint64(50000000)
	client := backends.NewSimulatedBackend(genesisAlloc, blockGasLimit)

	actualChainId := client.Blockchain().Config().ChainID
	if actualChainId.Cmp(chainId) != 0 {
		panic("chainId no match")
	}

	// 1. Deploy a contract with events that can be triggered by calling methods
	ctx := context.Background()
	nonce, err := client.PendingNonceAt(ctx, auth.From)
	if err != nil {
		panic(err)
	}

	// 2. Call method by sendTransaction to trigger event
	triggerEventTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   actualChainId,
		To:        &triggerEventContract,
		Nonce:     nonce,
		Data:      common.FromHex("0xa1611e0e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000010aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb00000000000000000000000000000000"),
		GasFeeCap: big.NewInt(7000000000),
		GasTipCap: big.NewInt(1000000000),
		Gas:       800000,
	})

	triggerEventTxSigned, err := types.SignTx(triggerEventTx, types.MakeSigner(client.Blockchain().Config(), big.NewInt(0)), privateKey)
	if err != nil {
		panic(err)
	}

	err = client.SendTransaction(ctx, triggerEventTxSigned)
	if err != nil {
		panic(err)
	}

	client.Commit()
	receipt, err := client.TransactionReceipt(ctx, triggerEventTxSigned.Hash())
	if err != nil {
		panic(err)
	}

	return receipt, NewWrapClient(client), nil

}

type WrapTendermint struct {
	*clique.Clique
	Client vm.ExternalCallClient
}

func NewWrapTendermint(cli *clique.Clique, client *ethclient.Client) *WrapTendermint {
	return &WrapTendermint{Clique: cli, Client: client}
}

type TestChainContext struct {
	tm consensus.Engine
}

func NewTestChainContext(tm consensus.Engine) *TestChainContext {
	return &TestChainContext{tm: tm}
}

func (ctx *TestChainContext) Engine() consensus.Engine {
	return ctx.tm
}

func (ctx *TestChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

type WrapTx struct {
	Tx             *types.Transaction
	GasUsed        uint64
	Args           *CrossChainCallArgment
	ExpectTxData   func() ([]byte, error)
	ExpectTraces   []*ExpectTrace
	ExpectCCRBytes []byte
	happenError    error
	Index          int
}

func (wt *WrapTx) SetExternalCallRes(crossChainCallRes []byte) {
	wt.ExpectCCRBytes = crossChainCallRes
}

func (wt *WrapTx) SetUnexpectErr(err error) {
	wt.happenError = err
}

func (wt *WrapTx) MarkTransitionIndex() string {
	return fmt.Sprintf("[Transaction Index %d]", wt.Index)
}

func NewWrapTx(tx *types.Transaction, args *CrossChainCallArgment) *WrapTx {
	return &WrapTx{Tx: tx, Args: args}
}

func (wt *WrapTx) VerifyCallResult(crossCallResult []byte, happenedError error, t *testing.T) {
	if happenedError != nil {
		if wt.happenError == nil {
			t.Fatal("happened err:", happenedError)
			return
		}

		if happenedError.Error() != wt.happenError.Error() {
			t.Fatal("\nexpect happen err:", wt.happenError, "\nactual happen err:", happenedError)
		} else {
			t.Log("expect happen err match:", happenedError.Error())
		}
		happenedError = nil
		return
	}

	tracesWithVersion := &vm.CrossChainCallResultsWithVersion{}
	err := rlp.DecodeBytes(crossCallResult, tracesWithVersion)
	if err != nil {
		t.Fatal(err)
	}

	actualTraces := tracesWithVersion.Results

	if len(wt.ExpectTraces) != len(actualTraces) {
		t.Fatalf("wrapTx.ExpectTraces length [%d] no match actualTraces length [%d]", len(wt.ExpectTraces), len(actualTraces))
	}

	for i, v := range actualTraces {
		cs := v.CallRes
		wt.ExpectTraces[i].verifyRes(cs, t, i, v.Success)
	}

}

type ExpectTrace struct {
	CallResultBytes []byte // call result
	ExpectErrBytes  error
	success         bool
	UnExpectErr     error
}

func NewExpectTrace(callResultBytes []byte, expectErrBytes error, unExpectErr error) *ExpectTrace {
	return &ExpectTrace{CallResultBytes: callResultBytes, ExpectErrBytes: expectErrBytes, UnExpectErr: unExpectErr}
}

func (et *ExpectTrace) compareRes(cs []byte) bool {
	return bytes.Equal(et.CallResultBytes, cs)
}

func (et *ExpectTrace) verifyRes(cs []byte, t *testing.T, traceIndex int, success bool) {

	if success != true {
		t.Error("the trace.Success should be true when execute succeed")
	}
	if bytes.Equal(et.CallResultBytes, cs) {
		t.Logf("[TraceIndex %d] res match!!! \ncall_result{%s} ", traceIndex, common.Bytes2Hex(et.CallResultBytes))
	} else {
		t.Errorf("[TraceIndex %d] res no match ,expect : %s, actual: %s", traceIndex, common.Bytes2Hex(et.CallResultBytes), common.Bytes2Hex(cs))
	}

}

type CrossChainCallArgment struct {
	ChainId     uint64
	TxHash      common.Hash
	LogIdx      uint64
	MaxDataLen  uint64
	Confirms    uint64
	contractAbi abi.ABI
	env         *vm.PrecompiledContractCallEnv
}

const CrossChainCallContract = `
[
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callOnce",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "chainId",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "txHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "logIdx",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "maxDataLen",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "confirms",
				"type": "uint256"
			}
		],
		"name": "callTwice",
		"outputs": [
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			},
			{
				"internalType": "bytes",
				"name": "",
				"type": "bytes"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "crossChainCallContract",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]`

func NewCrossChainCallArgment(chainconfig *params.ChainConfig, client vm.ExternalCallClient, chainId uint64, txHash common.Hash, logIdx uint64, maxDataLen uint64, confirms uint64) *CrossChainCallArgment {
	evmConfig := vm.Config{ExternalCallClient: client}
	evm := vm.NewEVM(vm.BlockContext{}, vm.TxContext{}, nil, chainconfig, evmConfig)
	env := vm.NewPrecompiledContractCallEnv(evm, nil)
	abi, err := abi.JSON(strings.NewReader(CrossChainCallContract))
	if err != nil {
		panic(err)
	}
	return &CrossChainCallArgment{ChainId: chainId, TxHash: txHash, LogIdx: logIdx, MaxDataLen: maxDataLen, Confirms: confirms, contractAbi: abi, env: env}
}

func (c *CrossChainCallArgment) CallOncePack() ([]byte, error) {
	return c.contractAbi.Pack("callOnce", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
}

func (c *CrossChainCallArgment) CallTwicePack() ([]byte, error) {
	return c.contractAbi.Pack("callTwice", big.NewInt(int64(c.ChainId)), c.TxHash, big.NewInt(int64(c.LogIdx)), big.NewInt(int64(c.MaxDataLen)), big.NewInt(int64(c.Confirms)))
}

func (c *CrossChainCallArgment) CrossChainCallResult() (*vm.GetLogByTxHash, *vm.ExpectCallErr, error) {
	return vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
}

func (c *CrossChainCallArgment) CrossChainCallResultToExpectCallResult() *ExpectTrace {
	cs, expErr, unExpErr := vm.GetExternalLog(context.Background(), c.env, c.ChainId, c.TxHash, c.LogIdx, c.MaxDataLen, c.Confirms)
	if unExpErr != nil {
		return NewExpectTrace(nil, nil, unExpErr)
	} else if expErr != nil {
		return NewExpectTrace(nil, expErr, nil)
	} else {
		pack, err := cs.ABIPack()
		if err != nil {
			panic(err)
		}
		return NewExpectTrace(pack, nil, nil)
	}
}

func TestApplyTransactionForTest(t *testing.T) {
	rec, externalClient, err := newMuskBlockChainForExternalCall()
	if err != nil {
		t.Error(err)
	}

	chainID, err := externalClient.ChainID(context.Background())
	if err != nil {
		t.Error(err)
	}

	var externalChainTxHash = rec.TxHash
	const externalChainTxNotFound = "0x0000000000000000000000000000000000000000000000000000000000000001"

	var (
		config = &params.ChainConfig{
			ChainID:             big.NewInt(3334),
			HomesteadBlock:      big.NewInt(0),
			DAOForkBlock:        nil,
			DAOForkSupport:      true,
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			MuirGlacierBlock:    nil,
			BerlinBlock:         big.NewInt(0),
			LondonBlock:         big.NewInt(0),
			PisaBlock:           big.NewInt(0),
			ArrowGlacierBlock:   nil,
			ExternalCall: &params.ExternalCallConfig{
				EnableBlockNumber: big.NewInt(0),
				Version:           1,
				SupportChainId:    chainID.Uint64(),
			},
		}
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
	)

	var (
		db = rawdb.NewMemoryDatabase()
		//preAddr      = common.HexToAddress("0x0000000000000000000000000000000000033303")
		contractAddr = common.HexToAddress("0xa000000000000000000000000000000000000aaa")
		gspec        = &core.Genesis{
			Config: config,
			Alloc: core.GenesisAlloc{
				addr1: core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   0,
				},
				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
				},
				contractAddr: core.GenesisAccount{
					Balance: big.NewInt(1000000000000000000), // 1 ether
					Nonce:   math.MaxUint64,
					Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100415760003560e01c80632061536214610046578063518a3510146100775780638c95e054146100a7575b600080fd5b610060600480360381019061005b9190610510565b6100c5565b60405161006e9291906106df565b60405180910390f35b610091600480360381019061008c9190610510565b610382565b60405161009e91906106bd565b60405180910390f35b6100af6104df565b6040516100bc91906106a2565b60405180910390f35b606080600087878787876040516024016100e3959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff168360405161018d919061068b565b6000604051808303816000865af19150503d80600081146101ca576040519150601f19603f3d011682016040523d82523d6000602084013e6101cf565b606091505b509150915081610214576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020b90610756565b60405180910390fd5b60008a8a60018b6102259190610801565b8a8a60405160240161023b959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff16836040516102e5919061068b565b6000604051808303816000865af19150503d8060008114610322576040519150601f19603f3d011682016040523d82523d6000602084013e610327565b606091505b50915091508161036c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036390610736565b60405180910390fd5b8381975097505050505050509550959350505050565b60606000868686868660405160240161039f959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff1683604051610449919061068b565b6000604051808303816000865af19150503d8060008114610486576040519150601f19603f3d011682016040523d82523d6000602084013e61048b565b606091505b5091509150816104d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c790610716565b60405180910390fd5b80935050505095945050505050565b6203330381565b6000813590506104f5816109dc565b92915050565b60008135905061050a816109f3565b92915050565b600080600080600060a0868803121561052c5761052b6108ff565b5b600061053a888289016104fb565b955050602061054b888289016104e6565b945050604061055c888289016104fb565b935050606061056d888289016104fb565b925050608061057e888289016104fb565b9150509295509295909350565b61059481610857565b82525050565b6105a381610869565b82525050565b60006105b4826107c9565b6105be81856107d4565b93506105ce81856020860161089d565b6105d781610904565b840191505092915050565b60006105ed826107c9565b6105f781856107e5565b935061060781856020860161089d565b80840191505092915050565b60006106206018836107f0565b915061062b82610915565b602082019050919050565b60006106436025836107f0565b915061064e8261093e565b604082019050919050565b60006106666025836107f0565b91506106718261098d565b604082019050919050565b61068581610893565b82525050565b600061069782846105e2565b915081905092915050565b60006020820190506106b7600083018461058b565b92915050565b600060208201905081810360008301526106d781846105a9565b905092915050565b600060408201905081810360008301526106f981856105a9565b9050818103602083015261070d81846105a9565b90509392505050565b6000602082019050818103600083015261072f81610613565b9050919050565b6000602082019050818103600083015261074f81610636565b9050919050565b6000602082019050818103600083015261076f81610659565b9050919050565b600060a08201905061078b600083018861067c565b610798602083018761059a565b6107a5604083018661067c565b6107b2606083018561067c565b6107bf608083018461067c565b9695505050505050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061080c82610893565b915061081783610893565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561084c5761084b6108d0565b5b828201905092915050565b600061086282610873565b9050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156108bb5780820151818401526020810190506108a0565b838111156108ca576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6109e581610869565b81146109f057600080fd5b50565b6109fc81610893565b8114610a0757600080fd5b5056fea2646970667358221220cb96efc14e55caf807c664755d68fa44a3228605b33e42bc7be92933e03ba95364736f6c63430008070033"),
				},
			},
		}

		globalchainId = config.ChainID
		genesis       = gspec.MustCommit(db)
	)

	argsForCallOnce := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), externalChainTxHash, 0, 300, 10)
	txdataForCallOnce, err := argsForCallOnce.CallOncePack()
	if err != nil {
		t.Error(err)
	}

	argsForExpectErrAsLogIdxExceed := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), externalChainTxHash, 5, 300, 10)
	txdataForExpectErrAsLogIdxExceed, err := argsForExpectErrAsLogIdxExceed.CallOncePack()
	if err != nil {
		t.Error(err)
	}
	argsForExpectErrAsNotFound := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), common.HexToHash(externalChainTxNotFound), 2, 300, 10)
	txdataForExpectErrAsNotFound, err := argsForExpectErrAsNotFound.CallOncePack()
	if err != nil {
		t.Error(err)
	}

	//trace0ForCallTwice := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), externalChainTxHash, 0, 300, 10)
	//trace1ForCallTwice := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), externalChainTxHash, 1, 300, 10)
	//
	//argsForCallTwice := NewCrossChainCallArgment(config, externalClient, chainID.Uint64(), externalChainTxHash, 0, 300, 10)
	//txdataForCallTwice, err := argsForCallTwice.CallTwicePack()
	//if err != nil {
	//	t.Error(err)
	//}

	argsForExpectErrChainIdNoSupport := NewCrossChainCallArgment(config, externalClient, 5, externalChainTxHash, 0, 300, 10)
	txdataForExpectErrChainIdNoSupport, err := argsForExpectErrChainIdNoSupport.CallOncePack()
	if err != nil {
		t.Error(err)
	}

	_wrapTxs := []*WrapTx{
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      txdataForCallOnce,
			}),
			Args: argsForCallOnce,
			ExpectTraces: []*ExpectTrace{
				argsForCallOnce.CrossChainCallResultToExpectCallResult(),
			},
		},
		// expect err match:CrossChainCall:logIdx out-of-bound
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      txdataForExpectErrAsLogIdxExceed,
			}),
			Args: argsForExpectErrAsLogIdxExceed,
			ExpectTraces: []*ExpectTrace{
				argsForExpectErrAsLogIdxExceed.CrossChainCallResultToExpectCallResult(),
			},
			happenError: vm.NewExpectCallErr("CrossChainCall:logIdx out-of-bound"),
		},
		// expect err txHash not found
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      txdataForExpectErrAsNotFound,
			}),
			Args: argsForExpectErrAsNotFound,
			ExpectTraces: []*ExpectTrace{
				argsForExpectErrAsNotFound.CrossChainCallResultToExpectCallResult(),
			},
			happenError: vm.NewExpectCallErr(ethereum.NotFound.Error()),
		},
		// expect err chainId no support
		&WrapTx{
			Tx: types.NewTx(&types.DynamicFeeTx{
				ChainID:   globalchainId,
				Nonce:     0,
				To:        &contractAddr,
				Value:     big.NewInt(0),
				Gas:       5000000,
				GasTipCap: big.NewInt(1000000000),
				GasFeeCap: big.NewInt(6000000000),
				Data:      txdataForExpectErrChainIdNoSupport,
			}),
			Args:         argsForExpectErrChainIdNoSupport,
			ExpectTxData: argsForExpectErrChainIdNoSupport.CallOncePack,
			happenError:  vm.NewExpectCallErr(fmt.Sprintf("CrossChainCall:chainId %d no support", argsForExpectErrChainIdNoSupport.ChainId)),
		},
		// external call twice
		//&WrapTx{
		//	Tx: types.NewTx(&types.DynamicFeeTx{
		//		ChainID:   globalchainId,
		//		Nonce:     0,
		//		To:        &contractAddr,
		//		Value:     big.NewInt(0),
		//		Gas:       5000000,
		//		GasTipCap: big.NewInt(1000000000),
		//		GasFeeCap: big.NewInt(6000000000),
		//		Data:      txdataForCallTwice,
		//	}),
		//	Args: argsForCallTwice,
		//	ExpectTraces: []*ExpectTrace{
		//		trace0ForCallTwice.CrossChainCallResultToExpectCallResult(),
		//		trace1ForCallTwice.CrossChainCallResultToExpectCallResult(),
		//	},
		//},
		//// call crossChainCall precompile contract directly
		//&WrapTx{
		//	Tx: types.NewTx(&types.DynamicFeeTx{
		//		ChainID:   globalchainId,
		//		Nonce:     0,
		//		To:        &preAddr,
		//		Value:     big.NewInt(0),
		//		Gas:       5000000,
		//		GasTipCap: big.NewInt(1000000000),
		//		GasFeeCap: big.NewInt(6000000000),
		//		Data:      common.FromHex("0x99e2007000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
		//	}),
		//	//Args:         Args_CallTwice,
		//	//ExpectTxData: Args_CallTwice.CallTwicePack,
		//	ExpectTraces: []*ExpectTrace{
		//		argsForCallOnce.CrossChainCallResultToExpectCallResult(),
		//	},
		//},
	}

	var wrapTxs []*WrapTx
	for _, wrapTx := range _wrapTxs {

		signer := types.LatestSignerForChainID(globalchainId)
		signTx, err := types.SignTx(wrapTx.Tx, signer, key1)
		if err != nil {
			t.Error(err)
		}

		wrapTx.Tx = signTx
		wrapTxs = append(wrapTxs, wrapTx)
	}

	// evm executes a transaction while the external calling client is active
	for _, wtx := range wrapTxs {
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis

		fmt.Println("BlockNumber", block.Number())

		//block.Header().Number = big.NewInt(10)
		gaspool := new(core.GasPool)
		gaspool.AddGas(8000000000)

		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: externalClient}

		_, statedb := MakePreState(db, gspec.Alloc, false)
		_, crossCallResult, err := core.ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), wtx.Tx, &wtx.GasUsed, vmconfig)
		t.Log("CrossCallResult:", crossCallResult)
		wtx.VerifyCallResult(crossCallResult, err, t)
		wtx.SetExternalCallRes(crossCallResult)
	}

	//evm executes a transaction while the external calling client is inactive
	for index, wtx := range wrapTxs {
		if wtx.happenError != nil {
			continue
		}
		// prepare chainContext
		cli := &clique.Clique{}
		wtm := NewWrapTendermint(cli, nil)
		chainContext := NewTestChainContext(wtm)

		// prepare block
		block := genesis
		gaspool := new(core.GasPool)
		gaspool.AddGas(8000000000)

		var actualUsedGas uint64 = 0
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		tracer := logger.NewJSONLogger(&logger.Config{}, w)
		// set the externalCallClient as nil
		vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: nil}

		_, statedb := MakePreState(db, gspec.Alloc, false)

		msg, err := wtx.Tx.AsMessage(types.MakeSigner(config, block.Header().Number), block.Header().BaseFee)
		if err != nil {
			t.Error(err)
		}
		// Create a new context to be used in the EVM environment
		blockContext := core.NewEVMBlockContext(block.Header(), chainContext, &addr1)
		vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, vmconfig)

		_, crossCallResult, err := core.ApplyTransactionForTest(msg, config, chainContext, &addr1, gaspool, statedb, block.Header().Number, block.Header().Hash(), wtx.Tx, &actualUsedGas, vmenv, wtx.ExpectCCRBytes)
		wtx.VerifyCallResult(crossCallResult, err, t)

		// compare gas use
		if actualUsedGas != wtx.GasUsed {
			t.Errorf("The gas consumption is different when the client is nil and not nil, txIndex=[%d] , nil gas used (%d) , no nil gas used (%d) ", index, actualUsedGas, wtx.GasUsed)
		}
	}
}

//func BenchmarkApplyTransactionWithCallResult(b *testing.B) {
//	var (
//		config = &params.ChainConfig{
//			ChainID:             big.NewInt(3334),
//			HomesteadBlock:      big.NewInt(0),
//			DAOForkBlock:        nil,
//			DAOForkSupport:      true,
//			EIP150Block:         big.NewInt(0),
//			EIP155Block:         big.NewInt(0),
//			EIP158Block:         big.NewInt(0),
//			ByzantiumBlock:      big.NewInt(0),
//			ConstantinopleBlock: big.NewInt(0),
//			PetersburgBlock:     big.NewInt(0),
//			IstanbulBlock:       big.NewInt(0),
//			MuirGlacierBlock:    nil,
//			BerlinBlock:         big.NewInt(0),
//			LondonBlock:         big.NewInt(0),
//			PisaBlock:           big.NewInt(0),
//			ArrowGlacierBlock:   nil,
//			ExternalCall: &params.ExternalCallConfig{
//				EnableBlockNumber: big.NewInt(0),
//				Version:           1,
//				SupportChainId:    4,
//			},
//		}
//		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
//		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
//	)
//
//	var (
//		db           = rawdb.NewMemoryDatabase()
//		contractAddr = common.HexToAddress("0xa000000000000000000000000000000000000aaa")
//		gspec        = &core.Genesis{
//			Config: config,
//			Alloc: core.GenesisAlloc{
//				addr1: core.GenesisAccount{
//					Balance: big.NewInt(1000000000000000000), // 1 ether
//					Nonce:   0,
//				},
//				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): core.GenesisAccount{
//					Balance: big.NewInt(1000000000000000000), // 1 ether
//					Nonce:   math.MaxUint64,
//				},
//				contractAddr: core.GenesisAccount{
//					Balance: big.NewInt(1000000000000000000), // 1 ether
//					Nonce:   math.MaxUint64,
//					Code:    common.FromHex("608060405234801561001057600080fd5b50600436106100415760003560e01c80632061536214610046578063518a3510146100775780638c95e054146100a7575b600080fd5b610060600480360381019061005b9190610510565b6100c5565b60405161006e9291906106df565b60405180910390f35b610091600480360381019061008c9190610510565b610382565b60405161009e91906106bd565b60405180910390f35b6100af6104df565b6040516100bc91906106a2565b60405180910390f35b606080600087878787876040516024016100e3959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff168360405161018d919061068b565b6000604051808303816000865af19150503d80600081146101ca576040519150601f19603f3d011682016040523d82523d6000602084013e6101cf565b606091505b509150915081610214576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161020b90610756565b60405180910390fd5b60008a8a60018b6102259190610801565b8a8a60405160240161023b959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff16836040516102e5919061068b565b6000604051808303816000865af19150503d8060008114610322576040519150601f19603f3d011682016040523d82523d6000602084013e610327565b606091505b50915091508161036c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036390610736565b60405180910390fd5b8381975097505050505050509550959350505050565b60606000868686868660405160240161039f959493929190610776565b6040516020818303038152906040527f99e20070000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806203330373ffffffffffffffffffffffffffffffffffffffff1683604051610449919061068b565b6000604051808303816000865af19150503d8060008114610486576040519150601f19603f3d011682016040523d82523d6000602084013e61048b565b606091505b5091509150816104d0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104c790610716565b60405180910390fd5b80935050505095945050505050565b6203330381565b6000813590506104f5816109dc565b92915050565b60008135905061050a816109f3565b92915050565b600080600080600060a0868803121561052c5761052b6108ff565b5b600061053a888289016104fb565b955050602061054b888289016104e6565b945050604061055c888289016104fb565b935050606061056d888289016104fb565b925050608061057e888289016104fb565b9150509295509295909350565b61059481610857565b82525050565b6105a381610869565b82525050565b60006105b4826107c9565b6105be81856107d4565b93506105ce81856020860161089d565b6105d781610904565b840191505092915050565b60006105ed826107c9565b6105f781856107e5565b935061060781856020860161089d565b80840191505092915050565b60006106206018836107f0565b915061062b82610915565b602082019050919050565b60006106436025836107f0565b915061064e8261093e565b604082019050919050565b60006106666025836107f0565b91506106718261098d565b604082019050919050565b61068581610893565b82525050565b600061069782846105e2565b915081905092915050565b60006020820190506106b7600083018461058b565b92915050565b600060208201905081810360008301526106d781846105a9565b905092915050565b600060408201905081810360008301526106f981856105a9565b9050818103602083015261070d81846105a9565b90509392505050565b6000602082019050818103600083015261072f81610613565b9050919050565b6000602082019050818103600083015261074f81610636565b9050919050565b6000602082019050818103600083015261076f81610659565b9050919050565b600060a08201905061078b600083018861067c565b610798602083018761059a565b6107a5604083018661067c565b6107b2606083018561067c565b6107bf608083018461067c565b9695505050505050565b600081519050919050565b600082825260208201905092915050565b600081905092915050565b600082825260208201905092915050565b600061080c82610893565b915061081783610893565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561084c5761084b6108d0565b5b828201905092915050565b600061086282610873565b9050919050565b6000819050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b60005b838110156108bb5780820151818401526020810190506108a0565b838111156108ca576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f6661696c20746f2063726f737320636861696e2063616c6c0000000000000000600082015250565b7f63726f73732063616c6c2032206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b7f63726f73732063616c6c2031206661696c20746f2063726f737320636861696e60008201527f2063616c6c000000000000000000000000000000000000000000000000000000602082015250565b6109e581610869565b81146109f057600080fd5b50565b6109fc81610893565b8114610a0757600080fd5b5056fea2646970667358221220cb96efc14e55caf807c664755d68fa44a3228605b33e42bc7be92933e03ba95364736f6c63430008070033"),
//				},
//			},
//		}
//
//		globalchainId = config.ChainID
//		genesis       = gspec.MustCommit(db)
//	)
//
//	externalClient, err := ethclient.Dial("https://rinkeby.infura.io/v3/63aa34e959614d01a9a65d3f93b70e66")
//	if err != nil {
//		b.Error(err)
//	}
//
//	const RinkebyTxHash = "0x7ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e46"
//	Args_CallOnce := NewCrossChainCallArgment(config, externalClient, 4, common.HexToHash(RinkebyTxHash), 0, 300, 10)
//
//	gaspool := new(core.GasPool)
//	gaspool.AddGas(30000000)
//	cli := &clique.Clique{}
//	wtm := NewWrapTendermint(cli, nil)
//	chainContext := NewTestChainContext(wtm)
//
//	// prepare block
//	block := genesis
//
//	buf := new(bytes.Buffer)
//	w := bufio.NewWriter(buf)
//	tracer := logger.NewJSONLogger(&logger.Config{}, w)
//	// set the externalCallClient as nil
//	vmconfig := vm.Config{Debug: true, Tracer: tracer, ExternalCallClient: externalClient}
//
//	_, statedb := MakePreState(db, gspec.Alloc, false)
//	for i := 0; i < b.N; i++ {
//		wrapTx :=
//			&WrapTx{
//				Tx: types.NewTx(&types.DynamicFeeTx{
//					ChainID:   globalchainId,
//					Nonce:     uint64(i),
//					To:        &contractAddr,
//					Value:     big.NewInt(0),
//					Gas:       5000000,
//					GasTipCap: big.NewInt(1000000000),
//					GasFeeCap: big.NewInt(6000000000),
//					Data:      common.FromHex("0x518a351000000000000000000000000000000000000000000000000000000000000000047ba399701b823976c367686562ca9fa11ecc81341d2b0026c5615740bd164e460000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c000000000000000000000000000000000000000000000000000000000000000a"),
//				}),
//				Args:           Args_CallOnce,
//				ExpectTxData:   Args_CallOnce.CallOncePack,
//				ExpectCCRBytes: common.FromHex("f901ae01f901aaf901a7b901a0000000000000000000000000751320c36f413a6280ad54487766ae0f780b6f58000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002dce721dc2d078c030530aeb5511eb76663a705797c2a4a4d41a70dddfb8efca9000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000028bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000000000000000000000000000000000000000000001826b08"),
//			}
//
//		signer := types.LatestSignerForChainID(globalchainId)
//		signTx, err := types.SignTx(wrapTx.Tx, signer, key1)
//		if err != nil {
//			b.Error(err)
//		}
//
//		wrapTx.Tx = signTx
//
//		if wrapTx.ExpectTxData != nil {
//			txData, err := wrapTx.ExpectTxData()
//			if err != nil {
//				b.Fatal(err)
//			}
//			if common.Bytes2Hex(txData) != common.Bytes2Hex(wrapTx.Tx.Data()) {
//				b.Fatalf("%d Tx data no match. wrapTx.ExpectTxData():%s ,", i, common.Bytes2Hex(txData))
//			}
//		}
//
//		var actualUsedGas uint64 = 0
//		_, cs, err := core.ApplyTransaction(config, chainContext, &addr1, gaspool, statedb, block.Header(), wrapTx.Tx, &actualUsedGas, vmconfig)
//		b.Log("i:", i, "\nCS:", common.Bytes2Hex(cs), "\nGasUsed:", actualUsedGas)
//		if err != nil {
//			b.Fatal(err)
//			break
//		}
//		if !bytes.Equal(cs, wrapTx.ExpectCCRBytes) {
//			b.Fatal("cross_chain_result err")
//		}
//		if gaspool.Gas() < actualUsedGas {
//			break
//		}
//		statedb.Commit(config.IsEIP158(block.Number()))
//
//	}
//}
