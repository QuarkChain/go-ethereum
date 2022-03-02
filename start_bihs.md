## 启动说明

### 1. 编译二进制文件
```buildoutcfg
make all
```

在`./build/bin`目录下可以看到下列二进制文件
```buildoutcfg
abidump
abigen
bootnode
checkpoint-admin
clef
devp2p
ethkey
evm
faucet
geth
p2psim
puppeth
rlpdump

```

### 2.环境准备
以本地启动四个节点为例
```
node1
node2
```
将geth 拷贝到每个文件夹下，执行：
```buildoutcfg
./geth --datadir ./data/ init bihs_genesis.json 
```

该命令初始化`genesis`为`bihs`共识，并生成`p2p nodekey`在`data/geth`目录下，需要手动计算私钥的地址，并填入到https://github.com/zhiqiangxu/go-ethereum/blob/web3q_bihs/consensus/bihs/gov/gov.go#L20 ，该模块内部以round robin方式确定每一轮的leader，仅用于demo。

### 3. 启动节点
假定二个节点的p2p端口为2000 ~ 2001,我们暂时只开放node1的http端口，默认为8545
首先通过下面的命令打印各个节点的公钥
```buildoutcfg
bootnode -nodekey ./data/geth/nodekey -writeaddress
```
将节点列表放入<datadir>/geth/static-nodes.json文件中，让节点主动连接和重连：https://geth.ethereum.org/docs/interface/peer-to-peer

```buildoutcfg
[
    "enode://7b9a62ee9350e0d3a86dc29f97875542a3b0a7765c177218bcbcaa2bbb0da945feb87a137f510d6ac0c976456e0d9a624d2534298ed45e07fa455b55ebfa1832@127.0.0.1:2000",
    "enode://d64121d4de07d8acf82e65a8ac7e2e331d4ff77e29496433366570cb0f632f8a60e7e64dfc0853a9f6bb3880b0436df77c9108fbd9fe762980d17d7f1ec92289@127.0.0.1:2001"
]
```

启动命令
```buildoutcfg
./geth  --datadir ./data --networkid 121 --port 2000 --http --http.addr 0.0.0.0 --http.port 8545 --miner.gasprice 0 --mine --miner.etherbase=0x49666faD0530f3A50A48Ed473104647ca2af777D --syncmode full --nodiscover --verbosity 5

./geth  --datadir ./data --networkid 121 --port 2001 --miner.gasprice 0 --mine --miner.etherbase=0x49666faD0530f3A50A48Ed473104647ca2af777D --syncmode full --nodiscover --verbosity 5
```
其中`miner.etherbase`需要跟p2p私钥`geth/nodekey`对应。