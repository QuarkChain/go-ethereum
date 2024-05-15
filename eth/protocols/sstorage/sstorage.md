# Ethereum Sharded Storage Protocol (SSTORAGE)

The `sstorage` protocol runs on top of [RLPx], facilitating the exchange of Web3q sharded storage 
between peers. The protocol is an optional extension for peers supporting sharded storage.

The current version is `sstorage/1`.

## Overview

The `sstorage` protocol's goal is to synchronize sharded storage content from peers. The `sstorage` 
protocol does not take part in chain maintenance (block and transaction propagation); and it is
**meant to be run side-by-side with the `eth` protocol**, not standalone (e.g. chain progression 
is announced via eth).

The `sstorage` protocol is supposed to be run after the node is synchronized to the latest block. 
The `sstorage` protocol itself is simplistic by design, it supports retrieving a contiguous segment 
of chunks from the peers' sharded storage. Those chunks can be verified by chunk metadata stored in 
the sharded storage system contracts. After retrieving and verifying all chunks, they will be saved 
to sharded storage files locally. An additional complexity must be aware of, is that chunk content 
is ephemeral and changes with the progress of the chain, so a syncer may receive chunks that mismatch 
with local chunk metadata. In this case, the syncer will fetch the data from other peers until the 
download chunks are matched. Another special case is that a node may crash with inconsistent local 
chunks (i.e., those chunks are not empty, but is inconsistent with metadata).Syncers need to support 
identifying inconsistent chunk segments and heal chunk inconsistencies by retrieving the chunks via 
`sstorage` protocol.

## Relation to `eth`

The `sstorage` protocol is a dependent satellite of `eth` (i.e. to run `sstorage`, you need to run 
`eth` too), not a fully standalone protocol. This is a deliberate design decision:

- `sstorage` is meant to be a bootstrap aid for newly joining full nodes with sharded storage function 
   enabled. `sstorage` protocol only keeps eth peers which also enables sharded storage with chunks the 
   node needed.
- `eth` already contains well-established chain and fork negotiation mechanisms, as well as remote peer 
  staleness detection during sync. By running both protocols side-by-side, `sstorage` can benefit from 
  all these mechanisms without having to duplicate them.

In order to let the `sstorage` protocol know which storage shards are supported by the peer node, the 
storage shards information needs to be added to the protocol's handshake function.

In order to make sure every storage shard has enough peers to fetch chunks, the `minSstoragePeers` will 
be set for each shard, so a new peer will ignore MaxPeers setting for eth protocol and register, only if 
that peer contains a storage shard which the local node having the same shard, and do not reach the 
`minSstoragePeers` limit.

## Synchronization algorithm

When starting a node with sharded storage enabled, it will check if the local storage content is correct. 
If any content is missing or not correct, a sync task will be added for that sharded storage file to sync 
data from peers. So the `sstorage` synchronization task will be added under the following conditions:

- Starting a node with new shards;
- Restarting a node that partially downloads the data of some shards;
- Starting an existing node which failed to flush chunk content from memory to sharded storage file when 
  the node stops (e.g., the node crashes because of OOM).

The caveat of the `sstorage` synchronization is that the target data constantly changes (as new blocks 
arrive). This is not a problem because we will discard mismatched chunks and try to download the chunks 
of another peer. If the chunks are unavailable from all peers (likely happen when the node is a bit behind 
the network), the syncer will try to download it later or it will automatically synchronize the chunks by 
executing new blocks.

In the case of inconsistency of local chunks with metadata (likely to happen when the node crashes), we 
can self-heal. 

## Request ID

Every on-demand request message contains a `reqID` field, which is simply returned by the server in the 
corresponding reply message. This helps matching replies for requests on the client side so that each 
reply doesn't need to be matched against each pending request.

## Protocol Messages

### GetChunks (0x00)

`[reqID: P, contract: B, chunkList: [idx: P, ...]]`

Requests a list of chunks using a list of chunk indexes. The intended purpose of this message is to fetch 
a large number of chunks from a remote node and refill a sharded storage file locally.

- `reqID`: Request ID to match up responses with
- `contract`: Sharded storage system contract related to chunk retrieve
- `chunkList`: A list of chunk index

Notes:

- Nodes **must** always respond to the query.
- If the node does **not** have the chunk for the requested chunk index, it **must** return an empty 
  reply. It is the responsibility of the caller to query chunks from the sharded storage file, not 
  including content saved in the memory.
- The responding node is allowed to return **less** data than requested, but the node must return at 
  least one chunk, unless none exists.

Rationale:

- The response is capped by the number of chunks set locally, because it makes the network traffic more 
deterministic.

Caveats:

- When requesting a range of chunks from a start index, malicious nodes may return incorrect chunk content 
  or missing some of them. Such a reply would cause the local node to spend a lot of time to verify the 
  chunk contents and drop them. So if too many chunks are dropped, the peer will be dropped to prevent 
  this attack.
- For the chunks being dropped, the chunk index will be saved to the healing list to retrieve again.


### Chunks (0x01)

`[reqID: P, contract: B, chunks: [[idx: P, data: B], ...]]`

Returns a number of consecutive Chunks for the requested chunk index (i.e. list of chunk). GetChunks 
requests will use this message as a response.

- `reqID`: ID of the request this is a response for
- `contract`: Sharded storage system contract related to chunk retrieve
- `chunks`: List of chunks in response
  - `idx`: index of the chunk
  - `data`: Data content of the chunk

## Change Log

### sstorage/1 (July 2022)

Version 1 was the introduction of the sharded storage protocol.

