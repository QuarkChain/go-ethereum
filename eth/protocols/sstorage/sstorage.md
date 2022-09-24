# Ethereum Sharded Storage Protocol (SSTORAGE)

The `sstorage` protocol runs on top of [RLPx], facilitating the exchange of Web3q sharded 
storage between peers. The protocol is an optional extension for peers supporting sharded
storage.

The current version is `sstorage/1`.

## Overview

The `sstorage` protocol's goal is to initial sharded storage content from peers. The `sstorage` 
protocol does not take part in chain maintenance (block and transaction propagation); and it is 
**meant to be run side-by-side with the `eth` protocol**, not standalone (e.g. chain progression 
is announced via `eth`).

The `sstorage` protocol itself is simplistic by design, it supports retrieving a contiguous 
segment of chunks from the peers' sharded storage files. Those chunks can be verified by chunk meta 
stored in the PrecompiledContracts. After retrieving and verifying all chunks, they will be saved to 
sharded storage files locally. An additional complexity nodes must be aware of, is that chunk 
content is ephemeral and moves with the chain, so syncers need to support reassembling partially 
consistent chunk segments. This is supported by chunk retrieval similar to
`eth`, which can be used to heal chunk inconsistencies (more on this later).


## Relation to `eth`

The `sstorage` protocol is a *dependent satellite* of `eth` (i.e. to run `sstorage`, you need to
run `eth` too), not a fully standalone protocol. This is a deliberate design decision:

- `sstorage` is meant to be a bootstrap aid for newly joining full nodes with sharded storage 
   function enabled. `sstorage` protocol only keep `eth` peers which also enable sharded storage 
   with chunks the node needed and sync is done, we can avoid synchronizing chunk data from 
   non-full nodes.
- `eth` already contains well established chain and fork negotiation mechanisms, as well
  as remote peer staleness detection during sync. By running both protocols side-by-side,
  `sstorage` can benefit from all these mechanisms without having to duplicate them.


## Synchronization algorithm

When starting a node with sharded storage enabled, it will check storage content is correct.
if any content is missing or not correct, a sync task will be added for that sharded 
storage file to sync data from peers. So the sstorage synchronization task will be added 
under the following conditions: 

- Starting a new node with sharded storage enable;
- Existing node restart with new sharded storage file added.
- Starting an Existing node which failed to flush chunk content from memory to sharded 
  storage file when it stops with sstorage content not flush completely.

For the first two cases (add new sharded storage file), syncer will download a number of 
contiguous chunks from peers until all chunks are synced and verified. For the last case, syncer 
will download a list of specified chunks using a chunk index list.

The caveat of the sstorage synchronization is that the available data constantly moves 
(as new blocks arrive). This is not a problem because we can self-heal. It is fine to 
import chunks from different states, because the inconsistencies can be fixed by fetching
specific chunks by index on top of the assembled semi-correct state afterwards. 
Synchronization can be aborted at any time and resumed later. It might cause self-healing 
to run longer, but it will fix the data.


## Protocol Messages

### GetChunks (0x00)

`[reqID: P, startIdx: P, endIdx: P]`

Requests a number of contiguous chunks, starting at the startIdx and end at the endIdx. 
The intended purpose of this message is to fetch a large number of chunks from a remote 
node and refill a sharded storage file locally.

- `reqID`: Request ID to match up responses with
- `startIdx`: Chunk index of the first to retrieve
- `endIdx`: Chunk index of the last to retrieve  

Notes:

- Nodes **must** always respond to the query.
- The returned nodes **must** be in ascending order.
- If the node does **not** have the chunk for the requested chunk index, it **must** return an
  empty reply. It is the responsibility of the caller to query chunks from the sharded storage 
  file, not including content saved in the memory.
- The responding node is allowed to return **less** data than requested, but the node must return 
  at least one chunk, unless none exists.

Rationale:

- The response is capped by the number of chunks set locally, because it makes the network 
  traffic more deterministic.

Caveats:

- When requesting a range of chunks from a start index, malicious nodes may return incorrect
  chunk content or missing some of them. Such a reply would cause the local node to spend a lot 
  of time to verify the chunk contents and drop them. So if too many chunks are dropped, the 
  peer will be dropped to prevent this attack.
- For the chunks being dropped, the chunk index will be saved to the healing list to retrieve again.

### GetChunkList (0x01)

`[reqID: P, chunkList: [idx: P, ...]]`

Requests a list of chunks using a list of chunk indexes. The intended purpose of this message 
is to fetch a large number of chunks from a remote node and refill a sharded storage file 
locally. 

- `reqID`: Request ID to match up responses with
- `chunkList`: A list of chunk index

Notes:

- Nodes **must** always respond to the query.
- If the node does **not** have the chunk for the requested chunk index, it **must** return an
  empty reply. It is the responsibility of the caller to query chunks from the sharded storage
  file, not including content saved in the memory.
- The responding node is allowed to return **less** data than requested, but the node must return
  at least one chunk, unless none exists.

Rationale:

- The response is capped by the number of chunks set locally, because it makes the network 
  traffic more deterministic.

Caveats:

- When requesting a range of chunks from a start index, malicious nodes may return incorrect
  chunk content or missing some of them. Such a reply would cause the local node to spend a
  lot of time to verify the chunk contents and drop them. So if too many chunks be dropped, the
  peer will be dropped to prevent this attack.
- For the chunks being dropped, the chunk index will be saved to the healing list to retrieve again.

### Chunks (0x02)

`[reqID: P, chunks: [[idx: P, data: B], ...]]`

Returns a number of consecutive Chunks for the requested chunk index (i.e. list of chunk). 
Both GetChunks and GetChunkList requests will use this message as a response.

- `reqID`: ID of the request this is a response for
- `chunks`: List of chunks 
    - `idx`: index of the chunk
    - `data`: Data content of the chunk


## Change Log

### sstorage/1 (July 2022)

Version 1 was the introduction of the sharded storage protocol.
