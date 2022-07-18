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

The protocol itself is simplistic by design (take note, the supporting implementation is
everything but simple). In its crux, `sstorage` supports retrieving a contiguous segment of
accounts from the Ethereum state trie, or a contiguous segment of storage slots from one
particular storage trie. Both replies are Merkle proven for immediate verification. In
addition batches of bytecodes can also be retrieved similarly to the `eth` protocol.

The synchronization mechanism the protocol enables is for peers to retrieve and verify all
the account and storage data without downloading intermediate Merkle trie nodes. The final
state trie is reassembled locally. An additional complexity nodes must be aware of, is
that state is ephemeral and moves with the chain, so syncers need to support reassembling
partially consistent state segments. This is supported by trie node retrieval similar to
`eth`, which can be used to heal trie inconsistencies (more on this later).

The `sstorage` protocol permits downloading the entire Ethereum state without having to
download all the intermediate Merkle proofs, which can be regenerated locally. This
reduces the networking load enormously:

- Ingress bandwidth is reduced from `O(accounts * log account + SUM(states * log states))`
  (Merkle trie nodes) to `O(accounts + SUM(states))` (actual state data).
- Egress bandwidth is reduced from `O(accounts * log account + SUM(states * log states)) *
  32 bytes` (Merkle trie node hashes) to `O(accounts + SUM(states)) / 100000 bytes`
  (number of 100KB chucks to cover the state).
- Round trip time is reduced from `O(accounts * log account + SUM(states * log states)) /
  384` (states retrieval packets) to `O(accounts + SUM(states)) / 100000 bytes` (number of
  100KB chucks to cover the state).

## Relation to `eth`

The `sstorage` protocol is a *dependent satellite* of `eth` (i.e. to run `sstorage`, you need to
run `eth` too), not a fully standalone protocol. This is a deliberate design decision:

- `sstorage` is meant to be a bootstrap aid for newly joining full nodes. By enforcing all
  `sstorage` peers to also speak `eth`, we can avoid non-full nodes from lingering attached to
  `sstorage` indefinitely.
- `eth` already contains well established chain and fork negotiation mechanisms, as well
  as remote peer staleness detection during sync. By running both protocols side-by-side,
  `sstorage` can benefit of all these mechanisms without having to duplicate them.

This *satellite* status may be changed later, but it's better to launch with a more
restricted protocol first and then expand if need be vs. trying to withdraw depended-upon
features.

The `sstorage` protocol is not an extension / next version of `eth` as it relies on the
availability of a *snapshot* acceleration structure that can iterate accounts and storage
slots linearly. Its purpose is also one specific sync method that might not be suitable
for all clients. Keeping `sstorage` as a separate protocol permits every client to decide to
pursue it or not, without hindering their capacity to participate in the `eth` protocol.

## Synchronization algorithm

The crux of the snapshot synchronization is making contiguous ranges of accounts and
storage slots available for remote retrieval. The sort order is the same as the state trie
iteration order, which makes it possible to not only request N subsequent accounts, but
also to Merkle prove them. Some important properties of this simple algorithm:

- Opposed to *fast sync*, we only need to transfer the useful leaf data from the state
  trie and can reconstruct internal nodes locally.
- Opposed to *warp sync*, we can download small chunks of accounts and storage slots and
  immediately verify their Merkle proofs, making junk attacks impossible.
- Opposed to *warp sync*, random account ranges can be retrieved, thus synchronization
  concurrency is totally dependent on client implementation and is not forced by the
  protocol.

The gotcha of the snapshot synchronization is that serving nodes need to be able to
provide **fast** iterable access to the state of the most recent `N` (128) blocks.
Iterating the Merkle trie itself might be functional, but it's not viable (iterating the
state trie at the time of writing takes 9h 30m on an idle machine). Geth introduced
support for [dynamic snapshots], which allows iterating all the accounts in 7m
(see [blog for more]). Some important properties of the dynamic snapshots:

- Serving a contiguous range of accounts or storage slots take `O(n)` operations, and more
  importantly, it's the same for disk access too, being stored contiguously on disk (not
  counting the database read amplification).
- Maintaining a live dynamic snapshot means:
    - Opposed to *warp sync*, syncing nodes can always get the latest data, thus they don't
      need to process days' worth of blocks afterwards.
    - Opposed to *warp sync*, there is no pre-computation to generate a snapshot (it's
      updated live), so there's no periodic burden on the nodes to iterate the tries (there
      it an initial burden to create the first snapshot after sync though).
    - Providing access to 128 recent snapshots permits `O(1)` direct access to any account
      and state, which can be used during EVM execution for `SLOAD`.

The caveat of the snapshot synchronization is that as with *fast sync* (and opposed to
*warp sync*), the available data constantly moves (as new blocks arrive). The probability
of finishing sync before the 128 block window (15m) moves out is asymptotically zero. This
is not a problem, because we can self-heal. It is fine to import state snapshot chunks
from different tries, because the d can be fixed by running a
*fast-sync-style-state-sync* on top of the assembled semi-correct state afterwards. Some
important properties of the self-healing:

- Synchronization can be aborted at any time and resumed later. It might cause
  self-healing to run longer, but it will fix the data either way.
- Synchronization on slow connections is guaranteed to finish too (as long as the node can
  download data faster than it's being produced by the network), the data cannot disappear
  from the network (opposed to warp sync).

## Data format

The accounts in the `sstorage` protocol are analogous to the Ethereum RLP consensus encoding
(same fields, same order), but in a **slim** format:

- The code hash is `empty list` instead of `Keccak256("")`
- The root hash is `empty list` instead of `Hash(<empty trie>)`

This is done to avoid having to transfer the same 32+32 bytes for all plain accounts over
the network.

## Protocol Messages

### GetChunks (0x00)

`[reqID: P, startIdx: P, endIdx: P]`

Requests a number of state (either account or storage) Merkle trie nodes **by path**. This
is analogous in functionality to the `eth/63` `GetNodeData`, but restricted to only tries
and queried by path, to break the generality that causes issues with database
optimizations.

- `reqID`: Request ID to match up responses with
- `rootHash`: Root hash of the account trie to serve
- `paths`: Trie paths to retrieve the nodes for, grouped by account
- `bytes`: Soft limit at which to stop returning data

The `paths` is one array of trie node paths to retrieve per account (i.e. list of list of
paths). Each list in the array special cases the first element as the path in the account
trie and the remaining elements as paths in the storage trie. To address an account node,
the inner list should have a length of 1 consisting of only the account path. Partial
paths (<32 bytes) should be compact encoded per the Ethereum wire protocol, full paths
should be plain binary encoded.

*This functionality was mutated into `sstorage` from `eth/65` to permit `eth` long term to
become a chain maintenance protocol only and move synchronization primitives out into
satellite protocols only.*

Notes:

- Nodes **must** always respond to the query.
- The returned nodes **must** be in the request order.
- If the node does **not** have the state for the requested state root or for **any**
  requested account paths, it **must** return an empty reply. It is the responsibility of
  the caller to query an state not older than 128 blocks; and the caller is expected to
  only ever query existing trie nodes.
- The responding node is allowed to return **less** data than requested (serving QoS
  limits), but the node **must** return at least one trie node.

Rationale:

- The response is capped by byte size and not by number of slots, because it makes the
  network traffic more deterministic. Although opposed to the previous request types
  (accounts, slots, codes), trie nodes are relatively deterministic (100-500B), the
  protocol remains cleaner if all packets follow the same traffic shaping rules.
- A naive way to represent trie nodes would be a simple list of `account || storage` path
  segments concatenated, but that would be very wasteful on the network as it would
  duplicate the account hash for every storage trie node.

### Chunks (0x01)

`[reqID: P, chunks: [[idx: P, data: B], ...]]`

Returns a number of requested Chunks. The order is from small to large. If the data 

## Change Log

### sstorage/1 (November 2020)

Version 1 was the introduction of the sharded storage protocol.
