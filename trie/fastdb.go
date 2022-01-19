package trie

import (
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

type fastDB struct {
	db     *Database
	cache  map[string]*[]byte // nil if it is removed
	prefix []byte
}

func NewFastDB(db *Database) *fastDB {
	return &fastDB{
		db:    db,
		cache: make(map[string]*[]byte),
	}
}

func NewFastDBWithPrefix(db *Database, prefix []byte) *fastDB {
	return &fastDB{
		db:     db,
		cache:  make(map[string]*[]byte),
		prefix: prefix,
	}
}

func (f *fastDB) makeDbKey(key []byte) []byte {
	dbKey := make([]byte, 0)
	dbKey = append(dbKey, f.prefix...)
	dbKey = append(dbKey, key...)
	return dbKey
}

func (f *fastDB) GetKey(key []byte) []byte {
	res, err := f.TryGet(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

func (f *fastDB) TryGet(key []byte) ([]byte, error) {
	if data, ok := f.cache[string(key)]; ok {
		if data == nil {
			return nil, fmt.Errorf("not found")
		}
		return *data, nil
	}
	return f.db.Get(f.makeDbKey(key))
}

func (f *fastDB) TryUpdate(key, value []byte) error {
	f.cache[string(key)] = &value
	return nil
}

func (f *fastDB) Update(key, value []byte) {
	if err := f.TryUpdate(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

func (f *fastDB) TryUpdateAccount(key []byte, acc *types.StateAccount) error {
	data, err := rlp.EncodeToBytes(acc)
	if err != nil {
		return fmt.Errorf("can't encode object at %x: %w", key[:], err)
	}
	return f.TryUpdate(key, data)
}

func (f *fastDB) TryDelete(key []byte) error {
	f.cache[string(key)] = nil
	return nil
}

// Return rawdb CRUD operation hash
func (f *fastDB) Hash() common.Hash {
	keyList := make([]string, 0, len(f.cache))
	for k, _ := range f.cache {
		keyList = append(keyList, k)
	}

	if len(f.cache) == 0 {
		return common.Hash{}
	}

	// TODO: May replace with a Merkle tree
	seed := make([]byte, 0)
	sort.Strings(keyList) // make sure the hash calculation is deterministic
	for _, k := range keyList {
		seed = append(seed, []byte(k)...)
		value := f.cache[k]
		if value == nil {
			seed = append(seed, 0)
		} else {
			seed = append(seed, 1)
			seed = append(seed, *value...)
		}
	}
	return common.BytesToHash(crypto.Keccak256(seed))
}

func (f *fastDB) Commit(onleaf LeafCallback) (common.Hash, int, error) {
	h := f.Hash()
	for k, v := range f.cache {
		if v == nil {
			if err := f.db.Delete([]byte(k)); err != nil {
				return common.Hash{}, 0, nil
			}
		} else if err := f.db.Put([]byte(k), *v); err != nil {
			return common.Hash{}, 0, nil
		}
	}

	f.cache = make(map[string]*[]byte)
	return h, 0, nil
}
