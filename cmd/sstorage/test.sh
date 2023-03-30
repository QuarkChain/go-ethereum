#!/bin/bash

set -e


test_string=abcdefg
test_string1=112233445566

./sstorage create --filename test.dat --miner=0x0000000000000000000000000000000000001234 --len=1024
echo $test_string | ./sstorage shard_write --filename test.dat --kv_idx=0 --kv_entries=16
a=$(./sstorage shard_read --filename test.dat --kv_idx=0 --kv_entries=16 --readlen=7)
[[ $test_string == $a ]] || (echo "cmp failed" && exit 1)

rm test.dat

# Test with encoding
./sstorage create --filename test.dat --miner=0x0000000000000000000000000000000000001234 --len=1024 --encode_type=1
echo $test_string | ./sstorage shard_write --filename test.dat --kv_idx=0 --kv_entries=16
a=$(./sstorage shard_read --filename test.dat --kv_idx=0 --kv_entries=16 --readlen=7)
[[ $test_string == $a ]] || (echo "cmp failed" && exit 1)

echo $test_string | ./sstorage shard_write --filename test.dat --kv_idx=1 --kv_entries=16 --encode_key=0x00000000000000000000000000000000000000000000000000000000000000aa
a=$(./sstorage shard_read --filename test.dat --kv_idx=1 --kv_entries=16 --readlen=7)
[[ $test_string == $a ]] && (echo "cmp failed" && exit 1)
a=$(./sstorage shard_read --filename test.dat --kv_idx=1 --kv_entries=16 --readlen=7 --encode_key=0x00000000000000000000000000000000000000000000000000000000000000aa)
[[ $test_string == $a ]] || (echo "cmp failed" && exit 1)

rm test.dat

echo "Testing Ethash encdec"

./sstorage create --filename test.dat --miner=0x0000000000000000000000000000000000001234 --len=1024 --encode_type=2
echo $test_string | ./sstorage shard_write --filename test.dat --kv_idx=0 --kv_entries=16
a=$(./sstorage shard_read --filename test.dat --kv_idx=0 --kv_entries=16 --readlen=7)
[[ $test_string == $a ]] || (echo "cmp failed" && exit 1)

echo $test_string1 | ./sstorage shard_write --filename test.dat --kv_idx=1 --kv_entries=16 --encode_key=0x00000000000000000000000000000000000000000000000000000000000000aa
a=$(./sstorage shard_read --filename test.dat --kv_idx=1 --kv_entries=16 --readlen=12)
[[ $test_string1 == $a ]] && (echo "cmp failed" && exit 1)
a=$(./sstorage shard_read --filename test.dat --kv_idx=1 --kv_entries=16 --readlen=12 --encode_key=0x00000000000000000000000000000000000000000000000000000000000000aa)
[[ $test_string1 == $a ]] || (echo "cmp failed" && exit 1)

a=$(./sstorage shard_read --filename test.dat --kv_idx=0 --kv_entries=16 --readlen=7)
[[ $test_string == $a ]] || (echo "cmp failed" && exit 1)

echo "All tests passed"
