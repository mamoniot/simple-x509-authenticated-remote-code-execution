#!/bin/bash
set -e

echo "Compiling server"
./debug.sh
./gen_sig.sh

echo "Testing ed25519"
./test_one.sh test/ed25519

echo "Testing ed448"
./test_one.sh test/ed448

echo "Testing alt"
./test_one.sh test/alt

echo "Testing rsa4096sha256"
./test_one.sh test/rsa4096sha256 sha256

echo "Testing rsa4096sha384"
./test_one.sh test/rsa4096sha384 sha384

echo "Testing rsa4096sha512"
./test_one.sh test/rsa4096sha512 sha512

echo "Testing rsa3072sha256"
./test_one.sh test/rsa3072sha256 sha256

echo "Testing rsa3072sha512"
./test_one.sh test/rsa3072sha512 sha512

echo "Testing rsa2048sha256"
./test_one.sh test/rsa2048sha256 sha256

echo "Testing wrong_code"
./test_one.sh test/wrong_code

echo "Testing multiple"
./test_one.sh test/multiple

echo "Testing multiple_wrong"
./test_one.sh test/multiple_wrong sha384

echo "Testing corrupted_date"
./test_one.sh test/corrupted_date

echo "Testing corrupted_sig"
./test_one.sh test/corrupted_sig

echo "Testing empty"
./test_one.sh test/empty

echo "Testing expired"
./test_one.sh test/expired

echo "Testing large"
./test_one.sh test/large

echo "Testing time_travel"
./test_one.sh test/time_travel

echo "Testing trailing_key"
./test_one.sh test/trailing_key
