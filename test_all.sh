#!/bin/bash
echo "compiling server"
./release.sh
./gen_sig.sh

echo "testing ed25519"
./test_one.sh test/ed25519

echo "testing ed448"
./test_one.sh test/ed448

echo "testing alt"
./test_one.sh test/alt

echo "testing rsa4096sha256"
./test_one.sh test/rsa4096sha256 sha256

echo "testing rsa4096sha384"
./test_one.sh test/rsa4096sha384 sha384

echo "testing rsa4096sha512"
./test_one.sh test/rsa4096sha512 sha512

echo "testing rsa3072sha256"
./test_one.sh test/rsa3072sha256 sha256

echo "testing rsa3072sha512"
./test_one.sh test/rsa3072sha512 sha512

echo "testing rsa2048sha256"
./test_one.sh test/rsa2048sha256 sha256

echo "testing wrong_code"
./test_one.sh test/wrong_code

echo "testing multiple"
./test_one.sh test/multiple

echo "testing multiple_wrong"
./test_one.sh test/multiple_wrong sha384

echo "testing corrupted_date"
./test_one.sh test/corrupted_date

echo "testing corrupted_sig"
./test_one.sh test/corrupted_sig

echo "testing empty"
./test_one.sh test/empty

echo "testing expired"
./test_one.sh test/expired

echo "testing large"
./test_one.sh test/large

echo "testing time_travel"
./test_one.sh test/time_travel

echo "testing trailing_key"
./test_one.sh test/trailing_key
