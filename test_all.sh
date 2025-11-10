#!/bin/bash

echo "testing ed25519"
./test.sh test/ed25519

echo "testing ed448"
./test.sh test/ed448

echo "testing alt"
./test.sh test/alt

echo "testing rsa4096sha256"
./test.sh test/rsa4096sha256 sha256

echo "testing rsa4096sha384"
./test.sh test/rsa4096sha384 sha384

echo "testing rsa4096sha512"
./test.sh test/rsa4096sha512 sha512

echo "testing rsa3072sha256"
./test.sh test/rsa3072sha256 sha256

echo "testing rsa3072sha512"
./test.sh test/rsa3072sha512 sha512

echo "testing rsa2048sha256"
./test.sh test/rsa2048sha256 sha256

echo "testing wrong_code"
./test.sh test/wrong_code

echo "testing multiple"
./test.sh test/multiple

echo "testing multiple_wrong"
./test.sh test/multiple_wrong sha384

echo "testing junk"
./test.sh test/junk
