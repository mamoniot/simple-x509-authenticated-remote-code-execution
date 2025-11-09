#!/bin/bash

if [[ "$#" -eq 0 ]]; then
    echo "Usage: $0 \"test directory to run\""
    exit 1
fi

EXPECTED=$1/expected.txt
TEMP=$1/temp.txt

if [[ -f $EXPECTED ]]; then
    TEST=1
    OUT=$TEMP
else
    TEST=0
    OUT=$EXPECTED
    echo "Expected program output not generated, generating now..."
fi

./server.exe $1/cert.der &> "$OUT" &
pid=$!

sleep 1

test/gen_sig.exe $1/priv.key test/scripts/hello.sh $2 | nc -q 1 127.0.0.1 56544
test/gen_sig.exe $1/priv.key test/scripts/empty.sh $2 | nc -q 1 127.0.0.1 56544
test/gen_sig.exe $1/priv.key test/scripts/large.sh $2 | nc -q 1 127.0.0.1 56544

test/gen_sig.exe test/wrong_code/priv.key test/scripts/hello.sh | nc -q 1 127.0.0.1 56544
test/gen_sig.exe test/wrong_code/priv.key test/scripts/empty.sh | nc -q 1 127.0.0.1 56544

sleep 1

kill $pid &> /dev/null

if [[ $TEST -eq 1 ]]; then
    if diff -u "$EXPECTED" "$TEMP" > /dev/null; then
        echo "Test passed"
    else
        echo "Output differs from expected:"
        cat "$TEMP"
    fi
else
    echo "Please verify the expected output is correct before testing again"
fi
