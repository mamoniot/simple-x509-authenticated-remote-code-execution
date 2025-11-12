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

./server.out $1/cert.der &> "$OUT" &
pid=$!
# Timeout to allow the server to finish opening a socket before sending data.
sleep 0.5

if pgrep server.out &> /dev/null; then
    # Requests are sent concurrently but they complete in a definite order.
    # This is technically a race condition if sending takes longer than 1 second to complete.
    # When sending over localhost this should never happen.
    # The only way to fully eliminate this race condition is for the server to communicate to this
    # bash script the current status of all of its connections, which is absurd.
    ./gen_sig.exe $1/priv.key test/scripts/hello.sh $2 | nc -w 1 127.0.0.1 56544 &
    pid1=$!
    ./gen_sig.exe $1/priv.key test/scripts/empty.sh $2 | nc -w 2 127.0.0.1 56544 &
    pid2=$!
    ./gen_sig.exe $1/priv.key test/scripts/large.sh $2 | nc -w 3 127.0.0.1 56544 &
    pid3=$!

    ./gen_sig.exe test/wrong_code/priv.key test/scripts/hello.sh | nc -w 4 127.0.0.1 56544 &
    pid4=$!
    ./gen_sig.exe test/wrong_code/priv.key test/scripts/empty.sh | nc -w 5 127.0.0.1 56544 &
    pid5=$!

    wait $pid1 $pid2 $pid3 $pid4 $pid5
    # I discovered that WSL is so goddamn slow that 0.5 seconds of timeout here is not long enough
    # for the test to be complete before we kill the process and start the next test. So the timeout
    # is now 2 seconds.
    sleep 2
    kill $pid &> /dev/null
    sleep 0.5
fi

if [[ $TEST -eq 1 ]]; then
    if diff -u "$EXPECTED" "$TEMP" > /dev/null; then
        echo "Test passed"
    else
        echo "Test failed! Incorrect output written to '$TEMP'"
        exit -1
    fi
else
    echo "Please verify the expected output is correct before testing again"
fi
