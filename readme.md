TODO: fix junk to be deterministic.

# How to compile
## Prerequisites

```sudo apt install -y clang libssl-dev```

## Command

Bash script `release.sh` contains the command to compile a release build of the server. It will be output as `server.exe`.
```./release.sh```

Bash script `debug.sh` contains the command to compile a debug build of the server. It will be output as `server.out`.
```./debug.sh```

# How to Run
## Prerequisites
## Command

# How to Use
## Prerequisites
## Command

# How to Test
## Prerequisites

TCP port 56544 must be available for binding prior to running the test script. The contents of `test/` must be unmodified. It is highly recommended to make sure that TCP port 56544 is blocked externally by a firewall. Otherwise anyone who has access to the testing keys could remotely execute code during the duration of the test. It is also recommended to run these tests from a non-admin user account.

If I were to continue development I would implement a networking layer within the server. This would then be used to test the server without allowing it to bind to a TCP port.

## Command

Bash script `test_all.sh` will run all test cases sequentially on a release build of the server. It will run the server repeatedly and compare its output with an `expected.txt` file that contains the correct output. "Test passed" or "Test failed" will be output for each of the test cases.

```./test_all.sh```

If the test is stopped before completion there will likely be an orphaned `server.exe` process that is still bound to port 56544. Command `kill "$(pgrep server.exe)"` can be used to kill this process and unbind port 56544.
