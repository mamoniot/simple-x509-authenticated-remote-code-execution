# Simple x509 Authenticated Remote Code Execution

This repository contains the source code for a linux server that takes as input a set of x509 certificates, and will listen over TCP for signed bash scripts. If the signature is considered valid under one of the x509 certificates, the entire script will be run and the output of the script will be written to stdout.

## How to compile
### Prerequisites
This server is compiled with clang, and it links to OpenSSL. As such both clang and OpenSSL must be installed. On a debian-based system this can be done with:

```sudo apt install -y clang libssl-dev```

Other systems will need to refer to their package managers to install clang and libssl-dev.

On rare occassion, OpenSSL and its headers are not installed to the correct locations. When this happens clang will report that a linker command failed. This is a problem with no common fix, but has been documented and solved countless times online.

This program can also be compiled by `gcc`, but this is less tested and will require modifying the existing build scripts.

### Command

Bash script `release.sh` contains the command to compile a release build of the server. It will be output as `server.exe`.

```./release.sh```

Bash script `debug.sh` contains the command to compile a debug build of the server. It will be output as `server.out`.

```./debug.sh```

## How to Run
### Prerequisites

TCP port 56544 must be available for binding prior to running the server. It is recommended to only run this software from a non-admin account behind a firewall.

At least one trusted and self-signed x509 certificate must be available. There are many utilities available to create these. The command `openssl req` is recommended.

### Command

The server executable expects a single argument. This argument specifies the path to the file or directory containing the x509 certificates that the server should use for verification. If the argument is a file, that file must be a single DER encoded x509 certificate. If the argument is a directory, that directory must contain only DER encoded x509 certificate files.

Each certificate will be parsed and verified, and only valid ceriticates will be used for signature verification. Only self-signed certificates are accepted.

```./server.exe FILE/DIR```

## How to Use

### Supported Algorithms

This is a list of all of the public key algorithms currently supported by this server:

* ED25519
* ED448
* RSA-4096-SHA-256
* RSA-4096-SHA-384
* RSA-4096-SHA-512
* RSA-3072-SHA-256
* RSA-3072-SHA-384
* RSA-3072-SHA-512

Any other will be rejected by the server upon parsing its x509 certificate.

This server deliberately does not support any version of RSA-2048, as RSA-2048 is no longer considered forward-secure and has been deprecated by NIST. It is straigthforward to support more public key algorithms by adding to source code file `src/crypto.c`. It is also straightforward to replace the implementation of any individual public key and digest algorithm.

### TCP Protocol

The server will listen to TCP port 56544 for connections. For all new connections, the server expects to receive the raw bytes of a digital signature, followed immediately by a newline character `'\n'`, followed by a plaintext bash script. The signature must have been generated over just the plaintext bash script using the private key of one of the trusted certificates passed to the server at startup.

The server will only attempt to verify and run the bash script after the TCP connection terminates. The server can accept multiple TCP connections concurrently and will number and execute each script in the order that their connections terminated. Each bash script is executed sequentially.

### Status of Execution

When the server fails to validate the input x509 certificates, or is unable to acquire necessary system resources, a plaintext error message will be output and execution will terminate. If a directory of many certificates was passed to the server, a non-fatal error message may be output. Execution may continue so long as a single x509 certificate is valid.

When the server successfully receives and authenticates a bash script, it will print the line "Remote bash script #%d received and authenticated, executing now...", where "%d" is replaced with the script number. What will then follow on the next line is the output of the received bash script. If an error occurred or the script could not be authenticated, it will print a plaintext error message to stderr. Inauthentic scripts will not be assigned a script number. The error message "Remote bash script could not be authenticated, aborting execution" will be written when the script is inauthentic.

### Command

There are a countless number of ways to generate a digital signature and then send it concatenated with a bash script over a TCP connection. However to automate the process I created a small utility program. It can be compiles with the command:

```./gen_sig.sh```

This will produce an executable `gen_sig.exe`. This executable takes as input a private key file, a bash script and an optional digest algorithm, and writes to stdout a signature on the bash script, followed immediately by a newline, followed by the bash script itself.

The digest algorithm name can only be `sha256`, `sha384` or `sha512`, and is only necessary when using an RSA key. The digest algorithm must match the digest algorithm used to sign the x509 certificate associated with this private key.

```./gen_sig KEY SCRIPT [sha256/sha384/sha512]```

The output of `gen_sig` can then be sent to the server through TCP. This can be done with netcat as follows:

```./gen_sig KEY SCRIPT [sha256/sha384/sha512] | nc -w 1 127.0.0.1 56544```

## How to Test
### Prerequisites

TCP port 56544 must be available for binding prior to running the test script. The contents of `test/` must be unmodified. It is highly recommended to make sure that TCP port 56544 is blocked externally by a firewall. Otherwise anyone who has access to the testing keys could remotely execute code during the duration of the test. It is also recommended to run these tests from a non-admin user account.

If I were to continue development I would implement a networking layer within the server, so that the server can be configured to use domain sockets or an in-process communication protocol instead of TCP. That way end to end tests can be run without openning external ports.

### Command

Bash script `test_all.sh` will run all end to end test cases sequentially on a debug build of the server. It will run the server repeatedly and compare its output with an `expected.txt` file that contains the correct output. "Test passed" or "Test failed" will be output for each of the test cases.

```./test_all.sh```

If the test is stopped before completion there will likely be an orphaned `server.out` process that is still bound to port 56544. Command `kill "$(pgrep server.out)"` can be used to kill this process and unbind port 56544.

### Networking Nondeterminism

To overcome the nondeterminism inherent to both networking and process scheduling, the test scripts rely heavily on timeouts. This allows the tests to have fully deterministic outcomes, so long as no individual test case takes longer than its timeout to process. However this does mean that testing takes unnecessarily long to complete, since nearly all testing time is spent waiting on timeouts.

If I were to continue development I would heavily consider building an instrumentation framework for this server, such that the testing script is able to block on status changes of individual requests. This would remove the need for timeouts, thus allowing the full testing suite to complete in just a  second or two. It would also remove the risk of tests failing on very low-end machines due to nothing more than too short of timeouts. This is a lot of work though and I consider the tests fast enough for software this simple.

## Security Disclaimers

This software is very dangerous. It generally a bad idea to remotely run scripts from the network that are authenticated by nothing more than a single signature. This server really ought to support a standardized data and signature format that includes options for key identification, signature expiration, salting and multi-signing, but that was not in the specification and is a lot of additional work.

Bash scripts are sent to the server entirely unencrypted. Even with public key authentication, this is still a security flaw under most applicable threat models.

This software was entirely written by one person. While I have confidence in my ability to write secure code, it is never a good idea to trust security entirely onto one programmer. If this software were to go into production, it ought to be thoroughly audited by multiple people.
