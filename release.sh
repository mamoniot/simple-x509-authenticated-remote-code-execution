#!/bin/bash
# I don't consider this project complex enough to warrant a make file.
clang -O3 src/main.c src/x509.c src/crypto.c -lcrypto -o server.exe
