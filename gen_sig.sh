#!/bin/bash
clang -O3 src/gen_sig.c -lssl -lcrypto -o gen_sig.exe
