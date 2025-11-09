./gen_sig.exe $1/priv.key scripts/large.sh $2 | nc -N 127.0.0.1 56543
./gen_sig.exe $1/priv.key scripts/small.sh $2 | nc -N 127.0.0.1 56543
./gen_sig.exe $1/priv.key scripts/hello.sh $2 | nc -N 127.0.0.1 56543
./gen_sig.exe $1/priv.key scripts/ls.sh $2 | nc -N 127.0.0.1 56543
