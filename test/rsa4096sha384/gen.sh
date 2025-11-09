DIR="rsa4096sha384"

openssl req -x509 -newkey rsa:4096 -sha384 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"

./gen_sig.out $DIR/priv.key scripts/hello.sh sha384 > $DIR/hello
./gen_sig.out $DIR/priv.key scripts/ls.sh sha384 > $DIR/ls
./gen_sig.out $DIR/priv.key scripts/large.sh sha384 > $DIR/large
