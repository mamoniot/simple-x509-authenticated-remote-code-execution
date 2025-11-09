DIR="rsa3072sha256"

openssl req -x509 -newkey rsa:3072 -sha256 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"

./gen_sig.out $DIR/priv.key scripts/hello.sh sha256 > $DIR/hello
./gen_sig.out $DIR/priv.key scripts/ls.sh sha256 > $DIR/ls
./gen_sig.out $DIR/priv.key scripts/large.sh sha256 > $DIR/large
