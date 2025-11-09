DIR="rsa3072sha512"

openssl req -x509 -newkey rsa:3072 -sha512 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"

./gen_sig.out $DIR/priv.key scripts/hello.sh sha512 > $DIR/hello
./gen_sig.out $DIR/priv.key scripts/ls.sh sha512 > $DIR/ls
./gen_sig.out $DIR/priv.key scripts/large.sh sha512 > $DIR/large
