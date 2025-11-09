DIR="ed448"

openssl req -x509 -newkey ed448 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"

./gen_sig.out $DIR/priv.key scripts/hello.sh > $DIR/hello
./gen_sig.out $DIR/priv.key scripts/ls.sh > $DIR/ls
./gen_sig.out $DIR/priv.key scripts/large.sh > $DIR/large
