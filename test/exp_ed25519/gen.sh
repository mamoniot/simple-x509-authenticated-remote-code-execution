DIR="exp_ed25519"

openssl req -x509 -newkey ed25519 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 1 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"

./gen_sig.out $DIR/priv.key scripts/hello.sh > $DIR/hello
./gen_sig.out $DIR/priv.key scripts/ls.sh > $DIR/ls
./gen_sig.out $DIR/priv.key scripts/large.sh > $DIR/large
