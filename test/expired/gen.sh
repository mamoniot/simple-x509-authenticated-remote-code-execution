DIR="expired"

openssl req -x509 -newkey ed25519 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 1 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
