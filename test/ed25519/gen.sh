DIR="ed25519"

openssl req -x509 -newkey ed25519 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
