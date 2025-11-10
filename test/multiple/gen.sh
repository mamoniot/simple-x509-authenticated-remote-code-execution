DIR="multiple"

openssl req -x509 -newkey ed448 -outform DER -keyout $DIR/ed448.key -out $DIR/cert/ed448.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
openssl req -x509 -newkey ed25519 -outform DER -keyout $DIR/ed25519.key -out $DIR/cert/ed25519.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing_alt -config code_signing.cnf
openssl req -x509 -newkey rsa:4096 -sha384 -outform DER -keyout $DIR/rsa4096.key -out $DIR/cert/rsa4096.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
