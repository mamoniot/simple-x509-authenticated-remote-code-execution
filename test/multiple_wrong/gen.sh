DIR="multiple_wrong"

openssl req -x509 -newkey ed448 -outform DER -keyout $DIR/ed448.key -out $DIR/cert.der/ed448.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
openssl req -x509 -newkey ed25519 -outform DER -keyout $DIR/wrong_ed25519.key -out $DIR/cert.der/wrong_ed25519.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions wrong_code -config code_signing.cnf
openssl req -x509 -newkey rsa:4096 -sha384 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der/rsa4096.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
openssl req -x509 -newkey rsa:3072 -sha384 -outform DER -keyout $DIR/wrong_rsa3072.key -out $DIR/cert.der/wrong_rsa3072.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions wrong_code -config code_signing.cnf
