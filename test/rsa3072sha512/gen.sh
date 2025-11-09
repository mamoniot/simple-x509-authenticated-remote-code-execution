DIR="rsa3072sha512"

openssl req -x509 -newkey rsa:3072 -sha512 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com" -extensions code_signing -config code_signing.cnf
