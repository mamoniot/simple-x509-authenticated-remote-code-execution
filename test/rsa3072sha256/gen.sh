DIR="rsa3072sha256"

openssl req -x509 -newkey rsa:3072 -sha256 -outform DER -keyout $DIR/priv.key -out $DIR/cert.der -days 365 -noenc -subj "/C=CA/ST=Ontario/O=Canonical/CN=canonical.com"
