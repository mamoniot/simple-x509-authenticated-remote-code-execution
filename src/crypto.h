#include "basic.h"
#include "x509.h"

typedef struct PubKey PubKey;

bool extract_self_sign(byte *raw_cert, const x509Fields *fields, time_t now, PubKey *ret_pub_key);

bool pub_key_verify(PubKey *pub_key, const byte *data, uinta data_size, const byte *sig,
                    uinta sig_size);
