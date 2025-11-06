#include "crypto.h"

bool certcmp(byte *raw_cert, uinta start0, uinta end0, uinta start1, uinta end1) {
  uinta size = end0 - start0;
  return size == end1 - start1 && memcmp(&raw_cert[start0], &raw_cert[start1], size) == 0;
}

bool extract_self_sign(byte *raw_cert, const x509Fields *fields, time_t now, PubKey *ret_pub_key) {
  if (fields->not_before > now || fields->not_after < now || !fields->key_cert_sign) {
    return false;
  }

  if (!certcmp(raw_cert, fields->sig_id_start, fields->sig_id_end, fields->pub_key_id_start,
               fields->pub_key_id_end)) {
    return false;
  }
  bool is_skid = fields->skid_start != IDX_NONE;
  bool is_akid = fields->akid_start != IDX_NONE;
  if (is_skid != is_akid) {
    return false;
  }
  if (is_skid && is_akid &&
      !certcmp(raw_cert, fields->skid_start, fields->skid_end, fields->akid_start,
               fields->akid_end)) {
    return false;
  }

  if (!pub_key_extract(raw_cert, fields, ret_pub_key)) {
    return false;
  }

  return pub_key_verify(ret_pub_key, &raw_cert[fields->signed_data_start],
      fields->signed_data_end - fields->signed_data_start, &raw_cert[fields->sig_start],
      fields->sig_end - fields->sig_start);
}
