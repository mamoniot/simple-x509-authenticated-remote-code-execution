#include "basic.h"

const uinta IDX_NONE = 0;

typedef struct {
  uinta sig_id_start;
  uinta sig_id_end;

  uinta sig_oid_start;
  uinta sig_oid_end;

  uinta sig_start;
  uinta sig_end;

  uinta pub_key_id_start;
  uinta pub_key_id_end;

  uinta pub_key_oid_start;
  uinta pub_key_oid_end;

  uinta pub_key_start;
  uinta pub_key_end;

  uinta signed_data_start;
  uinta signed_data_end;

  time_t not_before;
  time_t not_after;

  uinta skid_start;
  uinta skid_end;

  uinta akid_start;
  uinta akid_end;

  bool key_cert_sign;
  uint32 path_len_constraint;
} x509;
