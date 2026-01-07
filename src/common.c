#include <stun.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void _stun_transaction_id_new(uint8_t *id) {
  for (int i = 0; i < 8; i++) {
    id[i] = random() & 0xff;
  }
}

struct stun_header_s *stun_header_new(enum stun_htype_e type,
                                      const uint8_t *id) {
  struct stun_header_s *req = calloc(1, sizeof(struct stun_header_s));

  if (req == NULL) {
    fputs("calloc() failed!\n", stderr);
    return NULL;
  }

  req->cookie = htonl(STUN_MAGIC_COOKIE);
  req->type = htons(type);

  if (id == NULL) {
    _stun_transaction_id_new(req->id);
  } else {
    memcpy(req->id, id, sizeof(req->id));
  }

  return req;
}

void stun_header_free(struct stun_header_s *p) { free(p); }

int stun_attr_get(struct stun_attr_s /*const*/ **dst,
                  enum stun_attr_e matching_type,
                  const struct stun_header_s *h) {
  int i;

  for (i = 0; i < h->attrs_length; ) {
    struct stun_attr_s *a = (struct stun_attr_s*)&h->attrs[i];
    uint16_t type_h = ntohs(a->type);
    uint16_t value_len_h = ntohs(a->value_length);

    STUN_TRACE("attrs[byte_offset=%d] = { .type: %u, .value_length: %u };\n", i,
                type_h, value_len_h);

    if (type_h == matching_type) {
      *dst = a;
      return 0;
    }

    value_len_h = sizeof(struct stun_attr_s) + value_len_h;
    if (value_len_h & 3) {
      // account for the padding of certain attributes that have a
      // non-divisble-by-4 length. the padding is there. but the value_length
      // is reporting a value less than or non disible by 4
      value_len_h += ((4 - (value_len_h % 4)) % 4);
      STUN_TRACE("attr_size padded to 4-byte boundry = %u\n", value_len_h);
    }

    i += value_len_h;
  }

  // attribute not found or something, idk
  *dst = NULL;
  return 1;
}

int stun_attr_add(struct stun_header_s **h, const struct stun_attr_s *attr) {
  struct stun_header_s *p;
  uint16_t attr_length_h, attrs_length_h, next_size;

  STUN_TRACE("stun_attr_add(h: %p, attr: %p)\n", (void*)h, (void*)attr);

  if (h == NULL || *h == NULL || attr == NULL) {
    return -1;
  }

  p = *h;
  attr_length_h  = sizeof(struct stun_attr_s) + ntohs(attr->value_length);
  attrs_length_h = ntohs(p->attrs_length);

  // Some of these attributes have lengths that are not multiples of 4.
  // By the rules of STUN, any attribute whose length is not a multiple of
  // 4 bytes MUST be immediately followed by 1 to 3 padding bytes to
  // ensure the next attribute (if any) would start on a 4-byte boundary
  // (see [RFC5389]).
  if (attr_length_h & 3) {
    attr_length_h += (4 - (attr_length_h % 4)) % 4;
    STUN_TRACE("attr_length padded to 4-byte boundry = %u\n", attr_length_h);
  }

  STUN_TRACE("attrs_length = %u, attr_size = %u\n", attrs_length_h,
              attr_length_h);

  p->attrs_length = htons(attrs_length_h + attr_length_h);

  next_size = sizeof(struct stun_header_s) + attrs_length_h + attr_length_h;
  STUN_TRACE("realloc next_size= %u\n", next_size);

  p = realloc(p, next_size);
  if (p == NULL) {
    *h = NULL;
    fputs("realloc() failed!\n", stderr);
    return -2;
  }

  memcpy(&p->attrs[attrs_length_h], attr, attr_length_h);

  *h = p;
  return 0;
}
