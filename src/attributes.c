#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <stun.h>

void stun_attr_xor_mapped_addr_to_sa(
    struct sockaddr_in *dst, const struct stun_attr_xor_mapped_addr_s *from) {
  struct stun_attr_xor_mapped_addr_ipv4_s *v4 =
      (struct stun_attr_xor_mapped_addr_ipv4_s *)from;

  if (dst == NULL || from == NULL) {
    return;
  }

  memset(dst, 0, sizeof(*dst));

  if (from->family != STUN_ADDR_FAMILY_IPV4) {
    return;
  }

  ((struct sockaddr_in *)dst)->sin_family = AF_INET;
  ((struct sockaddr_in *)dst)->sin_port =
      (v4->x_port) ^ htons(STUN_MAGIC_COOKIE >> 16);
  ((struct sockaddr_in *)dst)->sin_addr.s_addr =
      (v4->x_ip) ^ htonl(STUN_MAGIC_COOKIE);

}

void stun_attr_xor_mapped_addr(struct stun_attr_xor_mapped_addr_s *dst,
    const struct sockaddr_in *src_sa) {
  struct stun_attr_xor_mapped_addr_ipv4_s *p4 =
                  (struct stun_attr_xor_mapped_addr_ipv4_s *)dst;
  struct sockaddr_in *sa4 = (struct sockaddr_in *)src_sa;

  memset(dst, 0, sizeof(*p4));

  if (src_sa->sin_family != AF_INET) {
    return;
  }

  p4->type = htons(STUN_ATTR_XOR_MAPPED_ADDR);
  p4->family = STUN_ADDR_FAMILY_IPV4;
  p4->value_length = 8;
  p4->x_port = sa4->sin_port ^ htons(STUN_MAGIC_COOKIE >> 16);
  p4->x_ip = sa4->sin_addr.s_addr ^ htonl(STUN_MAGIC_COOKIE);
}

void stun_attr_dont_fragment(struct stun_attr_dont_fragment_s *dst)
{
  dst->type = htons(STUN_ATTR_DONT_FRAGMENT);
  dst->value_length = 0;
  dst->__pad1 = 0;
}

void stun_attr_requested_transport(struct stun_attr_requested_transport_s *dst)
{
  dst->type = htons(STUN_ATTR_REQUESTED_TRANSPORT);
  dst->protocol = 17; // the only value allowed
  dst->rffu[0] = 0;
  dst->rffu[1] = 0;
  dst->rffu[2] = 0;
}

void stun_attr_reservation_token(struct stun_attr_reservation_token_s *src,
                                const uint8_t *token)
{
  src->type = htons(STUN_ATTR_RESERATION_TOKEN);
  src->value_length = 8;
  memcpy(src->token, token, sizeof(src->token));
}
