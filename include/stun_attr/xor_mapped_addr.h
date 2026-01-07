#include <stdint.h>

#include "../stun_common.h"

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
struct stun_attr_xor_mapped_addr_s {
  uint16_t type; // STUN_ATTR_XOR_MAPPED_ADDR
  uint16_t value_length; // 12 for ipv4, 24 for ipv6
  uint8_t  __pad1;
  uint8_t  family; // STUN_ADDR_FAMILY_IPV4 or STUN_ADDR_FAMILY_IPV6
  uint8_t  __pad2[18];
};

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
struct stun_attr_xor_mapped_addr_ipv4_s {
  uint16_t type; // STUN_ATTR_XOR_MAPPED_ADDR
  uint16_t value_length; // 8
  uint8_t  __pad1;
  uint8_t  family; // STUN_ADDR_FAMILY_IPV4
  uint16_t x_port;
  uint32_t x_ip;
};

// convert the *stun_attr_xor_mapped_addr_s values to sockaddr
// make sure dst* has enough size for the attribute's ip family!
void stun_attr_xor_mapped_addr_to_sa(
    struct sockaddr_in *dst, const struct stun_attr_xor_mapped_addr_s *from);

// fill the values of the XOR_MAPPED_ADDR attribute according to the given src.
// if src is NULL, then attribute's sa will be 0.0.0.0:0.
// a header is required if using an ipv6 sockaddr. (transaction id needed).
// if using an ipv4 sockaddr. the header is not required.
void stun_attr_xor_mapped_addr(struct stun_attr_xor_mapped_addr_s *dst,
    const struct sockaddr_in *src_sa);
