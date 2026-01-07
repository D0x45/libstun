#include <stdint.h>

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
struct stun_attr_requested_transport_s {
  uint16_t type; // STUN_ATTR_REQUESTED_TRANSPORT
  uint16_t value_length; // 4
  // The Protocol field specifies the desired protocol. The codepoints
  // used in this field are taken from those allowed in the Protocol field
  // in the IPv4 header and the NextHeader field in the IPv6 header
  // [Protocol-Numbers]. This specification only allows the use of
  // codepoint 17 (User Datagram Protocol).
  uint8_t  protocol;
  // The RFFU field MUST be set to zero on transmission and MUST be
  // ignored on reception. It is reserved for future uses.
  uint8_t  rffu[3];
};

void stun_attr_requested_transport(struct stun_attr_requested_transport_s *dst);
