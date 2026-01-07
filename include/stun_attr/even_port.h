#include <stdint.h>

#include "../stun_common.h"

enum stun_attr_even_port_e STUN_FIXED_ENUM_8 {
  STUN_EVEN_PORT_TRUE  = 0x80,
  STUN_EVEN_PORT_FALSE = 0x00,
};

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
//
// This attribute allows the client to request that the port in the
// relayed transport address be even, and (optionally) that the server
// reserve the next-higher port number. The value portion of this
// attribute is 1 byte long.
// The value contains a single 1-bit flag:
// R: If 1, the server is requested to reserve the next-higher port
// number (on the same IP address) for a subsequent allocation. If
// 0, no such reservation is requested.
// The other 7 bits of the attribute’s value must be set to zero on
// transmission and ignored on reception.
// Since the length of this attribute is not a multiple of 4, padding
// must immediately follow this attribute.
struct stun_attr_even_port_s {
  uint16_t type; // STUN_ATTR_EVEN_PORT
  uint16_t value_length; // 1
  uint8_t  flag; // STUN_EVEN_PORT_TRUE or STUN_EVEN_PORT_FALSE
  uint8_t  __pad[3]; // padding is present in req/response
};

// initialize the struct with given values to correct values.
void stun_attr_even_port(struct stun_attr_even_port_s *dst,
      enum stun_attr_even_port_e flag);
