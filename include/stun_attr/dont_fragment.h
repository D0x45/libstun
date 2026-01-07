#include <stdint.h>

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
//
// This attribute is used by the client to request that the server set
// the DF (Don’t Fragment) bit in the IP header when relaying the
// application data onward to the peer. This attribute has no value
// part and thus the attribute length field is 0.
struct stun_attr_dont_fragment_s {
  uint16_t type; // STUN_ATTR_DONT_FRAGMENT
  uint16_t value_length; // 0
  uint32_t __pad1; // TODO: make sure this padding is actually necessary?
};

// initialize the atrtibute struct with correct values
void stun_attr_dont_fragment(struct stun_attr_dont_fragment_s *dst);
