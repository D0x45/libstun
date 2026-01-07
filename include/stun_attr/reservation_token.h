#include <stdint.h>

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
//
// The RESERVATION-TOKEN attribute contains a token that uniquely
// identifies a relayed transport address being held in reserve by the
// server. The server includes this attribute in a success response to
// tell the client about the token, and the client includes this
// attribute in a subsequent Allocate request to request the server use
// that relayed transport address for the allocation.
struct stun_attr_reservation_token_s {
  uint16_t type; // STUN_ATTR_RESERATION_TOKEN
  uint16_t value_length; // 8
  uint8_t  token[8];
};

void stun_attr_reservation_token(struct stun_attr_reservation_token_s *src,
                                const uint8_t *token);
