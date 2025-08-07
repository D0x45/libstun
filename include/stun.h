// TODO: https://www.rfc-editor.org/rfc/rfc8656

#ifndef __STUN_H__
#define __STUN_H__

#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2ipdef.h>
#else
#  include <netinet/in.h>
#endif // _WIN32

// just in case other compilers don't support this syntax
#if defined(__clang__) || defined(__cplusplus)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wfixed-enum-extension"
#  define FIXED_ENUM_32 : uint32_t
#  define FIXED_ENUM_16 : uint16_t
#  define FIXED_ENUM_8  : uint8_t
#endif // defined(__clang__) || defined(__cplusplus)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// general-purpose constants
enum FIXED_ENUM_32 {
  STUN_MAX_PACKET_LEN = 508,
  STUN_MAGIC_COOKIE = 0x2112A442,
};

// stun header type
enum stun_htype_e FIXED_ENUM_16 {
  STUN_HTYPE_BINDING_REQUEST = 0x0001,
  STUN_HTYPE_BINDING_RESPONSE = 0x0101,
};

// stun attribute type
enum stun_attr_e FIXED_ENUM_16 {
  STUN_ATTR_XOR_MAPPED_ADDR = 0x0020,
  STUN_ATTR_USERNAME = 0x0006,
  STUN_ATTR_MSG_INTEGRITY = 0x0008,
  STUN_ATTR_FINGERPRINT = 0x8028,
  STUN_ATTR_SERVER = 0x8022,
};

enum stun_addr_family_e FIXED_ENUM_8 {
  STUN_ADDR_FAMILY_IPV4 = 0x01,
  STUN_ADDR_FAMILY_IPV6 = 0x02,
};

// all values must be stored in network byte order
struct stun_attr_s {
  uint16_t type;
  // value length is a multiple of 4.
  uint16_t value_length;
  uint8_t value[];
};

// all values must be stored in network byte order
struct stun_attr_xor_mapped_address_s {
  uint16_t type;
  uint16_t value_length;
  uint8_t __pad1;
  uint8_t family;
  // safe amount of padding for max size of both ipv6 and ipv4
  uint8_t __pad2[18];
};

// all values must be stored in network byte order
struct stun_attr_xor_mapped_address_ipv4_s {
  uint16_t type;
  uint16_t value_length;
  uint8_t __pad1;
  uint8_t family;
  uint16_t x_port;
  uint32_t x_ip;
};

// all values must be stored in network byte order
struct stun_attr_xor_mapped_address_ipv6_s {
  uint16_t type;
  uint16_t value_length;
  uint8_t __pad1;
  uint8_t family;
  uint16_t x_port;
  uint8_t x_ip[16];
};

// all fields must be stored in network byte order
struct stun_header_s {
  uint16_t type;
  // total length of the attributes starting after field `id` in bytes
  uint16_t attrs_length;
  uint32_t cookie;
  uint8_t id[12];
  uint8_t attrs[];
};

// allocate a new stun header with the given type
struct stun_header_s *stun_header_new(enum stun_htype_e type,
                                      const uint8_t *id);

void stun_header_free(struct stun_header_s *);

// get the pointer to an attribute in a message
// returns 0 on success. *dst must be a valid allocated memory.
int stun_attr_get(struct stun_attr_s /*const*/ **dst,
                  enum stun_attr_e matching_type,
                  const struct stun_header_s *h);

// append an attribute to the result.
// this function might resize the memory buffer.
int stun_attr_add(struct stun_header_s **h, const struct stun_attr_s *attr);

// write a stun message to the udp socket and block-wait for result!
struct stun_header_s *stun_query(int sock_fd, const struct stun_header_s *req,
                                 const struct sockaddr *stun_server_addr);

// convert the *nb_stun_attr_xor_mapped_address_t values to sockaddr
// make sure dst* has enough size for the attribute ip family!
void stun_attr_xor_mapped_addr_to_sa(
    struct sockaddr *dst, const struct stun_attr_xor_mapped_address_s *from,
    const struct stun_header_s *response);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __STUN_H__
