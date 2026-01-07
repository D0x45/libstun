#ifndef __STUN_COMMON_H__
#define __STUN_COMMON_H__

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
#  define STUN_FIXED_ENUM_32 : uint32_t
#  define STUN_FIXED_ENUM_16 : uint16_t
#  define STUN_FIXED_ENUM_8  : uint8_t
#endif // defined(__clang__) || defined(__cplusplus)

#if defined(NDEBUG)
#  define STUN_TRACE(...)
#else
#  include <stdio.h>
#  define STUN_STR2(B) #B
#  define STUN_STR1(A) STUN_STR2(A)
// clang __FILE_NAME__ is much cleaner :p
#  ifdef __FILE_NAME__
#    define STUN_TRACE(...) \
            fprintf(stdout, "[" __FILE_NAME__ ":" STUN_STR1(__LINE__) \
            "] " __VA_ARGS__);
#  else
#    define STUN_TRACE(...) \
            fprintf(stdout, "[" __FILE__ ":" STUN_STR1(__LINE__) \
            "] " __VA_ARGS__);
#  endif //__FILE_NAME__
#endif

// general-purpose constants
enum {
  // All STUN messages sent over UDP SHOULD be less than the path MTU, if
  // known. If the path MTU is unknown, messages SHOULD be the smaller of
  // 576 bytes and the first-hop MTU for IPv4 [RFC1122] and 1280 bytes for
  // IPv6 [RFC2460]. This value corresponds to the overall size of the IP
  // packet. Consequently, for IPv4, the actual STUN message would need
  // to be less than 548 bytes (576 minus 20-byte IP header, minus 8-byte
  // UDP header, assuming no IP options are used)
  STUN_MAX_PACKET_LEN = 548,
  STUN_MAGIC_COOKIE = 0x2112A442,
  STUN_PROTOCOL = 17,
};

// stun header type
enum stun_htype_e STUN_FIXED_ENUM_16 {
  STUN_HTYPE_BINDING_REQUEST  = 0x0001,
  STUN_HTYPE_ALLOCATE_REQUEST = 0x0003,
  STUN_HTYPE_REFRESH_REQUEST = 0x0004,
  STUN_HTYPE_CREATE_PERMISSION_REQUEST = 0x0008,
  STUN_HTYPE_CHANNEL_BIND_REQUEST = 0x0009,
  STUN_HTYPE_SEND_INDICATION = 0x0016,
  STUN_HTYPE_DATA_INDICATION = 0x0017,
  STUN_HTYPE_BINDING_RESPONSE = 0x0101,
  STUN_HTYPE_ALLOCATE_RESPONSE = 0x0103,
  STUN_HTYPE_REFRESH_RESPONSE = 0x0104,
  STUN_HTYPE_CREATE_PERMISSION_RESPONSE = 0x0108,
  STUN_HTYPE_CHANNEL_BIND_RESPONSE = 0x0109,
};

enum stun_err_e STUN_FIXED_ENUM_16 {
  STUN_ERR_BAD_REQUEST = 400,
  STUN_ERR_UNAUTHORIZED = 401,
  STUN_ERR_FORBIDDEN = 403,
  STUN_ERR_UNKNOWN_ATTR = 420,
  STUN_ERR_ALLOCATION_MISMATCH = 437,
  STUN_ERR_WRONG_CREDENTIALS = 441,
  STUN_ERR_UNSUPPORTED_PROTOCOL = 442,
  STUN_ERR_ALLOCATION_QUOTA = 486,
  STUN_ERR_INSUFFICIENT_CAPACITY = 508,
};

// stun attribute type
enum stun_attr_e STUN_FIXED_ENUM_16 {
  STUN_ATTR_MAPPED_ADDR = 0x0001,
  STUN_ATTR_XOR_MAPPED_ADDR = 0x0020,
  STUN_ATTR_USERNAME = 0x0006,
  STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
  STUN_ATTR_FINGERPRINT = 0x8028,
  STUN_ATTR_SERVER = 0x8022,
  STUN_ATTR_CHANNEL_NUMBER = 0x000C,
  STUN_ATTR_LIFETIME = 0x000D,
  STUN_ATTR_DATA = 0x0013,
  STUN_ATTR_XOR_RELAYED_ADDR = 0x0016,
  STUN_ATTR_EVEN_PORT = 0x0018,
  STUN_ATTR_REQUESTED_TRANSPORT = 0x0019,
  STUN_ATTR_DONT_FRAGMENT = 0x001A,
  STUN_ATTR_RESERATION_TOKEN = 0x0022,
  STUN_ATTR_ERROR_CODE = 0x0009,
  STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A,
  STUN_ATTR_REALM = 0x0014,
  STUN_ATTR_NONCE = 0x0015,
  STUN_ATTR_SOFTWARE = 0x8022,
};

enum stun_addr_family_e STUN_FIXED_ENUM_8 {
  STUN_ADDR_FAMILY_IPV4 = 0x01,
  STUN_ADDR_FAMILY_IPV6 = 0x02,
};

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
//
// Some of these attributes have lengths that are not multiples of 4.
// By the rules of STUN, any attribute whose length is not a multiple of
// 4 bytes MUST be immediately followed by 1 to 3 padding bytes to
// ensure the next attribute (if any) would start on a 4-byte boundary
// (see [RFC5389]).
struct stun_attr_s {
  uint16_t type; // stun_attr_e
  uint16_t value_length;
  uint8_t  value[];
};

// *ALL STRUCT FIELDS ARE STORED IN NETWORK BYTE-ORDER*
struct stun_header_s {
  uint16_t type;
  // The message length MUST contain the size, in bytes, of the message
  // not including the 20-byte STUN header. Since all STUN attributes are
  // padded to a multiple of 4 bytes, the last 2 bits of this field are
  // always zero. This provides another way to distinguish STUN packets
  // from packets of other protocols.
  uint16_t attrs_length;
  uint32_t cookie; // STUN_MAGIC_COOKIE
  uint8_t  id[12];
  uint8_t  attrs[];
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
// this function may realloc() the memory buffer.
int stun_attr_add(struct stun_header_s **h, const struct stun_attr_s *attr);

#endif // __STUN_COMMON_H__
