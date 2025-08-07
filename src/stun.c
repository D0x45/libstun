#include <stun.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2ipdef.h>
#else
#  include <netinet/in.h>
#endif // _WIN32

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

  for (i = 0; i < h->attrs_length; ++i) {
    uint16_t h_type = ntohs(*((uint16_t *)&h->attrs[i]));

    if (h_type == matching_type) {
      *dst = (struct stun_attr_s *)&h->attrs[i];
      return 0;
    }
  }

  // attribute not found or something idk
  *dst = NULL;
  return 1;
}

int stun_attr_add(struct stun_header_s **h, const struct stun_attr_s *attr) {
  struct stun_header_s *p;
  uint16_t attr_size_host, header_size_host;

  if (h == NULL || *h == NULL || attr == NULL) {
    return -1;
  }

  p = *h;
  attr_size_host = ntohs(attr->value_length) + sizeof(struct stun_attr_s);
  header_size_host = ntohs(p->attrs_length) + sizeof(struct stun_header_s);

  p = realloc(p, header_size_host + attr_size_host);
  if (p == NULL) {
    *h = NULL;
    fputs("realloc() failed!\n", stderr);
    return -2;
  }

  p->attrs_length = htons(ntohs(p->attrs_length) + attr_size_host);
  memcpy(&p->attrs[header_size_host], attr, attr_size_host);

  *h = p;
  return 0;
}

struct stun_header_s *stun_query(int sock_fd, const struct stun_header_s *req,
                                 const struct sockaddr *stun_server_addr) {
  union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
  } tmp_addr;
  struct stun_header_s *res = calloc(STUN_MAX_PACKET_LEN, 1);
  unsigned int sizeof_addr = stun_server_addr->sa_family == AF_INET6
                                 ? sizeof(struct sockaddr_in6)
                                 : sizeof(struct sockaddr_in);
  long i;

  if (stun_server_addr == NULL || req == NULL) {
    return NULL;
  }

  memset(&tmp_addr, 0, sizeof(tmp_addr));
  memcpy(&tmp_addr, stun_server_addr, sizeof_addr);

  i = sendto(sock_fd, req, sizeof(*req) + req->attrs_length, 0,
             stun_server_addr, sizeof_addr);

  if (i != (req->attrs_length + sizeof(struct stun_header_s))) {
    perror("sendto()");
    free(res);
    return NULL;
  }

  i = recvfrom(sock_fd, res, STUN_MAX_PACKET_LEN, 0,
               (struct sockaddr *)&tmp_addr, &sizeof_addr);

  if (i <= 0) {
    perror("recvfrom()");
    free(res);
    return NULL;
  }

  if (req->cookie != res->cookie) {
    fputs("stun cookie did not match!\n", stderr);
    free(res);
    return NULL;
  }

  if (memcmp(res->id, req->id, sizeof(req->id))) {
    fputs("stun transaction id did not match!\n", stderr);
    free(res);
    return NULL;
  }

  return res;
}

void stun_attr_xor_mapped_addr_to_sa(
    struct sockaddr *dst, const struct stun_attr_xor_mapped_address_s *from,
    const struct stun_header_s *response) {

  if (dst == NULL || from == NULL || response == NULL) {
    return;
  }

  memset(dst, 0, sizeof(*dst));

  if (from->family == STUN_ADDR_FAMILY_IPV4) {
    struct stun_attr_xor_mapped_address_ipv4_s *v4 =
        (struct stun_attr_xor_mapped_address_ipv4_s *)from;

    ((struct sockaddr_in *)dst)->sin_family = AF_INET;
    ((struct sockaddr_in *)dst)->sin_port =
        (v4->x_port) ^ htons(response->cookie >> 16);
    ((struct sockaddr_in *)dst)->sin_addr.s_addr =
        (v4->x_ip) ^ htonl(STUN_MAGIC_COOKIE);
    return;
  }

  // TODO: test this out! i did not test this. stole this part
  if (from->family == STUN_ADDR_FAMILY_IPV6) {
    struct stun_attr_xor_mapped_address_ipv6_s *v6 =
        (struct stun_attr_xor_mapped_address_ipv6_s *)from;

    ((struct sockaddr_in6 *)dst)->sin6_family = AF_INET6;

    memcpy(&((struct sockaddr_in6 *)dst)->sin6_addr, v6->x_ip,
           sizeof(v6->x_ip));

    // XOR first 4 bytes with magic cookie
    *((uint32_t *)(&((struct sockaddr_in6 *)dst)->sin6_addr)) ^=
        response->cookie;

    // XOR remaining 12 bytes with transaction ID
    for (int i = 4; i < 16; i++) {
      ((uint8_t *)(&((struct sockaddr_in6 *)dst)->sin6_addr))[i] ^=
          response->id[i];
    }

    return;
  }
}
