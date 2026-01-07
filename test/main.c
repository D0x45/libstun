#include <stddef.h>
#include <stdio.h>

#include <stun.h>

int main(int argc, const char **argv)
{
  (void)argc;
  (void)argv;

  struct stun_header_s *h;

  struct stun_attr_even_port_s a0;
  struct stun_attr_dont_fragment_s a1;
  struct stun_attr_reservation_token_s a2;

  h = stun_header_new(STUN_HTYPE_BINDING_REQUEST, NULL);

  stun_attr_even_port(&a0, STUN_EVEN_PORT_TRUE);
  stun_attr_dont_fragment(&a1);
  stun_attr_reservation_token(&a2, NULL);

  stun_attr_add(&h, (const struct stun_attr_s *)&a0);
  stun_attr_add(&h, (const struct stun_attr_s *)&a1);
  stun_attr_add(&h, (const struct stun_attr_s *)&a2);

  return 0;
}
