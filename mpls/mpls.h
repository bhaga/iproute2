#ifndef IPROUTE_MPLS_H
#define IPROUTE_MPLS_H

/* Message structure. */
struct message
{
  int key;
  const char *str;
};

static const struct message rtproto_str[] = {
  {RTPROT_REDIRECT, "redirect"},
  {RTPROT_KERNEL,   "kernel"},
  {RTPROT_BOOT,     "boot"},
  {RTPROT_STATIC,   "static"},
  {RTPROT_GATED,    "GateD"},
  {RTPROT_RA,       "router advertisement"},
  {RTPROT_MRT,      "MRT"},
  {RTPROT_ZEBRA,    "Zebra"},
  {RTPROT_BIRD,     "BIRD"},
  {RTPROT_XORP,     "XORP"},
  {0,               NULL}
};

#endif
