#ifndef IPROUTE_MPLS_H
#define IPROUTE_MPLS_H

#ifndef AF_MPLS
#define AF_MPLS 28
#endif
#ifndef PF_MPLS
#define PF_MPLS AF_MPLS
#endif

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
  {RTPROT_XORP,		"XORP"},
  {0,               NULL}
};

extern int print_ilm(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb);
extern int print_xc(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb);
extern int print_labelspace(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb);
extern int print_nhlfe(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb);

#define GENL_MAX_FAM_GRPS	256

#endif
