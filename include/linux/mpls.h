/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *          Igor Maravic     <igorm@etf.rs> - Innovation Center, School of Electrical Engineering in Belgrade
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>
 *   (c) 2003-2004   Ramon Casellas   <casellas@infres.enst.fr>
 *   (c) 2011-2012   Igor Maravic     <igorm@etf.rs>
 *
 * include/linux/mpls.h
 *      Data types and structs used by userspace programs to access MPLS
 *      forwarding. Most interface with the MPLS subsystem is IOCTL based
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
****************************************************************************/

#ifndef _LINUX_MPLS_H_
#define _LINUX_MPLS_H_

#include <asm/byteorder.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#if defined __KERNEL__ || (!(defined __KERNEL__) && !(defined _NET_IF_H))
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#if defined __KERNEL__
#include <linux/in.h>
#include <linux/in6.h>
#endif

/**
*MPLS DEBUGGING
**/

#define MPLS_LINUX_VERSION (0x01090100)

#define MPLS_HDR_LEN (sizeof(u32))

#define TC_MAX ((1 << 3) - 1)
#define DSCP_MAX ((1 << 8) - 1)

struct mpls_nh {
	__u32 iface;
	union {
		struct sockaddr addr;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};

struct mpls_key {
	__u32 label:20;
	__u8 tc:3;
	__u16 __pad:9;
};

struct ilmsg {
	union {
		struct {
			__u8 family;
			__u8 tc;
			__u8 owner;   /* Routing protocol */
			struct mpls_key key;
		};
		/* padding to pass rtnetlink min_len check */
		struct rtmsg __pad;
	};
};

enum {
	MPLS_ATTR_PUSH_UNSPEC,
	MPLS_PUSH_1,
	MPLS_PUSH_2,
	MPLS_PUSH_3,
	MPLS_PUSH_4,
	MPLS_PUSH_5,
	MPLS_PUSH_6,
	MPLS_NO_PUSHES,
#define MPLS_PUSH_MAX MPLS_NO_PUSHES
	__MPLS_ATTR_PUSH_MAX,
};
#define MPLS_ATTR_PUSH_MAX (__MPLS_ATTR_PUSH_MAX - 1)

enum {
	MPLS_ATTR_UNSPEC,
	MPLS_ATTR_POP,
	MPLS_ATTR_DSCP,
	MPLS_ATTR_TC_INDEX,
	MPLS_ATTR_SWAP,
	MPLS_ATTR_PUSH,
	MPLS_ATTR_PEEK, /* must be last instruction */
	MPLS_ATTR_DROP, /* must be last instruction */
	MPLS_ATTR_SEND_IPv4, /* must be last instruction */
	MPLS_ATTR_SEND_IPv6, /* must be last instruction */
	MPLS_ATTR_INSTR_COUNT, /* not a instruction */
#define MPLS_ATTR_INSTR_MAX MPLS_ATTR_INSTR_COUNT
	__MPLS_ATTR_MAX,
};
#define MPLS_ATTR_MAX (__MPLS_ATTR_MAX - 1)

#endif
