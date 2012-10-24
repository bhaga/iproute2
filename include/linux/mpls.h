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

/*based on netlink_group_mask from net/netlink/af_netlink.c */
#define _group_mask(group_id) ((group_id) ? 1 << ((group_id) - 1) : 0)

#define MPLS_NETLINK_NAME "nlmpls"
#define MPLS_MC_GRP_NAME "mpls_mcast_grp"

enum mpls_change {
	MPLS_CHANGE_MTU = 0x1,
	MPLS_CHANGE_INSTR = (0x1 << 1),
};

enum mpls_opcode_enum {
	MPLS_OP_DROP = 0x00,
	MPLS_OP_POP,
	MPLS_OP_PEEK,
	MPLS_OP_PUSH,
	MPLS_OP_SWAP,
	MPLS_OP_SEND_IPv4,
	MPLS_OP_SEND_IPv6,
	MPLS_OP_SET_TC_INDEX,
	MPLS_OP_SET_DS,
	__MPLS_OP_MAX
};

#define MPLS_HDR_LEN (sizeof(u32))

struct mpls_nh {
	__u32 iface;
	union {
		struct sockaddr addr;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};

struct mpls_push {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u32 label_u:4;
	__u32 label_l:16;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u32 label_l:16;
	__u32 label_u:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8 tc:3;
	__u16 pad:9;
};

struct ilm_key {
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			__u32 label_u:4;
			__u32 label_l:16;
#elif defined (__BIG_ENDIAN_BITFIELD)
			__u32 label_l:16;
			__u32 label_u:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
			__u32 __pad:12;
		};
		struct {
			__u32 label:20;
			__u16 ls:12;
		};
	};
};

struct instr_req {
	__u16 opcode;
	union {
		struct mpls_push push;
		__u16 pop;
		__u16 tc_index;
		__u16 dscp;
		struct mpls_nh nh;
	};
};

struct ilm_req {
	struct ilm_key label;
	__u8 change_flag;
	__u8 tc;
	__u8 owner;   /* Routing protocol */
};

struct nhlfe_req {
	__u8 instr_length;
	struct instr_req instr[0];
};

struct ls_req {
	int ifindex;
	int ls;
};

struct mpls_tunnel_req {
	char ifname[IFNAMSIZ];
	__u32 nhlfe_key;
};

/*2^12 - 1 (0xfff)*/
#define MPLS_LS_MAX ((1 << 12) - 2)
#define INACTIVE_LS (-1)
#define DEFAULT_LS ((1 << 12) - 1)

/* genetlink interface */
enum {
	MPLS_CMD_UNSPEC,
	MPLS_CMD_NEWILM,
	MPLS_CMD_DELILM,
	MPLS_CMD_GETILM,
	MPLS_CMD_SETLS,
	MPLS_CMD_GETLS,
	__MPLS_CMD_MAX,
};

enum {
	MPLS_ATTR_UNSPEC,
	MPLS_ATTR_ILM,
	MPLS_ATTR_INSTR,
	MPLS_ATTR_LS,
	__MPLS_ATTR_MAX,
};

#define key_ls(key)																			\
	((__u32)(key)->ls)

#define key_label(key)																		\
	((__u32)(key)->label)

#define set_key_ls(key, _ls)																\
	((key)->ls = (_ls))

#define set_key_label_2(key, _label_l, _label_u)											\
do {																						\
	(key)->label_l = (_label_l);															\
	(key)->label_u = (_label_u);															\
} while(0)

#define set_key_label(key, _label)															\
	((key)->label = (_label))

#endif
