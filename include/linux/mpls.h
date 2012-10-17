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

#define MPLS_LINUX_VERSION	0x01090910

/*based on netlink_group_mask from net/netlink/af_netlink.c */
#define _group_mask(group_id) group_id ? 1 << (group_id - 1) : 0

#define MPLS_NETLINK_NAME "nlmpls"
#define MPLS_MC_GRP_NAME "mpls_mcast_grp"

enum mpls_change {
	MPLS_CHANGE_MTU = 0x1,
	MPLS_CHANGE_PROP_TTL = (0x1 << 1),
	MPLS_CHANGE_INSTR = (0x1 << 2),
};

enum mpls_dir {
	MPLS_IN = 0x10,
	MPLS_OUT = 0x20
};

enum mpls_opcode_enum {
	MPLS_OP_DROP = 0x00,
	MPLS_OP_POP,
	MPLS_OP_PEEK,
	MPLS_OP_PUSH,
	MPLS_OP_FWD,
	MPLS_OP_SET,
	MPLS_OP_SET_TC,
	MPLS_OP_SET_DS,
	MPLS_OP_SET_EXP,
	MPLS_OP_EXP2TC,
	MPLS_OP_EXP2DS,
	MPLS_OP_TC2EXP,
	MPLS_OP_DS2EXP,
	MPLS_OP_NF2EXP,
	__MPLS_OP_MAX
};

#define MPLS_HDR_LEN 4

struct mpls_in_label_req {
	__u32 label;
	__u8 change_flag;
	__u8 owner;   /* Routing protocol */
};

/*2^12 - 1 (0xfff)*/
#define MPLS_LS_MAX ((1 << 12) - 2)
#define INACTIVE_LS (-1)
#define DEFAULT_LS ((1 << 12) - 1)

struct mpls_ls_req {
	int ifindex;                  /* Index to the MPLS-enab. interface*/
	int ls;               /* Labelspace IN/SET -- OUT/GET     */
};

struct mpls_nexthop_info {
	__u32 iface;
	union {
		struct sockaddr addr;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};

struct mpls_out_label_req {
	__u32 label;
	__u32 mtu;
	__u8 propagate_ttl;
	__u8 change_flag;
	__u8 owner;        /* Routing protocol */
};

struct mpls_xconnect_req {
	__u32 in;
	__u32 out;
	__u8 owner;        /* Routing protocol */
};

struct mpls_tunnel_req {
	char ifname[IFNAMSIZ];
	__u32 nhlfe_key;
};

#define MPLS_NFMARK_NUM 64
#define MPLS_DSMARK_NUM 64
#define MPLS_TCINDEX_NUM 64
#define MPLS_EXP_NUM 8

struct mpls_exp2tcindex {
	__u16 data[MPLS_EXP_NUM];
};

struct mpls_exp2dsmark {
	__u8 data[MPLS_EXP_NUM];
};

struct mpls_tcindex2exp {
	__u8 mask;
	__u8 data[MPLS_TCINDEX_NUM];
};

struct mpls_dsmark2exp {
	__u8 mask;
	__u8 data[MPLS_DSMARK_NUM];
};

struct mpls_nfmark2exp {
	__u8 mask;
	__u8 data[MPLS_NFMARK_NUM];
};

struct mpls_instr_elem {
	__u16 opcode;
	__u8 direction;
	union {
		__u32 push;
		__u32 fwd;
		struct mpls_nexthop_info set;
		__u32 set_rx;
		__u16 set_tc;
		__u16 set_ds;
		__u8 set_exp;
		struct mpls_exp2tcindex exp2tc;
		struct mpls_exp2dsmark exp2ds;
		struct mpls_tcindex2exp tc2exp;
		struct mpls_dsmark2exp ds2exp;
		struct mpls_nfmark2exp nf2exp;
	};
};

struct mpls_instr_req {
	__u8 instr_length;
	__u8 direction;
	struct mpls_instr_elem instr[0];
};

/* genetlink interface */
enum {
	MPLS_CMD_UNSPEC,
	MPLS_CMD_NEWILM,
	MPLS_CMD_DELILM,
	MPLS_CMD_GETILM,
	MPLS_CMD_NEWNHLFE,
	MPLS_CMD_DELNHLFE,
	MPLS_CMD_GETNHLFE,
	MPLS_CMD_NEWXC,
	MPLS_CMD_DELXC,
	MPLS_CMD_GETXC,
	MPLS_CMD_SETLS,
	MPLS_CMD_GETLS,
	__MPLS_CMD_MAX,
};

enum {
	MPLS_ATTR_UNSPEC,
	MPLS_ATTR_ILM,
	MPLS_ATTR_NHLFE,
	MPLS_ATTR_XC,
	MPLS_ATTR_LS,
	MPLS_ATTR_INSTR,
	__MPLS_ATTR_MAX,
};

#define key_ls(key)																			\
	(((__u32)(key) & ((__u32)(0xfff) << 20)) >> 20)
#define key_label(key)																		\
	((__u32)(key) & ((__u32)(0xfffff)))

#define set_key_ls(key, ls)																	\
	(key) = (__u32)(((__u32)(key) & ~((__u32)(0xfff) << 20)) | (((ls) & (__u32)(0xfff)) << 20))
#define set_key_label(key, label)															\
	(key) = (__u32)(((__u32)(key) & ~((__u32)(0xfffff))) | ((label) & (__u32)(0xfffff)))

#endif
