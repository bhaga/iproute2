/*
 * mpls.c		"mpls" utility frontend.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 * Authors
 *          James Leu        <jleu@mindspring.com>
 *          Igor Maravić     <igorm@etf.rs> - Innovational Centre of School of Electrical Engineering, Belgrade
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <linux/mpls.h>

#define AF_MPLS		28	/* MPLS sockets         */
#include "SNAPSHOT.h"
#include "utils.h"
#include "mpls.h"
struct rtnl_handle rth = { .fd = -1 }; /*for getting interface names*/

int resolve_hosts = 0;


#if 0
static int print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg);
static int print_all_tunnels(void);
#endif
static int print_stats(void);
static const char *lookup_proto(int key);
static int mpls_list(int cmd);
static int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);

static void usage(void)
{
	fprintf(stdout, "Usage: mpls CMD [tc TC] LABEL INSTR\n");
	/*fprintf(stdout, "       mpls tunnel add nhlfe KEY\n");
	fprintf(stdout, "       mpls tunnel change dev NAME nhlfe KEY\n");
	fprintf(stdout, "       mpls tunnel del dev NAME\n");*/
	fprintf(stdout, "\n");
	fprintf(stdout, "       mpls show\n");
	/*fprintf(stdout, "       mpls tunnel show [dev NAME]\n");*/
	fprintf(stdout, "       mpls stats\n");
	fprintf(stdout, "       mpls monitor\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Where:\n");
	fprintf(stdout, "CMD     := add | del | change\n");
	fprintf(stdout, "LABEL   := 16 .. 1048575\n");
	fprintf(stdout, "TC      := 0 .. 7\n");
	fprintf(stdout, "DSCP    := 0 .. 63\n");
	fprintf(stdout, "TC_INDEX:= 0 .. 63\n");
	fprintf(stdout, "SET_TC  := tc TC \n");
	fprintf(stdout, "DEVICE  := dev NAME\n");
	fprintf(stdout, "ADDR    := ipv6 or ipv4 address\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "POP     := pop NUMBER\n");
	fprintf(stdout, "SET_DSCP := dscp DSCP\n");
	fprintf(stdout, "SET_TCINDEX := tc_index TC_INDEX\n");
	fprintf(stdout, "SWAP    := swap [SET_TC] LABEL\n");
	fprintf(stdout, "PUSH    := push [SET_TC] LABEL [... [SET_TC] LABEL]\n");
	fprintf(stdout, "NH      := [DEVICE] ADDR\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "INSTR   := [POP] [SET_DSCP] [SET_TCINDEX]\n");
	fprintf(stdout, "           [SWAP] [PUSH] [peek | drop | NH] \n");
	fprintf(stdout, "\n");
	exit(-1);
}

/* Protocol lookup function. */
static const char *
lookup_proto(int key)
{
  const struct message *pnt;

  for (pnt = rtproto_str; pnt->key != 0; pnt++)
    if (pnt->key == key)
      return pnt->str;

  return "";
}

//prints stats from /proc/net/mpls_stats
static int
print_stats()
{
	FILE *fp;
	char   buf[8192];
	int status;
	fp = fopen("/proc/net/mpls_stat", "r");
	if(!fp)
		return -1;
	status = fread(&buf, 1, sizeof(buf), fp);

	if (status < 0) {
		return -1;
	}

	fprintf(stdout, "%s", buf);
	return 0;
}

static int
mpls_table_list(void)
{
	fprintf(stdout,"---\nMPLS entries:\n---\n");
	mpls_list(RTM_GETROUTE);
	fprintf(stdout,"---\nSTATS:\n---\n");
	print_stats();

	return 0;
}

static int
mpls_parse_label(struct mpls_key *label, char *err, int *pargc, char ***pargv)
{
	unsigned int l;
	int fatal = 0;
	int argc = *pargc;
	char **argv = *pargv;

	if (strcmp(*argv, "tc") == 0) {
		__u32 tc;
		fatal = 1;
		NEXT_ARG();
		if (get_unsigned(&tc, *argv, 0))
			invarg(*argv, "invalid tc");
		label->tc = tc;
		NEXT_ARG();
	}

	if (get_unsigned(&l, *argv, 0) || l > 1048575) {
		if (fatal)
			invarg(*argv, "invalid label");
		char *msg = "invalid label value";
		memcpy(err, msg, 20);
		return (-1);
	}

	label->label = l;
	*pargc = argc;
	*pargv = argv;
	return 0;
}

static void
parse_instr(struct nlmsghdr *nlh, size_t req_size, int *pargc, char ***pargv)
{
	int argc = *pargc;
	char **argv = *pargv;
	__u8 c = 0;
	__u8 no_push = 0;
	__u32 pop;
	__u32 dscp;
	__u32 tc_index;
	struct mpls_nh nh = {0};
	while (argc > 0) {
		if (strcmp(*argv, "drop") == 0) {
			addattr_l(nlh, req_size, MPLS_ATTR_DROP, NULL, 0);
		} else if (strcmp(*argv, "swap") == 0) {
			struct mpls_key swap = {0};
			char err[20];
			NEXT_ARG();
			if (mpls_parse_label(&swap, err, &argc, &argv))
				invarg(*argv, err);

			addattr_l(nlh, req_size, MPLS_ATTR_SWAP, &swap, sizeof(struct mpls_key));
		} else if (strcmp(*argv, "push") == 0) {
			char err[20];
			struct rtattr *push_info;
			struct mpls_key push = {0};
			if (no_push) {
				duparg("push", *argv);
				exit(-1);
			}
			NEXT_ARG();
			push_info = addattr_nest(nlh, req_size, MPLS_ATTR_PUSH);

			while(!mpls_parse_label(&push, err, &argc, &argv)) {
				addattr_l(nlh, req_size, MPLS_PUSH_1 + no_push, &push, sizeof(struct mpls_key));
				if (++no_push > MPLS_PUSH_MAX - 1)
					invarg(*argv, "invalid number of pushes");
				NEXT_ARG();
			}
			PREV_ARG();
			addattr_l(nlh, req_size, MPLS_NO_PUSHES, &no_push, sizeof(__u8));
			addattr_nest_end(nlh, push_info);
			if (no_push == 0)
				invarg(*argv, "invalid number of pushes");
		} else if (strcmp(*argv, "pop") == 0) {
			NEXT_ARG();
			if (get_unsigned(&pop, *argv, 0))
				invarg(*argv, "invalid number of pops");

			addattr_l(nlh, req_size, MPLS_ATTR_POP, &pop, sizeof(__u8));
		} else if (strcmp(*argv, "peek") == 0) {
			addattr_l(nlh, req_size, MPLS_ATTR_PEEK, NULL, 0);
		}  else if (strcmp(*argv, "dscp") == 0) {
			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");

			addattr_l(nlh, req_size, MPLS_ATTR_DSCP, &dscp, sizeof(__u8));
		} else if (strcmp(*argv, "tc_index") == 0) {
			NEXT_ARG();
			if (get_unsigned(&tc_index, *argv, 0))
				invarg(*argv, "invalid TC_INDEX");

			addattr_l(nlh, req_size, MPLS_ATTR_TC_INDEX, &tc_index, sizeof(__u16));
		} else {
			inet_prefix addr;
			int cmd;

			if (strcmp(*argv, "dev") == 0) {
				NEXT_ARG();
				nh.iface = ll_name_to_index(*argv);
				if (!nh.iface)
					invarg(*argv, "invalid interface name");
				NEXT_ARG();
			}

			if(**argv >= '0' && **argv <= '9') {
				get_prefix(&addr, *argv, 0);
				switch(addr.family) {
				case AF_INET:
					cmd = MPLS_ATTR_SEND_IPv4;
					nh.ipv4.sin_family = AF_INET;
					memcpy(&nh.ipv4.sin_addr, &addr.data, addr.bytelen);
					break;
				case AF_INET6:
					cmd = MPLS_ATTR_SEND_IPv6;
					nh.ipv6.sin6_family = AF_INET6;
					memcpy(&nh.ipv6.sin6_addr, &addr.data, addr.bytelen);
					break;
				default:
					invarg(*argv, "invalid nexthop type");
				}
			} else {
				invarg(*argv, "invalid nexthop type");
			}
			addattr_l(nlh, req_size, cmd, &nh, sizeof(struct mpls_nh));
		}
		argc--; argv++; c++;
	}
	addattr_l(nlh, req_size, MPLS_ATTR_INSTR_COUNT, &c, sizeof(__u8));
	*pargc = argc;
	*pargv = argv;
}

static int
mpls_ilm_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr n;
		struct ilmsg i;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ilmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | flags;
	req.n.nlmsg_type = cmd;

	req.i.family = AF_MPLS;
	req.i.owner = RTPROT_STATIC;

	if (argc > 0) {
		__u32 l;

		if (strcmp(*argv, "tc") == 0) {
			__u32 tc;
			NEXT_ARG();
			if (get_unsigned(&tc, *argv, 0))
				invarg(*argv, "invalid TC");
			req.i.tc = tc;
			NEXT_ARG();
		}

		if (get_unsigned(&l, *argv, 0) || l > 1048575)
			invarg(*argv, "invalid label value");

		req.i.key.label = l;
	} else
		incomplete_command();

	if (NEXT_ARG_OK()) {
		NEXT_ARG();
		parse_instr(&req.n, sizeof(req), &argc, &argv);
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(-2);

	return 0;
}

#if 0
static int
mpls_tunnel_modify(int cmd, int argc, char **argv)
{
	unsigned int key = -2;
	struct ifreq ifr;
	struct mpls_tunnel_req mtr;
	int err;
	int fd;
	int retval = 0;

	memset(&ifr, 0, sizeof(ifr));
	memset(&mtr, 0, sizeof(mtr));
	strcpy(ifr.ifr_name, "mpls0");

	while (argc > 0) {
		if ((cmd == SIOCDELTUNNEL || cmd == SIOCGETTUNNEL || cmd == SIOCCHGTUNNEL) && strcmp(*argv, "dev") == 0) {
			NEXT_ARG();

			strncpy(mtr.ifname, *argv, IFNAMSIZ);
		} else if ((cmd == SIOCADDTUNNEL || cmd == SIOCCHGTUNNEL) && strcmp(*argv, "nhlfe") == 0) {
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid NHLFE key");
			/*mtr.nhlfe_key = key;*/
		} else {
			usage();
		}
		argc--; argv++;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_data = (void*)&mtr;
	err = ioctl(fd, cmd, &ifr);

	if (err){
		perror("ioctl");
		retval = -1;
	}
	else
		print_tunnel(cmd, &mtr, stdout);

	return retval;
}
#endif

static void
print_address(FILE *fp, struct sockaddr *addr)
{
	char buf[256];
	switch (addr->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in*)addr;
		inet_ntop(addr->sa_family, &sin->sin_addr,
				buf, sizeof(buf));
		fprintf(fp, "%s ", buf);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
		inet_ntop(addr->sa_family, &sin6->sin6_addr,
				buf, sizeof(buf));
		fprintf(fp, "%s ", buf);
		break;
	}
	case AF_PACKET:
	{
		fprintf(fp, "packet");
		break;
	}
	default:
		fprintf(fp, "<unknown address family %d> ", addr->sa_family);
	}
}

static inline void
print_label(FILE *fp, const struct mpls_key *label, __u8 tc)
{
	fprintf(fp, "label %u ", label->label);
	if (tc)
		fprintf(fp, "tc %u ", tc);
}

static void
print_instructions(FILE *fp, struct rtattr **tb)
{
	int i;

	for(i = 0;i < MPLS_ATTR_MAX;i++) {
		if (!tb[i])
			continue;
		switch (i) {
		case MPLS_ATTR_DROP:
			fprintf(fp, "drop ");
			break;
		case MPLS_ATTR_POP:
			fprintf(fp, "pop %u ", *(__u8*)RTA_DATA(tb[MPLS_ATTR_POP]));
			break;
		case MPLS_ATTR_PEEK:
			fprintf(fp, "peek ");
			break;
		case MPLS_ATTR_PUSH:
			{
				struct rtattr *push_a[__MPLS_ATTR_PUSH_MAX];
				__u8 no_push;
				struct mpls_key *push;
				int j;
				parse_rtattr(push_a, MPLS_ATTR_PUSH_MAX, RTA_DATA(tb[MPLS_ATTR_PUSH]),
					    RTA_PAYLOAD(tb[MPLS_ATTR_PUSH]));

				if (push_a[MPLS_NO_PUSHES])
					no_push = *(__u8 *)RTA_DATA(push_a[MPLS_NO_PUSHES]);
				else {
					perror("Error talking to kernel");
					exit(-1);
				}

				fprintf(fp, "push ");
				for (j = 0; j < no_push; j++) {
					if (!push_a[MPLS_PUSH_1 + j])  {
						perror("Error talking to kernel");
						exit(-1);
					}
					push = (struct mpls_key *)RTA_DATA(push_a[MPLS_PUSH_1 + j]);
					if (push->tc)
						fprintf(fp, "tc %hhu ", push->tc);
					fprintf(fp, "%u ", push->label);
				}
			}
			break;
		case MPLS_ATTR_SWAP:
			{
				struct mpls_key *swap = (struct mpls_key *)RTA_DATA(tb[MPLS_ATTR_SWAP]);
				fprintf(fp, "swap ");
				if (swap->tc)
					fprintf(fp, "tc %hhu ", swap->tc);
				fprintf(fp, "%u ", swap->label);
			}
			break;
		case MPLS_ATTR_SEND_IPv4:
		case MPLS_ATTR_SEND_IPv6:
			{
				struct mpls_nh *nh = (struct mpls_nh *)RTA_DATA(tb[i]);
				if (nh->iface)
					fprintf(fp, "dev %s ", ll_index_to_name(nh->iface));
				print_address(fp, &nh->addr);
			}
			break;
		case MPLS_ATTR_TC_INDEX:
			fprintf(fp, "tc_index %hu ", *(__u16*)RTA_DATA(tb[MPLS_ATTR_TC_INDEX]));
			break;
		case MPLS_ATTR_DSCP:
			fprintf(fp, "dscp %hu ", *(__u8*)RTA_DATA(tb[MPLS_ATTR_DSCP]));
			break;
		case MPLS_ATTR_INSTR_COUNT:
			break;
		default:
			fprintf(fp, "<unknown opcode %d> ", i);
		}
	}
}

static int
print_ilm(int cmd, const struct ilmsg *ilm_msg, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;

	if (cmd == RTM_DELROUTE)
		fprintf(fp, "deleted ILM entry ");

	if (cmd == RTM_NEWROUTE || cmd == RTM_GETROUTE)
		fprintf(fp, "ILM entry ");

	print_label(fp, &ilm_msg->key, ilm_msg->tc);
	fprintf (fp,"proto %s \n\t", lookup_proto(ilm_msg->owner));
	print_instructions(fp, tb);

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

#if 0
int
print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg)
{
	FILE *fp = (FILE*)arg;
	switch(cmd){
	case SIOCADDTUNNEL:
		fprintf(fp,"Created tunnel: ");
		break;
	case SIOCDELTUNNEL:
		fprintf(fp,"Deleted tunnel: ");
		break;
	case SIOCCHGTUNNEL:
		fprintf(fp,"Changed tunnel: ");
		break;
	case SIOCGETTUNNEL:
		fprintf(fp,"->");
		break;
	}
	fprintf(fp, "%s ", mtr->ifname);
	/*if (cmd != SIOCDELTUNNEL)
		fprintf(fp, "0x%08x", mtr->nhlfe_key);*/
	fprintf(fp, "\n");

	fflush(fp);
	return 0;
}
#endif

#if 0
//taken from ip/ipaddress.c - IMAR
struct nlmsg_list
{
	struct nlmsg_list *next;
	struct nlmsghdr	  h;
};


//taken from ip/ipaddress.c - IMAR
static int
store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct nlmsg_list **linfo = (struct nlmsg_list**)arg;
	struct nlmsg_list *h;
	struct nlmsg_list **lp;

	h = malloc(n->nlmsg_len+sizeof(void*));
	if (h == NULL)
		return -1;

	memcpy(&h->h, n, n->nlmsg_len);
	h->next = NULL;

	for (lp = linfo; *lp; lp = &(*lp)->next) /* NOTHING */;

	*lp = h;

	ll_remember_index(who, n, NULL);
	return 0;
}

//written with little help from ip/ipaddress.c (functions print_linkinfo & ipaddr_list_or_flush) - IMAR
static int
print_all_tunnels()
{
	int retval = 0;
	int argc = 2;
	char* cmd = "dev";
	char* argv[argc];
	struct nlmsg_list *linfo = NULL;
	struct nlmsg_list *l, *n;


	if (rtnl_wilddump_request(&rth, AF_PACKET, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(-1);
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &linfo, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(-1);
	}

	argv[0] = cmd; //set dev command

	for (l=linfo; l; l = n) {
		struct ifinfomsg *ifi;
		struct rtattr * tb[IFLA_MAX+1];
		int len;

		n = l->next;
		ifi = NLMSG_DATA(&l->h);
		len = l->h.nlmsg_len;
		len -= NLMSG_LENGTH(sizeof(*ifi));

		if (len < 0)
			return -1;

		parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
		if(ifi->ifi_type == ARPHRD_MPLS_TUNNEL){
			argv[1] = (char*)RTA_DATA(tb[IFLA_IFNAME]);
			if (argv[1] == NULL || strcmp(argv[1],"mpls0")==0){
				fflush(stdout);
				free(l);
				continue;
			}
			retval = mpls_tunnel_modify(SIOCGETTUNNEL, argc, argv);
			if(retval) {
				fflush(stdout);
				free(l);
				break;
			}
		}

		fflush(stdout);
		free(l);
	}

	return retval;
}
#endif

static int
print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ilmsg *ilm_msg = NLMSG_DATA(n);
	struct rtattr *tb[__MPLS_ATTR_MAX];
	struct rtattr *attr;
	int len = n->nlmsg_len;

	if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE
			&& n->nlmsg_type != RTM_GETROUTE) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
				"nlmsg_type=0x%x\n", n->nlmsg_len, n->nlmsg_type);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*ilm_msg));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}
	attr = (struct rtattr *)((char *) ilm_msg + NLMSG_ALIGN(sizeof(struct ilmsg)));
	parse_rtattr(tb, MPLS_ATTR_MAX, attr, len);

	return print_ilm(n->nlmsg_type, ilm_msg, arg, tb);
}

static int
mpls_list(int cmd)
{
	struct {
		struct nlmsghdr n;
		struct ilmsg i;
		char buf[1024];
	} req;
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ilmsg));
	req.n.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.n.nlmsg_seq = rth.dump = ++rth.seq;

	req.i.family = AF_MPLS;

	if (rtnl_send(&rth, (const char *)&req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send dump request");
		exit(-1);
	}

	if (rtnl_dump_filter(&rth, print_mpls, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(-1);
	}

	return 0;
}

static int
do_ilm(int argc, char **argv)
{
	if (argc <= 0 || matches(*argv, "list") == 0 ||
				matches(*argv, "show") == 0){
			return mpls_list(RTM_GETROUTE);
	}
	if (matches(*argv, "add") == 0)
		return mpls_ilm_modify(RTM_NEWROUTE, NLM_F_CREATE, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_ilm_modify(RTM_NEWROUTE, NLM_F_REPLACE, argc-1, argv+1);
	if (matches(*argv, "delete") == 0){
		return mpls_ilm_modify(RTM_DELROUTE, 0, argc-1, argv+1);
	}
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
				"Option \"%s\" is unknown, try \"mpls --help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

#if 0
static int
do_tunnel(int argc, char **argv)
{
	if (argc <= 0)
		usage();
	if (matches(*argv, "add") == 0)
		return mpls_tunnel_modify(SIOCADDTUNNEL, argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return mpls_tunnel_modify(SIOCDELTUNNEL, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_tunnel_modify(SIOCCHGTUNNEL, argc-1, argv+1);
	if (matches(*argv, "show") == 0){
		if(NEXT_ARG_OK())
			return mpls_tunnel_modify(SIOCGETTUNNEL, argc-1, argv+1);
		else {
			return print_all_tunnels();
		}
	}
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
				"Option \"%s\" is unknown, try \"mpls --help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}
#endif

static int
do_mplsmonitor(void)
{
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0) {
		fprintf (stderr, "Error openning netlink socket\n");
		exit(-1);
	}
	ll_init_map(&rth);
	rtnl_close(&rth);

	if (rtnl_open(&rth, nl_mgrp(RTNLGRP_MPLS)) < 0)
		exit(1);

	do {
		if (rtnl_listen(&rth, print_mpls, (void*)stdout) < 0)
			exit(2);
	} while (1);

	rtnl_close(&rth);
	exit(0);
}

int main(int argc, char **argv)
{
	char *basename;
	int retval;

	basename = strrchr(argv[0], '/');
	if (basename == NULL)
		basename = argv[0];
	else
		basename++;

	while (argc > 1) {
		if (argv[1][0] != '-')
			break;
		if (matches(argv[1], "--version") == 0 || matches(argv[1], "-v") == 0) {
			printf("mpls utility, iproute2-ss%s mpls-linux %d.%d%d%d\n",
					SNAPSHOT, (MPLS_LINUX_VERSION >> 24) & 0xFF,
					(MPLS_LINUX_VERSION >> 16) & 0xFF,
					(MPLS_LINUX_VERSION >> 8) & 0xFF,
					(MPLS_LINUX_VERSION) & 0xFF);
			exit(0);
		} else if (matches(argv[1], "--help") == 0 || matches(argv[1], "-h") == 0) {
			usage();
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, try \"mpls --help\".\n", argv[1]);
			exit(-1);
		}
		argc--;	argv++;
	}

	if (argc > 1) {
		if (rtnl_open(&rth, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth);
		rtnl_close(&rth);

		if (matches(argv[1], "monitor") == 0) {
			retval = do_mplsmonitor();
		} else {
			if (rtnl_open(&rth, nl_mgrp(RTNLGRP_MPLS)) < 0){
				fprintf (stderr,"Error opening rtnl\n");
				exit(-1);
			}

#if 0
			if (matches(argv[1], "tunnel") == 0)
				retval = do_tunnel(argc-2,argv+2);
			else
#endif
			if (matches(argv[1], "stats") == 0)
				retval = print_stats();
			else if (matches(argv[1], "show") == 0 && argv[2] &&
					matches(argv[2], "all") == 0)
				retval = mpls_table_list();
			else
				retval = do_ilm(argc - 1, argv + 1);

			rtnl_close(&rth);
		}
	} else {
		usage();
		retval = 1;
	}
	return retval;
}
