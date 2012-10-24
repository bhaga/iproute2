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
#include <linux/genetlink.h>
#include <linux/mpls.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "mpls.h"

int show_details = 0;
int show_raw = 0;
int resolve_hosts = 0;

unsigned int mpls_mc_grp;
unsigned int mpls_netlink_id;

struct rtnl_handle rth_mpls;
struct rtnl_handle rth = { .fd = -1 }; /*for getting interface names*/

extern int do_mplsmonitor(int argc, char **argv,unsigned int MPLS_MC_GRP);
static int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
static int print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg);
static int print_all_tunnels(void);
static int print_stats(void);
static const char *lookup_proto (int key);
static int mpls_get_mcast_group_ids(void);
static int mpls_list(int cmd);

static void usage(void)
{
	fprintf(stdout, "Usage: mpls CMD label [tc TC] LABEL INSTR\n");
	fprintf(stdout, "       mpls tunnel add nhlfe KEY\n");
	fprintf(stdout, "       mpls tunnel change dev NAME nhlfe KEY\n");
	fprintf(stdout, "       mpls tunnel del dev NAME\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "       mpls show [label [tc TC] LABEL]\n");
	fprintf(stdout, "       mpls tunnel show [dev NAME]\n");
	fprintf(stdout, "       mpls stats\n");
	fprintf(stdout, "       mpls show all\n");
	fprintf(stdout, "       mpls monitor ...\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Where:\n");
	fprintf(stdout, "CMD     := add | del | change\n");
	fprintf(stdout, "LABEL   := 16 .. 1048575\n");
	fprintf(stdout, "DEVICE  := dev NAME\n");
	fprintf(stdout, "ADDR    := ipv6 or ipv4 address\n");
	fprintf(stdout, "NH      := [DEVICE] ADDR\n");
	fprintf(stdout, "SET_TC  := tc TC \n");
	fprintf(stdout, "PUSH    := push [SET_TC] LABEL\n");
	fprintf(stdout, "SWAP    := swap [SET_TC] LABEL\n");
	fprintf(stdout, "POP     := pop NUMBER\n");
	fprintf(stdout, "TC     := 0 .. 7\n");
	fprintf(stdout, "DSCP    := 0 .. 63\n");
	fprintf(stdout, "TC_INDEX:= 0 .. 63\n");
	fprintf(stdout, "INSTR   := [POP] [dscp DSCP] [tc_index TC_INDEX]\n");
	fprintf(stdout, "           [SWAP] [PUSH ... [PUSH]] [peek | drop | NH] \n");
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
	mpls_list(MPLS_CMD_GETILM);
	fprintf(stdout,"---\nSTATS:\n---\n");
	print_stats();

	return 0;
}

static void
mpls_parse_label(struct ilm_key *label, char **argv)
{
	unsigned int l1;
	char *value;

	value = *argv;

	if (get_unsigned(&l1, value, 0) || l1 > 1048575)
		invarg(value, "invalid label value");

	set_key_label(label, l1);
}

#define realloc_instr(instr, c)																\
		(struct nhlfe_req *)realloc((instr), sizeof(struct nhlfe_req) + ((c) + 1) * sizeof(struct instr_req))

static void
mpls_parse_instr(struct nhlfe_req *instr, int *pargc, char ***pargv)
{
	int argc = *pargc;
	char **argv = *pargv;
	int c = 0;

	while (argc > 0) {
		if (strcmp(*argv, "drop") == 0) {
			/*make room for new element*/
			instr = realloc_instr(instr, c);
			instr->instr[c].opcode = MPLS_OP_DROP;
		} else if (strcmp(*argv, "push") == 0 ||
					strcmp(*argv, "swap") == 0) {
			instr = realloc_instr(instr, c);
			instr->instr[c].opcode =
					(strcmp(*argv, "swap") == 0) ? MPLS_OP_SWAP : MPLS_OP_PUSH;

			NEXT_ARG();

			if (strcmp(*argv, "tc") == 0) {
				__u32 tc;
				NEXT_ARG();
				if (get_unsigned(&tc, *argv, 0))
					invarg(*argv, "invalid TC");

				instr->instr[c].push.tc = tc;
				NEXT_ARG();
			}
			mpls_parse_label((struct ilm_key *)&instr->instr[c].push, argv);
		} else if (strcmp(*argv, "pop") == 0) {
			__u32 pop;
			NEXT_ARG();
			if (get_unsigned(&pop, *argv, 0))
				invarg(*argv, "invalid number of pops");

			instr = realloc_instr(instr, c);

			instr->instr[c].opcode = MPLS_OP_POP;
			instr->instr[c].pop = pop;
		} else if (strcmp(*argv, "peek") == 0) {
			instr = realloc_instr(instr, c);

			instr->instr[c].opcode = MPLS_OP_PEEK;
		}  else if (strcmp(*argv, "dscp") == 0) {
			__u32 dscp;

			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");

			instr = realloc_instr(instr, c);

			instr->instr[c].opcode = MPLS_OP_SET_DS;
			instr->instr[c].dscp = dscp;
		} else if (strcmp(*argv, "tc_index") == 0) {
			__u32 tc_index;
			NEXT_ARG();
			if (get_unsigned(&tc_index, *argv, 0))
				invarg(*argv, "invalid TC_INDEX");

			instr = realloc_instr(instr, c);

			instr->instr[c].opcode = MPLS_OP_SET_TC_INDEX;
			instr->instr[c].tc_index = tc_index;
		} else {
			inet_prefix addr;
			/*make room for new element*/
			instr = realloc_instr(instr, c);
			if (strcmp(*argv, "dev") == 0) {
				NEXT_ARG();
				instr->instr[c].nh.iface = ll_name_to_index(*argv);
				if (!instr->instr[c].nh.iface)
					invarg(*argv, "invalid interface name");
				NEXT_ARG();
			}

			if(**argv >= '0' && **argv <= '9') {
				get_prefix(&addr, *argv, 0);
				switch(addr.family){
				case AF_INET:
					instr->instr[c].opcode = MPLS_OP_SEND_IPv4;
					instr->instr[c].nh.ipv4.sin_family = AF_INET;
					memcpy(&instr->instr[c].nh.ipv4.sin_addr, &addr.data, addr.bytelen);
					break;
				case AF_INET6:
					instr->instr[c].opcode = MPLS_OP_SEND_IPv6;
					instr->instr[c].nh.ipv6.sin6_family = AF_INET6;
					memcpy(&instr->instr[c].nh.ipv6.sin6_addr, &addr.data, addr.bytelen);
					break;
				default:
					invarg(*argv, "invalid nexthop type");
				}
			} else {
				invarg(*argv, "invalid nexthop type");
			}
		}
		argc--; argv++; c++;
	}
	instr->instr_length = c;
	*pargc = argc;
	*pargv = argv;
}

static int
mpls_ilm_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;
	struct ilm_req	mil;
	struct nhlfe_req*		instr;
	int got_label = 0;

	memset(&req, 0, sizeof(req));
	memset(&mil, 0, sizeof(mil));
	instr = (struct nhlfe_req*)malloc(sizeof(struct nhlfe_req));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = mpls_netlink_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "label") == 0) {
			if (++got_label > 1) {
				perror("Only one label could be set per ILM");
				exit(1);
			}
			NEXT_ARG();
			if (strcmp(*argv, "tc") == 0) {
				__u32 tc;
				NEXT_ARG();
				if (get_unsigned(&tc, *argv, 0))
					invarg(*argv, "invalid TC");
				mil.tc = (__u8)tc;
				NEXT_ARG();
			}
			mpls_parse_label(&mil.label, argv);
		} else {
			mpls_parse_instr(instr, &argc, &argv);
			mil.change_flag |= MPLS_CHANGE_INSTR;
		}
		argc--; argv++;
	}
	if (got_label == 0) {
		perror("Please specify MPLS label");
		exit(1);
	}

	mil.owner = RTPROT_STATIC;
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_ILM, &mil, sizeof(mil));
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, instr,
			sizeof(*instr) + instr->instr_length * sizeof(struct instr_req));

	if (rtnl_talk(&rth_mpls, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);
	free(instr);
	return 0;
}

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
print_label(FILE *fp, const struct ilm_key *label, __u8 tc)
{
	fprintf(fp, "label %u ", key_label(label));
	if (tc)
		fprintf(fp, "tc %u ", tc);
}

static void
print_instructions(FILE *fp, struct nhlfe_req *instr)
{
	struct instr_req *ci;   /* current instruction */
	int i;

	for(i = 0;i < instr->instr_length;i++) {
		ci = &instr->instr[i];

		switch (ci->opcode) {
		case MPLS_OP_DROP:
			fprintf(fp, "drop ");
			break;
		case MPLS_OP_POP:
			fprintf(fp, "pop %u ", ci->pop);
			break;
		case MPLS_OP_PEEK:
			fprintf(fp, "peek ");
			break;
		case MPLS_OP_PUSH:
			fprintf(fp, "push ");
			if (ci->push.tc)
				fprintf(fp, "tc %hhu ", ci->push.tc);
			fprintf(fp, "%u ", key_label((struct ilm_key *)&ci->push));
			break;
		case MPLS_OP_SWAP:
			fprintf(fp, "swap ");
			if (ci->push.tc)
				fprintf(fp, "tc %hhu ", ci->push.tc);
			fprintf(fp, "%u ", key_label((struct ilm_key *)&ci->push));
			break;
		case MPLS_OP_SEND_IPv4:
		case MPLS_OP_SEND_IPv6:
			if (ci->nh.iface)
				fprintf(fp, "dev %s ",
						ll_index_to_name(ci->nh.iface));
			print_address(fp, &ci->nh.addr);
			break;
		case MPLS_OP_SET_TC_INDEX:
			fprintf(fp, "tc_index %hu ",ci->tc_index);
			break;
		case MPLS_OP_SET_DS:
			fprintf(fp, "dscp %hu ",ci->dscp);
			break;
		default:
			fprintf(fp, "<unknown opcode %d> ", ci->opcode);
		}
	}
}

int
print_ilm(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct ilm_req *mil;
	struct nhlfe_req *instr;

	if (cmd == MPLS_CMD_DELILM)
		fprintf(fp, "deleted ILM entry ");

	if (cmd == MPLS_CMD_NEWILM)
		fprintf(fp, "ILM entry ");

	mil = RTA_DATA(tb[MPLS_ATTR_ILM]);
	instr = RTA_DATA(tb[MPLS_ATTR_NHLFE]);

	print_label(fp, &mil->label, mil->tc);

	fprintf (fp,"proto %s ", lookup_proto(mil->owner));
	fprintf(fp, "\n\t");
	if (instr && instr->instr_length)
		print_instructions(fp, instr);

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

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
		exit(1);
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &linfo, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
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

static int
print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[__MPLS_ATTR_MAX];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;

	if (n->nlmsg_type !=  mpls_netlink_id) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
				"nlmsg_type=0x%x\n", n->nlmsg_len, n->nlmsg_type);
		return 0;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr(tb, __MPLS_ATTR_MAX - 1, attrs, len);

	switch (ghdr->cmd) {
	case MPLS_CMD_NEWILM:
	case MPLS_CMD_DELILM:
		return print_ilm(ghdr->cmd, n,arg,tb);
	default:
		return 0;
	}

	return 0;
}

static int
mpls_list(int cmd)
{
	struct genlmsghdr *ghdr;
	struct rtnl_handle rth;

	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0) {
		fprintf (stderr, "Error opening nl socket\n");
		exit(-1);
	}
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.n.nlmsg_type = mpls_netlink_id;
	req.n.nlmsg_seq = rth.dump = ++rth.seq;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	if (rtnl_send(&rth, (const char *)&req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, print_mpls, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}
	rtnl_close(&rth);

	return 0;
}

static int
do_ilm(int argc, char **argv)
{

	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = argc-1>=5? 5: argc-1;
			return mpls_ilm_modify(MPLS_CMD_GETILM, 0, args, argv+1);
		}else
			return mpls_list(MPLS_CMD_GETILM);
	}
	if (matches(*argv, "add") == 0)
		return mpls_ilm_modify(MPLS_CMD_NEWILM, NLM_F_CREATE,
				argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_ilm_modify(MPLS_CMD_NEWILM, 0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0){
		return mpls_ilm_modify(MPLS_CMD_DELILM, 0, argc-1, argv+1);
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

static int
_mpls_get_mcast_group_ids(struct nlmsghdr *n)
{
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;

	if (n->nlmsg_type !=  GENL_ID_CTRL) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
				"nlmsg_type=0x%x\n", n->nlmsg_len, n->nlmsg_type);
		return 0;
	}
	if (ghdr->cmd != CTRL_CMD_GETFAMILY &&
			ghdr->cmd != CTRL_CMD_DELFAMILY &&
			ghdr->cmd != CTRL_CMD_NEWFAMILY &&
			ghdr->cmd != CTRL_CMD_NEWMCAST_GRP &&
			ghdr->cmd != CTRL_CMD_DELMCAST_GRP) {
		fprintf(stderr, "Unknown controller command %d\n", ghdr->cmd);
		return 0;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		fprintf(stderr, "wrong controller message len %d\n", len);
		return -1;
	}

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if(tb[CTRL_ATTR_FAMILY_ID]) {
		__u32 *id = RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
		mpls_netlink_id = *id;
	} else {
		fprintf(stderr, "No family ID\n");
		return -1;
	}


	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		struct rtattr *tb2[GENL_MAX_FAM_GRPS + 1];
		int i;

		parse_rtattr_nested(tb2, GENL_MAX_FAM_GRPS,	tb[CTRL_ATTR_MCAST_GROUPS]);
		mpls_mc_grp = 0;

		for (i = 0; i < GENL_MAX_FAM_GRPS; i++) {
			if (tb2[i]) {
				struct rtattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];
				parse_rtattr_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, tb2[i]);
				if (tb[1]) {
					char *name = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_NAME]);
					if(strncmp(name,MPLS_MC_GRP_NAME,strlen(MPLS_MC_GRP_NAME)) == 0) {
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_mc_grp = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for MPLS mcast group!\n");
							return -1;
						}
					}
				}
			}
		}
		if(!mpls_mc_grp) {
			fprintf(stderr,"Couldn't find multicast MPLS ID!\n");
			return -1;
		}
	} else {
		fprintf(stderr,"No multicast groups registered!\n");
		return -1;
	}
	return 0;
}

/*
 * For getting mpls multicast group IDs
 */
static int
mpls_get_mcast_group_ids()
{
	struct rtnl_handle rth_g;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	int ret = -1;
	char d[GENL_NAMSIZ];
	struct {
		struct nlmsghdr         n;
		char                    buf[4096];
	} req;

	memset(&req, 0, sizeof(req));

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = GENL_ID_CTRL;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = CTRL_CMD_GETFAMILY;

	if (rtnl_open_byproto(&rth_g, 0, NETLINK_GENERIC) < 0) {
		fprintf(stderr, "Cannot open generic netlink socket\n");
		exit(1);
	}

	strncpy(d, MPLS_NETLINK_NAME, sizeof (d) - 1);
	addattr_l(nlh, 128, CTRL_ATTR_FAMILY_NAME,d, strlen(d) + 1);

	if (rtnl_talk(&rth_g, nlh, 0, 0, nlh, NULL, NULL) < 0) {
		fprintf(stderr, "Error talking to the kernel\n");
		goto ctrl_done;
	}

	if (_mpls_get_mcast_group_ids(nlh) < 0) {
		fprintf(stderr, "Dump terminated\n");
		goto ctrl_done;
	}
	ret = 0;
ctrl_done:
	rtnl_close(&rth_g);
	return ret;
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

	if (mpls_get_mcast_group_ids() < 0)
		exit(-1);

	if (argc > 1) {
		if (rtnl_open(&rth_mpls, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth_mpls);
		rtnl_close(&rth_mpls);

		if (matches(argv[1], "monitor") == 0) {
			retval = do_mplsmonitor(argc - 2, argv + 2, mpls_mc_grp);
		} else {
			if (rtnl_open_byproto(&rth_mpls, mpls_mc_grp, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening MPLS rtnl\n");
				exit(-1);
			}
			if (rtnl_open(&rth, 0) < 0){
				fprintf (stderr,"Error opening rtnl\n");
				rtnl_close(&rth_mpls);
				exit(-1);
			}

			if (matches(argv[1], "tunnel") == 0)
				retval = do_tunnel(argc-2,argv+2);
			else if (matches(argv[1], "stats") == 0)
				retval = print_stats();
			else if (matches(argv[1], "show") == 0 && argv[2] &&
					matches(argv[2], "all") == 0)
				retval = mpls_table_list();
			else
				retval = do_ilm(argc - 1, argv + 1);

			rtnl_close(&rth_mpls);
			rtnl_close(&rth);
		}
	} else {
		usage();
		retval = 1;
	}
	return retval;
}
