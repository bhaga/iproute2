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
#include "rt_names.h"
#include "mpls.h"
struct rtnl_handle rth = { .fd = -1 }; /*for getting interface names*/

int resolve_hosts = 0;

static int print_stats(void);
static int mpls_list(int cmd);
static int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);

static void usage(void)
{
	fprintf(stdout, "Usage: mpls { add | del | change } [ tc TC ] LABEL_i [ pop NUMBER ]\n");
	fprintf(stdout, "            [ dscp DSCP ] [ tc_index TC_INDEX ] [ swap [ tc TC ] LABEL_o ]\n");
	fprintf(stdout, "            [ push [ tc TC ] LABEL_o [... [ tc TC ] LABEL_o ] ]\n");
	fprintf(stdout, "            {peek | { [ dev NAME ] { IP_ADDRESS | IPv6_ADDRESS } } } \n");
	fprintf(stdout, "       mpls show\n");
	fprintf(stdout, "       mpls stats\n");
	fprintf(stdout, "       mpls monitor\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Where: LABEL_i := 16 .. 1048575\n");
	fprintf(stdout, "       LABEL_o := 0 .. 1048575\n");
	fprintf(stdout, "       TC      := 0 .. 7\n");
	fprintf(stdout, "       DSCP    := 0 .. 63\n");
	fprintf(stdout, "       TC_INDEX:= 0 .. 65535\n");
	fprintf(stdout, "\n");
	exit(-1);
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
		if (parse_instr(&req.n, sizeof(req), &argc, &argv))
			invarg(*argv, "invalid nexthop type");
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(-2);

	return 0;
}

static int
print_ilm(int cmd, const struct ilmsg *ilm_msg, void *arg, struct rtattr **tb)
{
	SPRINT_BUF(buf);

	FILE *fp = (FILE*)arg;

	if (cmd == RTM_DELROUTE)
		fprintf(fp, "deleted ILM entry ");

	if (cmd == RTM_NEWROUTE || cmd == RTM_GETROUTE)
		fprintf(fp, "ILM entry ");

	print_label(fp, &ilm_msg->key, ilm_msg->tc);

	fprintf(fp, "proto %s \n\t", rtnl_rtprot_n2a(ilm_msg->owner, buf, sizeof(buf)));
	print_instructions(fp, tb);

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

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
				"Option \"%s\" is unknown, try \"mpls help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

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
		} else if (matches(argv[1], "help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, try \"mpls help\".\n", argv[1]);
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
