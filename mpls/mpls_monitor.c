/*
 * mplsmonitor.c	"mpls monitor".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:
 * 		James R. Leu <jleu@mindspring.com> shamlesslessly copied this code from Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *		Igor Maravić     <igorm@etf.rs> - Innovational Centre of School of Electrical Engineering, Belgrade
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <linux/mpls.h>
#include <linux/genetlink.h>

#include "utils.h"
#include "mpls.h"

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: mpls monitor [all] [nhlfe] [ilm] [xc] [labelspace]\n");
	exit(-1);
}

int accept_msg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE*)arg;
        struct rtattr *tb[MPLS_ATTR_MAX + 1];
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
        parse_rtattr(tb, MPLS_ATTR_MAX, attrs, len);

	switch (ghdr->cmd) {
		case MPLS_CMD_NEWNHLFE:
		case MPLS_CMD_DELNHLFE:
			print_nhlfe(ghdr->cmd, n, arg, tb);
			return 0;
		case MPLS_CMD_NEWILM:
		case MPLS_CMD_DELILM:
			print_ilm(ghdr->cmd, n, arg, tb);
			return 0;
		case MPLS_CMD_NEWXC:
		case MPLS_CMD_DELXC:
			print_xc(ghdr->cmd, n, arg, tb);
			return 0;
		case MPLS_CMD_SETLABELSPACE:
			print_labelspace(ghdr->cmd, n, arg, tb);
			return 0;
		default:
			return -1;
	}
	if (n->nlmsg_type != NLMSG_ERROR && n->nlmsg_type != NLMSG_NOOP &&
	    n->nlmsg_type != NLMSG_DONE) {
		fprintf(fp, "Unknown message: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
	}
	return 0;
}

int do_mplsmonitor(int argc, char **argv,unsigned int MPLS_GRP_NHLFE,unsigned int MPLS_GRP_ILM, unsigned int MPLS_GRP_XC, unsigned int MPLS_GRP_LABELSPACE)
{
	struct rtnl_handle rth;
	unsigned int groups = MPLS_GRP_NHLFE | MPLS_GRP_ILM | MPLS_GRP_XC | MPLS_GRP_LABELSPACE;
	int nhlfe=0;
	int ilm=0;
	int xc=0;
	int labelspace=0;

	while (argc > 0) {
		if (matches(*argv, "nhlfe") == 0) {
			nhlfe=1;
			groups = 0;
		} else if (matches(*argv, "ilm") == 0) {
			ilm=1;
			groups = 0;
		} else if (matches(*argv, "xc") == 0) {
			xc=1;
			groups = 0;
		} else if (matches(*argv, "labelspace") == 0) {
			labelspace=1;
			groups = 0;
		} else if (strcmp(*argv, "all") == 0) {
			groups =  MPLS_GRP_NHLFE | MPLS_GRP_ILM | MPLS_GRP_XC | MPLS_GRP_LABELSPACE;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Argument \"%s\" is unknown, try \"mpls monitor help\".\n", *argv);
			exit(-1);
		}
		argc--;	argv++;
	}

	if (nhlfe)
		groups |= MPLS_GRP_NHLFE;
	if (ilm)
		groups |= MPLS_GRP_ILM;
	if (xc)
		groups |= MPLS_GRP_XC;
	if (labelspace)
		groups |= MPLS_GRP_LABELSPACE;

	if (rtnl_open(&rth, 0) < 0) {
		fprintf (stderr, "Error openning netlink socket\n");
		exit(-1);
	}
	ll_init_map(&rth);
	rtnl_close(&rth);

	if (rtnl_open_byproto(&rth, groups, NETLINK_GENERIC) < 0)
		exit(1);

	fprintf(stdout,"Monitoring:\n");

	if (groups&MPLS_GRP_NHLFE)
		fprintf(stdout,"NHLFE\n");
	if (groups&MPLS_GRP_ILM)
		fprintf(stdout,"ILM\n");
	if (groups&MPLS_GRP_XC)
		fprintf(stdout,"XC\n");
	if (groups&MPLS_GRP_LABELSPACE)
		fprintf(stdout,"LABELSPACE\n");

	fprintf(stdout,"---\n");

	if (rtnl_listen(&rth, accept_msg, (void*)stdout) < 0)
		exit(2);

	rtnl_close(&rth);
	exit(0);
}
