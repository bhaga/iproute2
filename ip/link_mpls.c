/*
 * link_mpls.c	mpls driver module
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Igor Maravic <igorm@etf.rs>
 *
 */

#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/mpls.h>
#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "../mpls/mpls.h"

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
	fprintf(stdout, "Usage: ip link { add | set | change | replace | del } NAME\n");
	fprintf(stdout, "          type mpls [ dscp DSCP ] [ tc_index TC_INDEX ]\n");
	fprintf(stdout, "          [ push [ tc TC ] LABEL_o [... [ tc TC ] LABEL_o ] ]\n");
	fprintf(stdout, "          { [ dev NAME ] { IP_ADDRESS | IPv6_ADDRESS } }} \n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Where: LABEL_o := 0 .. 1048575\n");
	fprintf(stdout, "       TC      := 0 .. 7\n");
	fprintf(stdout, "       DSCP    := 0 .. 63\n");
	fprintf(stdout, "       TC_INDEX:= 0 .. 65535\n");
	exit(-1);
}

static int mpls_parse_opt(struct link_util *lu, int argc, char **argv,
			 struct nlmsghdr *n)
{
	if (argc > 0) {
		if (strcmp(*argv, "help") == 0)
			usage();
		parse_instr(n, 1024, &argc, &argv);
	} else
		usage();

	return 0;
}

static void mpls_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	if (!tb)
		return;

	print_instructions(f, tb);
}

struct link_util mpls_link_util = {
	.id = "mpls",
	.maxattr = MPLS_ATTR_MAX,
	.parse_opt = mpls_parse_opt,
	.print_opt = mpls_print_opt,
};
