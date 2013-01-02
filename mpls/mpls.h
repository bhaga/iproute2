#ifndef IPROUTE_MPLS_H
#define IPROUTE_MPLS_H

#include <linux/mpls.h>
#include <linux/rtnetlink.h>
#include "utils.h"

static int
mpls_parse_label(struct mpls_hdr *hdr, char *err, int *pargc, char ***pargv)
{
	unsigned int label;
	int fatal = 0;
	int argc = *pargc;
	char **argv = *pargv;

	memset(hdr, 0, sizeof(hdr));
	if (strcmp(*argv, "tc") == 0) {
		__u32 tc;
		fatal = 1;
		NEXT_ARG();
		if (get_unsigned(&tc, *argv, 0))
			invarg(*argv, "invalid tc");
		hdr->tc = tc;
		NEXT_ARG();
	}

	if (get_unsigned(&label, *argv, 0) || label > 1048575) {
		if (fatal)
			invarg(*argv, "invalid label");
		char *msg = "invalid label value";
		memcpy(err, msg, 20);
		return (-1);
	}
	mpls_hdr_set_label(hdr, label);

	*pargc = argc;
	*pargv = argv;
	return 0;
}

static int
parse_instr(struct nlmsghdr *nlh, size_t req_size, int *pargc, char ***pargv)
{
	int argc = *pargc;
	char **argv = *pargv;
	__u8 c = 0;
	__u8 no_push = 0;
	__u32 pop;
	__u32 dscp;
	__u32 tc_index;
	int nh_is_set = 0;
	int ret = 0;
	struct mpls_nh nh = {0};

	while (argc > 0) {
		if (strcmp(*argv, "swap") == 0) {
			struct mpls_hdr swap;
			char err[20];
			NEXT_ARG();
			if (mpls_parse_label(&swap, err, &argc, &argv))
				invarg(*argv, err);

			addattr_l(nlh, req_size, MPLS_ATTR_SWAP, &swap, sizeof(swap));
		} else if (strcmp(*argv, "push") == 0) {
			char err[20];
			struct rtattr *push_info;
			struct mpls_hdr push;
			if (no_push) {
				duparg("push", *argv);
				exit(-1);
			}
			NEXT_ARG();

			push_info = addattr_nest(nlh, req_size, MPLS_ATTR_PUSH);
			while (!mpls_parse_label(&push, err, &argc, &argv)) {
				addattr_l(nlh, req_size, MPLS_PUSH_1 + no_push, &push, sizeof(push));
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

			if (nh_is_set) {
				ret = -1;
				PREV_ARG();
				goto exit;
			}

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
					nh_is_set = 1;
					memcpy(&nh.ipv4.sin_addr, &addr.data, addr.bytelen);
					break;
				case AF_INET6:
					cmd = MPLS_ATTR_SEND_IPv6;
					nh.ipv6.sin6_family = AF_INET6;
					nh_is_set = 1;
					memcpy(&nh.ipv6.sin6_addr, &addr.data, addr.bytelen);
					break;
				default:
					invarg(*argv, "invalid nexthop type");
				}
			} else if (nh.iface != 0) {
				invarg(*argv, "invalid nexthop");
			} else if (nh_is_set) {
				ret = -1;
				PREV_ARG();
				goto exit;
			} else
				invarg(*argv, "invalid nexthop");
			addattr_l(nlh, req_size, cmd, &nh, sizeof(struct mpls_nh));
		}
		argc--; argv++; c++;
	}
exit:
	addattr_l(nlh, req_size, MPLS_ATTR_INSTR_COUNT, &c, sizeof(__u8));
	*pargc = argc;
	*pargv = argv;
	return ret;
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

static void
print_instructions(FILE *fp, struct rtattr **tb)
{
	int i;

	for(i = 0;i < MPLS_ATTR_MAX;i++) {
		if (!tb[i])
			continue;
		switch (i) {
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
				struct mpls_hdr *push;
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
					push = (struct mpls_hdr *)RTA_DATA(push_a[MPLS_PUSH_1 + j]);
					if (push->tc)
						fprintf(fp, "tc %hhu ", push->tc);
					fprintf(fp, "%u ", mpls_hdr_label(push));
				}
			}
			break;
		case MPLS_ATTR_SWAP:
			{
				struct mpls_hdr *swap = (struct mpls_hdr *)RTA_DATA(tb[MPLS_ATTR_SWAP]);
				fprintf(fp, "swap ");
				if (swap->tc)
					fprintf(fp, "tc %hhu ", swap->tc);
				fprintf(fp, "%u ", mpls_hdr_label(swap));
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

#endif
