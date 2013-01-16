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
	__u32 pop;
	__u32 dscp;
	__u32 tc_index;
	__u32 ifindex;
	int nh_is_set = 0, num_push = 0, ret = 0, netns = -1;

	while (argc > 0) {
		if (strcmp(*argv, "swap") == 0) {
			struct mpls_hdr swap;
			char err[20];
			NEXT_ARG();
			if (mpls_parse_label(&swap, err, &argc, &argv))
				invarg(*argv, err);

			addattr_l(nlh, req_size, MPLSA_SWAP, &swap, sizeof(swap));
		} else if (strcmp(*argv, "push") == 0) {
			char err[20];
			struct rtattr *push_info;
			struct mpls_hdr push;

			if (num_push) {
				duparg("push", *argv);
				exit(-1);
			}
			NEXT_ARG();

			push_info = addattr_nest(nlh, req_size, MPLSA_PUSH);
			while (!mpls_parse_label(&push, err, &argc, &argv)) {
				addraw_l(nlh, req_size, &push, sizeof(push));
				num_push++;
				NEXT_ARG();
			}
			PREV_ARG();
			addattr_nest_end(nlh, push_info);

			if (num_push == 0)
				invarg(*argv, "invalid number of pushes");
		} else if (strcmp(*argv, "pop") == 0) {
			NEXT_ARG();
			if (get_unsigned(&pop, *argv, 0))
				invarg(*argv, "invalid number of pops");

			addattr_l(nlh, req_size, MPLSA_POP, &pop, sizeof(__u8));
		} else if (strcmp(*argv, "netns") == 0) {
			NEXT_ARG();
			if (netns != -1)
				duparg("netns", *argv);
			if ((netns = get_netns_fd(*argv)) >= 0) {
				char netns_name[MPLS_NETNS_NAME_MAX];
				strncpy(netns_name, *argv, MPLS_NETNS_NAME_MAX);
				addattr_l(nlh, req_size, MPLSA_NETNS_FD, &netns, 4);
				addattr_l(nlh, req_size, MPLSA_NETNS_NAME, netns_name, MPLS_NETNS_NAME_MAX);
			} else if (get_integer(&netns, *argv, 0) == 0)
				addattr_l(nlh, req_size, MPLSA_NETNS_PID, &netns, 4);
			else
				invarg("Invalid \"netns\" value\n", *argv);
		} else if (strcmp(*argv, "dscp") == 0) {
			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");

			addattr_l(nlh, req_size, MPLSA_DSCP, &dscp, sizeof(__u8));
		} else if (strcmp(*argv, "tc_index") == 0) {
			NEXT_ARG();
			if (get_unsigned(&tc_index, *argv, 0))
				invarg(*argv, "invalid TC_INDEX");

			addattr_l(nlh, req_size, MPLSA_TC_INDEX, &tc_index, sizeof(__u16));
		} else if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			ifindex = ll_name_to_index(*argv);
			if (!ifindex) {
				int len = strlen(*argv) + 1;
				if (len == 1)
					invarg("\"\" is not a valid device identifier\n", "dev");
				if (len > IFNAMSIZ)
					invarg("\"dev\" too long\n", *argv);
				addattr_l(nlh, req_size, MPLSA_NEXTHOP_IFNAME, *argv, len);
			} else
				addattr_l(nlh, req_size, MPLSA_NEXTHOP_OIF, &ifindex, sizeof(ifindex));
		} else if (strcmp(*argv, "global") == 0 ||
					strcmp(*argv, "g") == 0) {
			addattr_l(nlh, req_size, MPLSA_NEXTHOP_GLOBAL, NULL, 0);
		} else {
			inet_prefix addr;

			if (nh_is_set) {
				ret = -1;
				PREV_ARG();
				goto exit;
			}

			if(**argv >= '0' && **argv <= '9') {
				get_prefix(&addr, *argv, 0);
				nh_is_set = 1;
				switch(addr.family) {
				case AF_INET: {
					struct sockaddr_in sin;
					memset(&sin, 0, sizeof(sin));
					sin.sin_family = AF_INET;
					memcpy(&sin.sin_addr, addr.data, addr.bytelen);
					addattr_l(nlh, req_size, MPLSA_NEXTHOP_ADDR,
						  &sin, sizeof(sin));
					break;
				}
				case AF_INET6: {
					struct sockaddr_in6 sin6;
					sin6.sin6_family = AF_INET6;
					memset(&sin6, 0, sizeof(sin6));
					memcpy(&sin6.sin6_addr, addr.data, addr.bytelen);
					addattr_l(nlh, req_size, MPLSA_NEXTHOP_ADDR,
						  &sin6, sizeof(sin6));
					break;
				}
				default:
					invarg(*argv, "invalid nexthop type");
				}
			} else if (ifindex != 0) {
				invarg(*argv, "invalid nexthop");
			} else if (nh_is_set) {
				ret = -1;
				PREV_ARG();
				goto exit;
			} else
				invarg(*argv, "invalid nexthop");
		}
		argc--; argv++;
	}
exit:
	*pargc = argc;
	*pargv = argv;
	return ret;
}

static void
print_address(FILE *fp, const struct sockaddr *addr)
{
	char buf[256];
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in*)addr;
		inet_ntop(addr->sa_family, &sin->sin_addr,
				buf, sizeof(buf));
		fprintf(fp, "%s ", buf);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
		inet_ntop(addr->sa_family, &sin6->sin6_addr,
				buf, sizeof(buf));
		fprintf(fp, "%s ", buf);
		break;
	}
	case AF_PACKET: {
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
	struct mpls_hdr *mhdr;
	int i, j;

	for(i = 0; i <= MPLS_ATTR_MAX; i++) {
		if (!tb[i])
			continue;
		switch (i) {
		case MPLSA_POP:
			fprintf(fp, "pop %u ", *(__u8*)RTA_DATA(tb[i]));
			break;
		case MPLSA_PUSH:
			fprintf(fp, "push ");
			mhdr = (struct mpls_hdr *)RTA_DATA(tb[i]);
			for (j = 0; j < RTA_PAYLOAD(tb[i]) / MPLS_HDR_LEN; j++, mhdr++) {
				if (mhdr->tc)
					fprintf(fp, "tc %hhu ", mhdr->tc);
				fprintf(fp, "%u ", mpls_hdr_label(mhdr));
			}
			break;
		case MPLSA_NETNS_FD:
			break;
		case MPLSA_NETNS_NAME:
			fprintf(fp, "netns %s ", (char*)RTA_DATA(tb[i]));
			break;
		case MPLSA_NETNS_PID:
			fprintf(fp, "netns %d ", *(__u32*)RTA_DATA(tb[i]));
			break;
		case MPLSA_SWAP:
			mhdr = (struct mpls_hdr *)RTA_DATA(tb[i]);
			fprintf(fp, "swap ");
			if (mhdr->tc)
				fprintf(fp, "tc %hhu ", mhdr->tc);
			fprintf(fp, "%u ", mpls_hdr_label(mhdr));
			break;
		case MPLSA_TC_INDEX:
			fprintf(fp, "tc_index %hu ", *(__u16*)RTA_DATA(tb[i]));
			break;
		case MPLSA_DSCP:
			fprintf(fp, "dscp %hu ", *(__u8*)RTA_DATA(tb[i]));
			break;
		case MPLSA_NEXTHOP_GLOBAL:
			fprintf(fp, "global ");
			break;
		case MPLSA_NEXTHOP_IFNAME:
			fprintf(fp, "dev %s ", (char *)RTA_DATA(tb[i]));
			break;
		case MPLSA_NEXTHOP_OIF:
			fprintf(fp, "dev %s ", ll_index_to_name(*(__u32*)RTA_DATA(tb[i])));
			break;
		case MPLSA_NEXTHOP_ADDR:
			print_address(fp, (struct sockaddr *)RTA_DATA(tb[i]));
			break;
		default:
			fprintf(fp, "<unknown opcode %d> ", i);
		}
	}
}

#endif
