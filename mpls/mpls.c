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
int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
int print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg);
int print_all_tunnels(void);
static int print_stats(void);
static const char *lookup_proto (int key);
static int mpls_get_mcast_group_ids(void);
int mpls_list(int cmd,int argc, char **argv);

static void usage(void)
{
	fprintf(stderr, "Usage: mpls ilm CMD label LABEL [(labelspace | ls) NUMBER] FWD\n");
	fprintf(stderr, "       mpls nhlfe CMD key KEY [[mtu MTU] | [propagate_ttl | no_propagate_ttl] | [instructions INSTR]]\n");
	fprintf(stderr, "       mpls xc CMD ilm_label LABEL ilm_ls NUMBER nhlfe_key KEY\n");
	fprintf(stderr, "       mpls (labelspace | ls) set NAME NUMBER\n");
	fprintf(stderr, "       mpls (labelspace | ls) set NAME -1\n");
	fprintf(stderr, "       mpls tunnel add nhlfe KEY\n");
	fprintf(stderr, "       mpls tunnel change dev NAME nhlfe KEY\n");
	fprintf(stderr, "       mpls tunnel del dev NAME\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "       mpls ilm show [label LABEL [(labelspace| ls) NUMBER]]\n");
	fprintf(stderr, "       mpls nhlfe show [key KEY]\n");
	fprintf(stderr, "       mpls xc show [ilm_label LABEL [ilm_ls NUMBER]]\n");
	fprintf(stderr, "       mpls (labelspace | ls) show [NAME]\n");
	fprintf(stderr, "       mpls tunnel show [dev NAME]\n");
	fprintf(stderr, "       mpls stats\n");
	fprintf(stderr, "       mpls show\n");
	fprintf(stderr, "       mpls monitor ...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where:\n");
	fprintf(stderr, "CMD    := add | del | change\n");
	fprintf(stderr, "NUMBER := 0 .. 255\n");
	fprintf(stderr, "LABEL  := 16 .. 1048575\n");
	fprintf(stderr, "KEY    := any unsigned int, except 0\n");
	fprintf(stderr, "NAME   := network device name (i.e. eth0)\n");
	fprintf(stderr, "ADDR   := ipv6 or ipv4 address\n");
	fprintf(stderr, "NH     := nexthop NAME [none|packet|ADDR]\n");
	fprintf(stderr, "FWD    := forward KEY \n");
	fprintf(stderr, "SET_EXP:= set-exp EXP | \n");
	fprintf(stderr, "	  nf2exp MASK  NFMARK - EXP ... [default - EXP] |\n");
	fprintf(stderr, "	  tc2exp MASK  TCINDEX - EXP ... [default - EXP] |\n");
	fprintf(stderr, "	  ds2exp MASK  DSCP - EXP ... [default - EXP] |\n");
	fprintf(stderr, "PUSH   := push [SET_EXP] LABEL\n");
	fprintf(stderr, "EXP    := 0 .. 7\n");
	fprintf(stderr, "DSCP   := 0 .. 63\n");
	fprintf(stderr, "NFMARK := 0 .. 63\n");
	fprintf(stderr, "TCINDEX:= 0 .. 63\n");
	fprintf(stderr, "MASK   := 0x0 .. 0x3f | 00 .. 077 | 0 .. 63 \n");
	fprintf(stderr, "INSTR  := NH | PUSH | pop | peek | FWD |\n");
	fprintf(stderr, "	  set-dscp DSCP | set-tcindex TCINDEX | \n");
	fprintf(stderr, "	  exp2tc EXP - TCINDEX ... [default - TCINDEX]| \n");
	fprintf(stderr, "	  exp2ds EXP - DSCP ... [default - DSCP] \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "!!!NOTE - recursive label lookup is done in context label space,\n");
	fprintf(stderr, "        - that's specified by upper label\n");
	fprintf(stderr, "        - e.g if upper label is 300, label space\n");
	fprintf(stderr, "        - in which the next label is looked is 300\n");
	fprintf(stderr, "\n");
	exit(-1);
}

/* Protocol lookup function. */
const char *lookup_proto(int key)
{
  const struct message *pnt;

  for (pnt = rtproto_str; pnt->key != 0; pnt++)
    if (pnt->key == key)
      return pnt->str;

  return "";
}

//prints stats from /proc/net/mpls_stats
int print_stats()
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

int mpls_table_list(int argc, char **argv)
{
	if (argc <= 0) {
		fprintf(stdout,"NHLFE entries:\n---\n");
		mpls_list(MPLS_CMD_GETNHLFE,0,NULL);
		fprintf(stdout,"---\nILM entries:\n---\n");
		mpls_list(MPLS_CMD_GETILM,0,NULL);
		fprintf(stdout,"---\nXC entries:\n---\n");
		mpls_list(MPLS_CMD_GETXC,0,NULL);
		fprintf(stdout,"---\nLABELSPACE entries:\n---\n");
		mpls_list(MPLS_CMD_GETLS,0,NULL);
		fprintf(stdout,"---\nSTATS:\n---\n");
		print_stats();
	}
	return 0;
}

void mpls_parse_label(__u32 *label, char **argv) {
	unsigned int l1;
	char *value;

	value = *argv;

	if (get_unsigned(&l1, value, 0) || l1 > 1048575)
		invarg(value, "invalid label value");

	set_key_label(*label, l1);
}

void
mpls_parse_instr(struct mpls_instr_req *instr, int *pargc, char ***pargv,
		int direction) {
	int argc = *pargc;
	char **argv = *pargv;
	int c = 0;

	while (argc > 0) {
		if (strcmp(*argv, "drop") == 0) {
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));
			instr->instr[c].opcode = MPLS_OP_DROP;
		} else if (strcmp(*argv, "nexthop") == 0) {
			NEXT_ARG();
			inet_prefix addr;
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_SET;
			instr->instr[c].set.iface = ll_name_to_index(*argv);
			NEXT_ARG();
			if(strcmp(*argv, "none") == 0) {
				struct sockaddr *s = &instr->instr[c].set.addr;
				memset(s, 0, sizeof(struct sockaddr));
			} else if (strcmp(*argv, "packet") == 0) {
				struct sockaddr *s = &instr->instr[c].set.addr;
				s->sa_family = AF_PACKET;
			} else if(**argv >= '0' && **argv <= '9') {
				get_prefix(&addr, *argv, 0);
				switch(addr.family){
				case AF_INET:{
					instr->instr[c].set.ipv4.sin_family = AF_INET;
					memcpy(&instr->instr[c].set.ipv4.sin_addr, &addr.data, addr.bytelen);
				}
				break;
				case AF_INET6:{
					instr->instr[c].set.ipv6.sin6_family = AF_INET6;
					memcpy(&instr->instr[c].set.ipv6.sin6_addr, &addr.data, addr.bytelen);
				}
				break;
				default:
					invarg(*argv, "invalid nexthop type");
				}
			} else {
				invarg(*argv, "invalid nexthop type");
			}
		} else if (strcmp(*argv, "push") == 0) {
			NEXT_ARG();
			//get exp
			if (strcmp(*argv, "set-exp") == 0) {
				__u32 exp;
				NEXT_ARG();
				if (get_unsigned(&exp, *argv, 0))
					invarg(*argv, "invalid EXP");
				//make room for new element
				instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

				instr->instr[c].opcode = MPLS_OP_SET_EXP;
				instr->instr[c].set_exp = exp;
				NEXT_ARG(); c++;
			} else if (strcmp(*argv, "nf2exp") == 0) {
				int done = 0;
				unsigned int nfmark;
				unsigned int exp;
				unsigned int mask;
				int got_default = 0;
				NEXT_ARG();
				/*make room for new element*/
				instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));
				if (!get_unsigned(&mask, *argv, 0)) {
					instr->instr[c].nf2exp.mask = mask;
					do {
						NEXT_ARG();
						if(strcmp(*argv, "default") == 0){
							got_default=1;
						} else if (get_unsigned(&nfmark, *argv, 0)) {
							done = 1;
							break;
						}
						NEXT_ARG();
						if (strcmp(*argv, "-") != 0){
							invarg(*argv, "expected '-' between nfmark and exp");
						}
						NEXT_ARG();
						if (get_unsigned(&exp, *argv, 0)) {
							invarg(*argv, "not unsigned int");
						}
						if (!got_default){
							int i;
							for (i=0;i<MPLS_NFMARK_NUM;i++){
								if((i & mask) == (nfmark & mask) )
									instr->instr[c].nf2exp.data[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_NFMARK_NUM;i++){
								if(instr->instr[c].nf2exp.data[i]==0)
									instr->instr[c].nf2exp.data[i] = exp;
							}
						}
						if(!NEXT_ARG_OK()){
							break;
						}
					} while (!done && !got_default);
				} else {
					invarg(*argv, "not unsigned int");
				}

				/*if we didn't reach last argument we will have here 1*/
				if(done)
					PREV_ARG();
				instr->instr[c].opcode = MPLS_OP_NF2EXP;
				NEXT_ARG(); c++;
			} else if (strcmp(*argv, "tc2exp") == 0) {
				int done = 0;
				unsigned int tcindex;
				unsigned int exp;
				unsigned int mask;
				int got_default = 0;
				NEXT_ARG();
				/*make room for new element*/
				instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

				if (!get_unsigned(&mask, *argv, 0)) {
					instr->instr[c].tc2exp.mask = mask;
					do {
						NEXT_ARG();
						if(strcmp(*argv, "default") == 0){
							got_default=1;
						} else if (get_unsigned(&tcindex, *argv, 0)) {
							done = 1;
							break;
						}
						NEXT_ARG();
						if (strcmp(*argv, "-") != 0){
							invarg(*argv, "expected '-' between tcindex and exp");
						}
						NEXT_ARG();
						if (get_unsigned(&exp, *argv, 0)) {
							invarg(*argv, "not unsigned int");
						}
						if (!got_default){
							int i;
							for (i=0;i<MPLS_TCINDEX_NUM;i++){
								if((i & mask) == (tcindex & mask) )
									instr->instr[c].tc2exp.data[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_TCINDEX_NUM;i++){
								if(instr->instr[c].nf2exp.data[i]==0)
									instr->instr[c].nf2exp.data[i] = exp;
							}
						}
						if(!NEXT_ARG_OK()){
							break;
						}
					} while (!done && !got_default);
				} else {
					invarg(*argv, "not unsigned int");
				}
				/*if we didn't reach last argument we will have here 1*/
				if(done)
					PREV_ARG();
				instr->instr[c].opcode = MPLS_OP_TC2EXP;
				NEXT_ARG(); c++;
			} else if (strcmp(*argv, "ds2exp") == 0) {
				int done = 0;
				unsigned int dscp;
				unsigned int exp;
				unsigned int mask;
				int got_default =0;
				/*if (direction == MPLS_IN)
					invarg(*argv, "invalid ILM instruction");*/
				NEXT_ARG();
				/*make room for new element*/
				instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

				if (!get_unsigned(&mask, *argv, 0)) {
					instr->instr[c].ds2exp.mask = mask;
					do {
						NEXT_ARG();
						if(strcmp(*argv, "default") == 0){
							got_default=1;
						} else if (get_unsigned(&dscp, *argv, 0)) {
							done = 1;
							break;
						}
						NEXT_ARG();
						if (strcmp(*argv, "-") != 0){
							invarg(*argv, "expected '-' between dscp and exp");
						}
						NEXT_ARG();
						if (get_unsigned(&exp, *argv, 0)) {
							invarg(*argv, "not unsigned int");
						}
						if (!got_default){
							int i;
							for (i=0;i<MPLS_DSMARK_NUM;i++){
								if((i & mask) == (dscp & mask))
									instr->instr[c].ds2exp.data[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_DSMARK_NUM;i++){
								if(instr->instr[c].ds2exp.data[i]==0)
									instr->instr[c].ds2exp.data[i] = exp;
							}
						}
						if(!NEXT_ARG_OK()){
							break;
						}
					} while (!done && !got_default);
				} else {
					invarg(*argv, "not unsigned int");
				}
				/*if we didn't reach last argument we will have here 1*/
				if(done)
					PREV_ARG();
				instr->instr[c].opcode = MPLS_OP_DS2EXP;
				NEXT_ARG(); c++;
			}
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_PUSH;

			mpls_parse_label(&instr->instr[c].push, argv);
		} else if (strcmp(*argv, "forward") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].fwd = key;
			instr->instr[c].opcode = MPLS_OP_FWD;
		} else if (strcmp(*argv, "pop") == 0) {
			/*if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");*/
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_POP;
		} else if (strcmp(*argv, "peek") == 0) {
			/*if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");*/
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_PEEK;
		}  else if (strcmp(*argv, "set-dscp") == 0) {
			__u32 dscp;
			/*if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");*/
			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_SET_DS;
			instr->instr[c].set_ds = dscp;
		} else if (strcmp(*argv, "set-tcindex") == 0) {
			__u32 tcindex;
			NEXT_ARG();
			if (get_unsigned(&tcindex, *argv, 0))
				invarg(*argv, "invalid TCINDEX");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->instr[c].opcode = MPLS_OP_SET_TC;
			instr->instr[c].set_tc = tcindex;
		} else if (strcmp(*argv, "exp2tc") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int tcindex;
			int got_default = 0;
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			do {
				NEXT_ARG();
				if(strcmp(*argv, "default") == 0){
					got_default=1;
				} else if (get_unsigned(&exp, *argv, 0)) {
					done = 1;
					break;
				}
				NEXT_ARG();
				if (strcmp(*argv, "-") != 0){
					invarg(*argv, "expected '-' between exp and tcindex");
				}
				NEXT_ARG();
				if (get_unsigned(&tcindex, *argv, 0)) {
					invarg(*argv, "not unsigned int");
				}
				if (!got_default){
					instr->instr[c].exp2tc.data[exp] = tcindex;
				} else {
					int i;
					for (i=0;i<MPLS_EXP_NUM;i++){
						if(instr->instr[c].exp2tc.data[i]==0)
							instr->instr[c].exp2tc.data[i] = tcindex;
					}
				}
				if(!NEXT_ARG_OK()){
					break;
				}
			} while (!done && !got_default);
			/*if we didn't reach last argument we will have here 1*/
			if(done)
				PREV_ARG();
			instr->instr[c].opcode = MPLS_OP_EXP2TC;
		} else if (strcmp(*argv, "exp2ds") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int dscp;
			int got_default = 0;
			/*if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");*/
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			do {
				NEXT_ARG();
				if(strcmp(*argv, "default") == 0){
					got_default=1;
				} else if (get_unsigned(&exp, *argv, 0)) {
					done = 1;
					break;
				}
				NEXT_ARG();
				if (strcmp(*argv, "-") != 0){
					invarg(*argv, "expected '-' between exp and dscp");
				}
				NEXT_ARG();
				if (get_unsigned(&dscp, *argv, 0)) {
					invarg(*argv, "not unsigned int");
				}
				if (!got_default){
					instr->instr[c].exp2ds.data[exp] = dscp;
				} else {
					int i;
					for (i=0;i<MPLS_EXP_NUM;i++){
						if(instr->instr[c].exp2ds.data[i]==0)
							instr->instr[c].exp2ds.data[i] = dscp;
					}
				}
				if(!NEXT_ARG_OK()){
					break;
				}
			} while (!done && !got_default);
			/*if we didn't reach last argument we will have here 1*/
			if(done)
				PREV_ARG();
			instr->instr[c].opcode = MPLS_OP_EXP2DS;
		} else {
			invarg(*argv, "invalid mpls instruction");
		}
		argc--; argv++; c++;
	}
	instr->instr_length = c;
	instr->direction = direction;
	*pargc = argc;
	*pargv = argv;
}

int
mpls_ilm_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;
	struct mpls_in_label_req	mil;
	struct mpls_instr_req*		instr;

	memset(&req, 0, sizeof(req));
	memset(&mil, 0, sizeof(mil));
	instr = (struct mpls_instr_req*)malloc(sizeof(struct mpls_instr_req));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = mpls_netlink_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "labelspace") == 0 ||
				strcmp(*argv, "ls") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0))
				invarg(*argv, "invalid label space");
			set_key_ls(mil.label, ls);
		} else if (strcmp(*argv, "label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&mil.label, argv);
		} else if (strcmp(*argv, "forward") == 0) {
			mpls_parse_instr(instr, &argc, &argv, MPLS_IN);
			mil.change_flag |= MPLS_CHANGE_INSTR;
		} else {
			invarg(*argv, "invalid ilm argument");
		}
		argc--; argv++;
	}

	mil.owner = RTPROT_STATIC;
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_ILM, &mil, sizeof(mil));
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, instr,
			sizeof(*instr)+instr->instr_length*sizeof(struct mpls_instr_elem));

	if (rtnl_talk(&rth_mpls, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);
	free(instr);
	return 0;
}

int
mpls_nhlfe_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;
	struct mpls_out_label_req 	mol;
	struct mpls_instr_req* 		instr = NULL;

	memset(&req, 0, sizeof(req));
	memset(&mol, 0, sizeof(mol));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = mpls_netlink_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			mol.label = key;
		} else if (strcmp(*argv, "mtu") == 0) {
			__u32 mtu;
			NEXT_ARG();
			if (get_unsigned(&mtu, *argv, 0))
				invarg(*argv, "invalid mtu");
			mol.mtu = mtu;
			mol.change_flag |= MPLS_CHANGE_MTU;
		} else if (strcmp(*argv, "no_propagate_ttl") == 0) {
			mol.propagate_ttl = 0;
			mol.change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "propagate_ttl") == 0) {
			mol.propagate_ttl = 1;
			mol.change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "instructions") == 0) {
			NEXT_ARG();
			instr = (struct mpls_instr_req*)malloc(sizeof(struct mpls_instr_req));
			mpls_parse_instr(instr, &argc, &argv, MPLS_OUT);
			mol.change_flag |= MPLS_CHANGE_INSTR;
		} else {
			usage();
		}
		argc--; argv++;
	}
	mol.owner = RTPROT_STATIC;
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof(mol));
	if(instr)
		addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, instr,
				sizeof(*instr)+instr->instr_length*sizeof(struct mpls_instr_elem));

	if (rtnl_talk(&rth_mpls, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);
	if(instr)
		free(instr);
	return 0;
}

int
mpls_xc_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_xconnect_req	xc;

	memset(&req, 0, sizeof(req));
	memset(&xc, 0, sizeof(xc));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = mpls_netlink_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {

		if (strcmp(*argv, "ilm_ls") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0) || ls > 255)
				invarg(*argv, "invalid labelspace");
			set_key_ls(xc.in, ls);
		} else if (strcmp(*argv, "ilm_label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&xc.in, argv);
		} else if (strcmp(*argv, "nhlfe_key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			xc.out = key;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (!xc.out && cmd!=MPLS_CMD_GETXC ) {
		fprintf(stderr, "you must specify a NHLFE key\n");
		exit(1);
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_XC, &xc, sizeof(xc));

	if (rtnl_talk(&rth_mpls, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);

	return 0;
}

int
mpls_ls_modify(int cmd, unsigned flags, int argc, char **argv)
{
	__u32 ls = -2;
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_ls_req ls_req;

	memset(&req, 0, sizeof(req));
	memset(&ls, 0, sizeof(ls));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = mpls_netlink_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	ls_req.ifindex = ll_name_to_index(*argv);

	if(NEXT_ARG_OK()) {
		NEXT_ARG();
		if (get_unsigned(&ls, *argv, 0))
		    if (!get_integer((int*) &ls, *argv, 0) && ls != (__u32) -1)
			invarg(*argv, "invalid labelspace");
	} else
		ls = 0;

	ls_req.ls = ls;

	if (ls_req.ifindex == 0 || ls_req.ls < -1) {
		fprintf(stderr, "Invalid arguments\n");
		exit(1);
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_LS, &ls_req, sizeof(ls_req));

	if (rtnl_talk(&rth_mpls, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);

	return 0;
}

int
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
			mtr.nhlfe_key = key;
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

void print_address(FILE *fp, struct sockaddr *addr) {
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
		fprintf(fp, "<unknown address family %d> ",
				addr->sa_family);
	}
}

inline void print_label(FILE *fp, __u32 *label) {
	fprintf(fp, "ls %d label %u ", key_ls(*label), key_label(*label));
}

inline void print_key(FILE *fp, __u32 *key) {
	fprintf(fp, "key %u ", *key);
}

void mpls_smart_print_key(FILE *fp, unsigned int key, int index, int *first,int *last, int *repeating_value,int array_length){
	if (*repeating_value == key){
		*last = index;
	} else if (*repeating_value == -1){
		*repeating_value = key;
		*first = index;
		*last = index;
	} else {
		if (*first == *last){
			fprintf(fp,"| %d->%8.8x | ",*first,*repeating_value);
		} else {
			fprintf(fp,"| %d..%d->%8.8x | ",*first,*last,*repeating_value);
		}
		*repeating_value = key;
		*first = index;
		*last = index;
	}

	if(index==array_length-1){
		if (*first == *last){
			fprintf(fp,"| %d->%8.8x |",*first,*repeating_value);
		} else {
			fprintf(fp,"| %d..%d->%8.8x |",*first,*last,*repeating_value);
		}
	}
}

void print_instructions(FILE *fp, struct mpls_instr_req *instr)
{
	struct mpls_instr_elem *ci;   /* current instruction */
	unsigned int key;
	int i,j;
	int first = 0, last = 0; // for print purposes
	int repeating_value = -1;


	for(i = 0;i < instr->instr_length;i++) {
		ci = &instr->instr[i];

		switch (ci->opcode) {
		case MPLS_OP_DROP:
			fprintf(fp, "drop ");
			break;
		case MPLS_OP_POP:
			fprintf(fp, "pop ");
			break;
		case MPLS_OP_PEEK:
			fprintf(fp, "peek ");
			break;
		case MPLS_OP_PUSH:
			fprintf(fp, "push ");
			fprintf(fp, "label %u ", key_label(ci->push));
			break;
		case MPLS_OP_FWD:
			fprintf(fp, "forward ");
			print_key(fp, &ci->fwd);
			break;
		case MPLS_OP_SET:
			fprintf(fp, "set %s ",
					ll_index_to_name(ci->set.iface));
			print_address(fp, &ci->set.addr);
			break;
		case MPLS_OP_SET_TC:
			fprintf(fp, "set-tcindex %hu ",ci->set_tc);
			break;
		case MPLS_OP_SET_DS:
			fprintf(fp, "set-dscp %hu ",ci->set_ds);
			break;
		case MPLS_OP_SET_EXP:
			fprintf(fp, "set-exp %hhu ",ci->set_exp);
			break;
		case MPLS_OP_EXP2TC:
			fprintf(fp, "exp2tc ");
			for(j=0;j<MPLS_EXP_NUM;j++) {
				key = ci->exp2tc.data[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_EXP_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_EXP2DS:
			fprintf(fp, "exp2ds ");
			for(j=0;j<MPLS_EXP_NUM;j++) {
				key = ci->exp2ds.data[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_EXP_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_TC2EXP:
			fprintf(fp, "tc2exp mask->0x%2.2hhx ",
					ci->tc2exp.mask);
			for(j=0;j<MPLS_TCINDEX_NUM;j++) {
				key = ci->tc2exp.data[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_TCINDEX_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_DS2EXP:
			fprintf(fp, "ds2exp mask->0x%2.2hhx ",
					ci->ds2exp.mask);
			for(j=0;j<MPLS_DSMARK_NUM;j++) {
				key = ci->ds2exp.data[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_DSMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_NF2EXP:
			fprintf(fp, "nf2exp mask->0x%2.2hhx ",
					ci->nf2exp.mask);
			for(j=0;j<MPLS_NFMARK_NUM;j++) {
				key = ci->nf2exp.data[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_NFMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		default:
			fprintf(fp, "<unknown opcode %d> ",
					ci->opcode);
		}
	}
}

int print_ilm(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_in_label_req *mil;
	struct mpls_instr_req *instr;

	if (cmd == MPLS_CMD_DELILM)
		fprintf(fp, "deleted ILM entry ");

	if (cmd == MPLS_CMD_NEWILM)
		fprintf(fp, "ILM entry ");

	mil = RTA_DATA(tb[MPLS_ATTR_ILM]);
	instr = RTA_DATA(tb[MPLS_ATTR_INSTR]);

	fprintf(fp, "label ");
	print_label(fp, &mil->label);

	fprintf (fp,"proto %s ", lookup_proto(mil->owner));
	fprintf(fp, "\n\t");
	if (instr && instr->instr_length) {
		print_instructions(fp, instr);
	}

	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

int print_xc(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_xconnect_req *xc;

	xc = RTA_DATA(tb[MPLS_ATTR_XC]);

	if (cmd == MPLS_CMD_DELXC)
		fprintf(fp, "deleted XC entry ");

	if (cmd == MPLS_CMD_NEWXC)
		fprintf(fp, "XC entry ");

	fprintf(fp, "ilm_label ");
	print_label(fp, &xc->in);
	fprintf(fp, "nhlfe_key 0x%08x ",xc->out);
	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

int print_ls(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_ls_req *ls;

	ls = RTA_DATA(tb[MPLS_ATTR_LS]);

	fprintf(fp, "LABELSPACE entry ");

	fprintf(fp, "dev %s ", ll_index_to_name(ls->ifindex));
	fprintf(fp, "ls %d ",ls->ls);
	fprintf(fp, "\n");
	fflush(fp);

	return 0;
}

int print_nhlfe(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_out_label_req *mol;
	struct mpls_instr_req *instr;

	mol = RTA_DATA(tb[MPLS_ATTR_NHLFE]);
	instr = RTA_DATA(tb[MPLS_ATTR_INSTR]);

	if (cmd == MPLS_CMD_DELNHLFE)
		fprintf(fp, "deleted NHLFE entry ");

	if (cmd == MPLS_CMD_NEWNHLFE)
		fprintf(fp, "NHLFE entry ");

	fprintf(fp, "key 0x%08x ", mol->label);
	fprintf(fp, "mtu %d ",mol->mtu);
	if (mol->propagate_ttl) {
		fprintf(fp, "propagate_ttl ");
	}
	fprintf(fp,"proto %s ", lookup_proto(mol->owner));
	fprintf(fp, "\n\t");
	if (instr && instr->instr_length) {
		print_instructions(fp, instr);
	}

	fprintf(fp, "\n");

	fflush(fp);
	return 0;
}

int print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg)
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
	if (cmd != SIOCDELTUNNEL)
		fprintf(fp, "0x%08x", mtr->nhlfe_key);
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
static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
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
int print_all_tunnels(){
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

int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
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
	case MPLS_CMD_NEWNHLFE:
	case MPLS_CMD_DELNHLFE:
		return print_nhlfe(ghdr->cmd, n,arg,tb);
	case MPLS_CMD_NEWXC:
	case MPLS_CMD_DELXC:
		return print_xc(ghdr->cmd, n,arg,tb);
	case MPLS_CMD_SETLS:
		return print_ls(ghdr->cmd, n,arg,tb);
	default:
		return 0;
	}

	return 0;
}

int mpls_list(int cmd,int argc, char **argv)
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

int do_ilm(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = argc-1>=5? 5: argc-1;
			return mpls_ilm_modify(MPLS_CMD_GETILM, 0, args, argv+1);
		}else
			return mpls_list(MPLS_CMD_GETILM,argc-1, argv+1);
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
int do_nhlfe(int argc, char **argv)
{
	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = argc-1>=2? 2: argc-1;
			return mpls_nhlfe_modify(MPLS_CMD_GETNHLFE, 0, args, argv+1);
		}else
			return mpls_list(MPLS_CMD_GETNHLFE,argc-1, argv+1);
	}
	if (matches(*argv, "add") == 0)
		return mpls_nhlfe_modify(MPLS_CMD_NEWNHLFE, NLM_F_CREATE, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_nhlfe_modify(MPLS_CMD_NEWNHLFE, 0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0){
		return mpls_nhlfe_modify(MPLS_CMD_DELNHLFE, 0, argc-1, argv+1);
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
int do_xc(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = argc-1>=5? 5: argc-1;
			return mpls_xc_modify(MPLS_CMD_GETXC, 0, args, argv+1);
		}else
			return mpls_list(MPLS_CMD_GETXC,argc-1, argv+1);
	}
	if (matches(*argv, "add") == 0)
		return mpls_xc_modify(MPLS_CMD_NEWXC, NLM_F_CREATE, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_xc_modify(MPLS_CMD_NEWXC, 0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0){
		return mpls_xc_modify(MPLS_CMD_DELXC, 0, argc-1, argv+1);
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

int do_ls(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = (argc - 1 >= 2) ? 2 : argc - 1;
			return mpls_ls_modify(MPLS_CMD_GETLS,0, args, argv+1);
		} else
			return mpls_list(MPLS_CMD_GETLS, argc-1, argv+1);
	}
	if (matches(*argv, "set") == 0)
		return mpls_ls_modify(MPLS_CMD_SETLS,0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
				"Option \"%s\" is unknown, try \"mpls --help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

int do_tunnel(int argc, char **argv) {
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

static int _mpls_get_mcast_group_ids(struct nlmsghdr *n){
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
static int mpls_get_mcast_group_ids(){
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

int main(int argc, char **argv) {
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

			if (matches(argv[1], "nhlfe") == 0) {
				retval = do_nhlfe(argc-2,argv+2);
			} else if (matches(argv[1], "ilm") == 0) {
				retval = do_ilm(argc-2,argv+2);
			} else if (matches(argv[1], "xc") == 0) {
				retval = do_xc(argc-2,argv+2);
			} else if (matches(argv[1], "labelspace") == 0 ||
					matches(argv[1], "ls") == 0) {
				retval = do_ls(argc-2,argv+2);
			} else if (matches(argv[1], "tunnel") == 0) {
				retval = do_tunnel(argc-2,argv+2);
			} else if (matches(argv[1], "stats") == 0) {
				retval = print_stats();
			} else if (matches(argv[1], "show") == 0){
				retval = mpls_table_list(argc-2,argv+2);
			} else {
				usage();
				retval = 1;
			}
			rtnl_close(&rth_mpls);
			rtnl_close(&rth);
		}
	} else {
		usage();
		retval = 1;
	}
	return retval;
}
