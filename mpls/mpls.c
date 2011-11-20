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
#include <linux/mpls.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <linux/genetlink.h>

#include "SNAPSHOT.h"
#include "utils.h"
#include "mpls.h"

int show_details = 0;
int show_raw = 0;
int resolve_hosts = 0;

unsigned int mpls_grp_ilm;
unsigned int mpls_grp_nhlfe;
unsigned int mpls_grp_xc;
unsigned int mpls_grp_lspace;
unsigned int mpls_grp_get;

struct rtnl_handle rth_nhlfe;	/* RTNL for NHLFE*/
struct rtnl_handle rth_ilm;		/* RTNL for ILM*/
struct rtnl_handle rth_xc;		/* RTNL for XC */
struct rtnl_handle rth_labelspace;		/* RTNL for Labelspace */
struct rtnl_handle rth = { .fd = -1 }; /*for getting interface names*/

extern int do_mplsmonitor(int argc, char **argv,unsigned int MPLS_GRP_NHLFE,unsigned int MPLS_GRP_ILM,unsigned int MPLS_GRP_XC,unsigned int MPLS_GRP_LABELSPACE);
int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
int print_tunnel(int cmd, const struct mpls_tunnel_req *mtr, void *arg);
int print_all_tunnels(void);
static int print_stats(void);
static const char *lookup_proto (int key);
static int mpls_get_mcast_group_ids(void);
int mpls_list(int cmd,int argc, char **argv);

static void usage(void)
{
	fprintf(stderr, "Usage: mpls ilm CMD label LABEL labelspace NUMBER [[proto PROTO] | [instructions INSTR]]\n");
	fprintf(stderr, "       mpls nhlfe CMD key KEY [[mtu MTU] | [propagate_ttl | no_propagate_ttl] | [instructions INSTR]]\n");
	fprintf(stderr, "       mpls xc CMD ilm_label LABEL ilm_labelspace NUMBER nhlfe_key KEY\n");
	fprintf(stderr, "       mpls labelspace set dev NAME labelspace NUMBER\n");
	fprintf(stderr, "       mpls labelspace set dev NAME labelspace -1\n");
	fprintf(stderr, "       mpls tunnel add nhlfe KEY\n");
	fprintf(stderr, "       mpls tunnel change dev NAME nhlfe KEY\n");
	fprintf(stderr, "       mpls tunnel del dev NAME\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "       mpls ilm show [label LABEL [labelspace NUMBER]]\n");
	fprintf(stderr, "       mpls nhlfe show [key KEY]\n");
	fprintf(stderr, "       mpls xc show [ilm_label LABEL [ilm_labelspace NUMBER]]\n");
	fprintf(stderr, "       mpls labelspace show [dev NAME]\n");
	fprintf(stderr, "       mpls tunnel show [dev NAME]\n");
	fprintf(stderr, "       mpls stats\n");
	fprintf(stderr, "       mpls show\n");
	fprintf(stderr, "       mpls monitor ...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where:\n");
	fprintf(stderr, "CMD    := add | del | change\n");
	fprintf(stderr, "NUMBER := 0 .. 255\n");
	fprintf(stderr, "TYPE   := gen | atm | fr\n");
	fprintf(stderr, "VALUE  := 16 .. 1048575 | <VPI>/<VCI> | 16 .. 1023\n");
	fprintf(stderr, "LABEL  := TYPE VALUE\n");
	fprintf(stderr, "KEY    := any unsigned int, except 0\n");
	fprintf(stderr, "NAME   := network device name (i.e. eth0)\n");
	fprintf(stderr, "PROTO  := ipv4 | ipv6\n");
	fprintf(stderr, "ADDR   := ipv6 or ipv4 address\n");
	fprintf(stderr, "NH     := nexthop NAME [none|packet|ADDR]\n");
	fprintf(stderr, "FWD    := forward KEY\n");
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
	fprintf(stderr, "INSTR  := NH | PUSH | pop | deliver | peek | FWD |\n");
	fprintf(stderr, "	  set-dscp DSCP | set-tcindex TCINDEX | set-rx-if NAME |\n");
	fprintf(stderr, "	  exp2tc EXP - TCINDEX ... [default - TCINDEX]| \n");
	fprintf(stderr, "	  exp2ds EXP - DSCP ... [default - DSCP]| \n");
	fprintf(stderr, "	  expfwd EXP - KEY ... [default - KEY]|\n");
	fprintf(stderr, "	  nffwd MASK  NFMARK - KEY ... [default - KEY] |\n");
	fprintf(stderr, "	  dsfwd MASK  DSCP - KEY ... [default - KEY] \n");
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

	fprintf(stdout,buf);
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
		mpls_list(MPLS_CMD_GETLABELSPACE,0,NULL);
		fprintf(stdout,"---\nSTATS:\n---\n");
		print_stats();
	}
	return 0;
}

void mpls_parse_label (struct mpls_label *label, int *pargc, char ***pargv) {
	unsigned int l1, l2;
	char *value;
	int argc = *pargc;
	char **argv = *pargv;

	if (strncmp(*argv, "fr", 2) == 0) {
		label->ml_type = MPLS_LABEL_FR;
	} else if (strncmp(*argv, "atm", 3) == 0) {
		label->ml_type = MPLS_LABEL_ATM;
	} else if (strncmp(*argv, "gen", 3) == 0) {
		label->ml_type = MPLS_LABEL_GEN;
	} else {
		invarg(*argv, "invalid mpls label type");
	}

	NEXT_ARG();
	value = *argv;

	switch (label->ml_type) {
	case MPLS_LABEL_GEN:
		if (get_unsigned(&l1, value, 0) || l1 > 1048575)
			invarg(value, "invalid label value");
		label->u.ml_gen = l1;
		break;
	case MPLS_LABEL_ATM:
		if (sscanf(value, "%u/%d", &l1, &l2) != 2)
			invarg(value, "invalid label value");
		label->u.ml_atm.mla_vpi = l1;
		label->u.ml_atm.mla_vci = l2;
	case MPLS_LABEL_FR:
		if (get_unsigned(&l1, value, 0) || l1 > 1023)
			invarg(value, "invalid label value");
		label->u.ml_fr = l1;
	default:
		fprintf(stderr, "Invalid label type!\n");
		exit(-1);
	}
	*pargc = argc;
	*pargv = argv;
}

void
mpls_parse_instr(struct mpls_instr_req *instr, int *pargc, char ***pargv,
		int direction) {
	int argc = *pargc;
	char **argv = *pargv;
	int c = 0;

	while (argc > 0) {
		if (strcmp(*argv, "nexthop") == 0) {
			NEXT_ARG();
			inet_prefix addr;
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_SET;
			instr->mir_instr[c].mir_set.mni_if = ll_name_to_index(*argv);
			NEXT_ARG();
			if(strcmp(*argv, "none") == 0) {
				struct sockaddr *s = &instr->mir_instr[c].mir_set.mni_addr;
				memset(s, 0, sizeof(struct sockaddr));
			} else if (strcmp(*argv, "packet") == 0) {
				struct sockaddr *s = &instr->mir_instr[c].mir_set.mni_addr;
				s->sa_family = AF_PACKET;
			} else if(**argv >= '0' && **argv <= '9') {
				get_prefix(&addr, *argv, 0);
				switch(addr.family){
				case AF_INET:{
					instr->mir_instr[c].mir_set.mni_nh.ipv4.sin_family = AF_INET;
					memcpy(&instr->mir_instr[c].mir_set.mni_nh.ipv4.sin_addr, &addr.data, addr.bytelen);
				}
				break;
				case AF_INET6:{
					instr->mir_instr[c].mir_set.mni_nh.ipv6.sin6_family = AF_INET6;
					memcpy(&instr->mir_instr[c].mir_set.mni_nh.ipv6.sin6_addr, &addr.data, addr.bytelen);
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

				instr->mir_instr[c].mir_opcode = MPLS_OP_SET_EXP;
				instr->mir_instr[c].mir_set_exp = exp;
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
					instr->mir_instr[c].mir_nf2exp.n2e_mask = mask;
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
									instr->mir_instr[c].mir_nf2exp.n2e[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_NFMARK_NUM;i++){
								if(instr->mir_instr[c].mir_nf2exp.n2e[i]==0)
									instr->mir_instr[c].mir_nf2exp.n2e[i] = exp;
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
				instr->mir_instr[c].mir_opcode = MPLS_OP_NF2EXP;
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
					instr->mir_instr[c].mir_tc2exp.t2e_mask = mask;
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
									instr->mir_instr[c].mir_tc2exp.t2e[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_TCINDEX_NUM;i++){
								if(instr->mir_instr[c].mir_nf2exp.n2e[i]==0)
									instr->mir_instr[c].mir_nf2exp.n2e[i] = exp;
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
				instr->mir_instr[c].mir_opcode = MPLS_OP_TC2EXP;
				NEXT_ARG(); c++;
			} else if (strcmp(*argv, "ds2exp") == 0) {
				int done = 0;
				unsigned int dscp;
				unsigned int exp;
				unsigned int mask;
				int got_default =0;
				if (direction == MPLS_IN)
					invarg(*argv, "invalid ILM instruction");
				NEXT_ARG();
				/*make room for new element*/
				instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

				if (!get_unsigned(&mask, *argv, 0)) {
					instr->mir_instr[c].mir_ds2exp.d2e_mask = mask;
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
									instr->mir_instr[c].mir_ds2exp.d2e[i] = exp;
							}
						} else {
							int i;
							for (i=0;i<MPLS_DSMARK_NUM;i++){
								if(instr->mir_instr[c].mir_ds2exp.d2e[i]==0)
									instr->mir_instr[c].mir_ds2exp.d2e[i] = exp;
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
				instr->mir_instr[c].mir_opcode = MPLS_OP_DS2EXP;
				NEXT_ARG(); c++;
			}
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_PUSH;
			*pargc = argc; *pargv = argv;
			mpls_parse_label(&instr->mir_instr[c].mir_push,
					pargc, pargv);
			argc = *pargc; argv = *pargv;
		} else if (strcmp(*argv, "forward") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_fwd.ml_type = MPLS_LABEL_KEY;
			instr->mir_instr[c].mir_fwd.u.ml_key = key;
			instr->mir_instr[c].mir_opcode = MPLS_OP_FWD;
		} else if (strcmp(*argv, "pop") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_POP;
		} else if (strcmp(*argv, "peek") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_PEEK;
		} else if (strcmp(*argv, "deliver") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_DLV;
		} else if (strcmp(*argv, "set-dscp") == 0) {
			__u32 dscp;
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_DS;
			instr->mir_instr[c].mir_set_ds = dscp;
		} else if (strcmp(*argv, "set-tcindex") == 0) {
			__u32 tcindex;
			NEXT_ARG();
			if (get_unsigned(&tcindex, *argv, 0))
				invarg(*argv, "invalid TCINDEX");
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_TC;
			instr->mir_instr[c].mir_set_tc = tcindex;
		} else if (strcmp(*argv, "set-rx-if") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			NEXT_ARG();
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_RX;
			instr->mir_instr[c].mir_set_rx =ll_name_to_index(*argv);
		} else if (strcmp(*argv, "expfwd") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int key;
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
					invarg(*argv, "expected '-' between exp and key");
				}
				NEXT_ARG();
				if (get_unsigned(&key, *argv, 0)) {
					invarg(*argv, "not unsigned int");
				}
				if (!got_default){
					instr->mir_instr[c].mir_exp_fwd.ef_key[exp] = key;
				} else {
					int i;
					for (i=0;i<MPLS_EXP_NUM;i++){
						if(instr->mir_instr[c].mir_exp_fwd.ef_key[i]==0)
							instr->mir_instr[c].mir_exp_fwd.ef_key[i] = key;
					}
				}

				if(!NEXT_ARG_OK()){
					break;
				}
			} while (!done && !got_default);
			/*if we didn't reach last argument we will have here 1*/
			if(done)
				PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP_FWD;
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
					instr->mir_instr[c].mir_exp2tc.e2t[exp] = tcindex;
				} else {
					int i;
					for (i=0;i<MPLS_EXP_NUM;i++){
						if(instr->mir_instr[c].mir_exp2tc.e2t[i]==0)
							instr->mir_instr[c].mir_exp2tc.e2t[i] = tcindex;
					}
				}
				if(!NEXT_ARG_OK()){
					break;
				}
			} while (!done && !got_default);
			/*if we didn't reach last argument we will have here 1*/
			if(done)
				PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP2TC;
		} else if (strcmp(*argv, "exp2ds") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int dscp;
			int got_default = 0;
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
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
					instr->mir_instr[c].mir_exp2ds.e2d[exp] = dscp;
				} else {
					int i;
					for (i=0;i<MPLS_EXP_NUM;i++){
						if(instr->mir_instr[c].mir_exp2ds.e2d[i]==0)
							instr->mir_instr[c].mir_exp2ds.e2d[i] = dscp;
					}
				}
				if(!NEXT_ARG_OK()){
					break;
				}
			} while (!done && !got_default);
			/*if we didn't reach last argument we will have here 1*/
			if(done)
				PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP2DS;
		} else if (strcmp(*argv, "nffwd") == 0) {
			int done = 0;
			unsigned int nfmark;
			unsigned int key;
			int got_default = 0;
			unsigned int mask;
			NEXT_ARG();
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_nf_fwd.nf_mask = mask;
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
						invarg(*argv, "expected '-' between nfmark and key");
					}
					NEXT_ARG();
					if (get_unsigned(&key, *argv, 0)) {
						invarg(*argv, "not unsigned int");
					}
					if (!got_default){
						int i;
						for (i=0;i<MPLS_NFMARK_NUM;i++){
							if((i & mask)==(nfmark & mask))
								instr->mir_instr[c].mir_nf_fwd.nf_key[i] = key;
						}
					} else {
						int i;
						for (i=0;i<MPLS_NFMARK_NUM;i++){
							if(instr->mir_instr[c].mir_nf_fwd.nf_key[i]==0)
								instr->mir_instr[c].mir_nf_fwd.nf_key[i] = key;
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
			instr->mir_instr[c].mir_opcode = MPLS_OP_NF_FWD;
		} else if (strcmp(*argv, "dsfwd") == 0) {
			int done = 0;
			unsigned int dscp;
			unsigned int key;
			unsigned int mask;
			int got_default = 0;
			NEXT_ARG();
			/*make room for new element*/
			instr=(struct mpls_instr_req*)realloc(instr,sizeof(*instr)+(c+1)*sizeof(struct mpls_instr_elem));

			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_ds_fwd.df_mask = mask;
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
						invarg(*argv, "expected '-' between dscp and key");
					}
					NEXT_ARG();
					if (get_unsigned(&key, *argv, 0)) {
						invarg(*argv, "not unsigned int");
					}
					if (!got_default){
						int i;
						for (i=0;i<MPLS_DSMARK_NUM;i++){
							if((i & mask) == (dscp & mask))
								instr->mir_instr[c].mir_ds_fwd.df_key[dscp] = key;
						}
					} else {
						int i;
						for (i=0;i<MPLS_DSMARK_NUM;i++){
							if(instr->mir_instr[c].mir_ds_fwd.df_key[i]==0)
								instr->mir_instr[c].mir_ds_fwd.df_key[i] = key;
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
			instr->mir_instr[c].mir_opcode = MPLS_OP_DS_FWD;
		} else {
			invarg(*argv, "invalid mpls instruction");
		}
		argc--; argv++; c++;
	}
	instr->mir_instr_length = c;
	instr->mir_direction = direction;
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
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	mil.mil_proto = AF_INET;

	while (argc > 0) {
		if (strcmp(*argv, "labelspace") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0) || ls > 255)
				invarg(*argv, "invalid labelspace");
			mil.mil_label.ml_labelspace = ls;
		} else if (strcmp(*argv, "label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&mil.mil_label, &argc, &argv);
		} else if (strcmp(*argv, "proto") == 0) {
			NEXT_ARG();
			if (strncmp(*argv, "ipv4", 4) == 0) {
				mil.mil_proto = AF_INET;
			} else if (strncmp(*argv, "ipv6", 4) == 0) {
				mil.mil_proto = AF_INET6;
			} else if (strncmp(*argv, "packet", 6) == 0) {
				mil.mil_proto = AF_PACKET;
			} else {
				invarg(*argv, "invalid ilm proto");
			}
			mil.mil_change_flag |= MPLS_CHANGE_PROTO;
		} else if (strcmp(*argv, "instructions") == 0) {
			NEXT_ARG();
			mpls_parse_instr(instr, &argc, &argv, MPLS_IN);
			mil.mil_change_flag |= MPLS_CHANGE_INSTR;
		} else {
			invarg(*argv, "invalid ilm argument");
		}
		argc--; argv++;
	}

	if (!mil.mil_label.ml_type) {
		fprintf(stderr, "you must specify a label value\n");
		exit(1);
	}
	mil.mil_owner = RTPROT_STATIC;
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_ILM, &mil, sizeof(mil));
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, instr, sizeof(*instr)+instr->mir_instr_length*sizeof(struct mpls_instr_elem));

	if (rtnl_talk(&rth_ilm, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
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
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			mol.mol_label.u.ml_key = key;
			mol.mol_label.ml_type = MPLS_LABEL_KEY;
		} else if (strcmp(*argv, "mtu") == 0) {
			__u32 mtu;
			NEXT_ARG();
			if (get_unsigned(&mtu, *argv, 0))
				invarg(*argv, "invalid mtu");
			mol.mol_mtu = mtu;
			mol.mol_change_flag |= MPLS_CHANGE_MTU;
		} else if (strcmp(*argv, "no_propagate_ttl") == 0) {
			mol.mol_propagate_ttl = 0;
			mol.mol_change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "propagate_ttl") == 0) {
			mol.mol_propagate_ttl = 1;
			mol.mol_change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "instructions") == 0) {
			NEXT_ARG();
			instr = (struct mpls_instr_req*)malloc(sizeof(struct mpls_instr_req));
			mpls_parse_instr(instr, &argc, &argv, MPLS_OUT);
			mol.mol_change_flag |= MPLS_CHANGE_INSTR;
		} else {
			usage();
		}
		argc--; argv++;
	}
	mol.mol_owner = RTPROT_STATIC;
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof(mol));
	if(instr)
		addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, instr, sizeof(*instr)+instr->mir_instr_length*sizeof(struct mpls_instr_elem));

	if (rtnl_talk(&rth_nhlfe, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
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
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {

		if (strcmp(*argv, "ilm_labelspace") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0) || ls > 255)
				invarg(*argv, "invalid labelspace");
			xc.mx_in.ml_labelspace = ls;
		} else if (strcmp(*argv, "ilm_label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&xc.mx_in, &argc, &argv);
		} else if (strcmp(*argv, "nhlfe_key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			xc.mx_out.u.ml_key = key;
			xc.mx_out.ml_type = MPLS_LABEL_KEY;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (!xc.mx_in.ml_type) {
		fprintf(stderr, "you must specify a ILM label value\n");
		exit(1);
	}

	if (!xc.mx_out.u.ml_key && cmd!=MPLS_CMD_GETXC ) {
		fprintf(stderr, "you must specify a NHLFE key\n");
		exit(1);
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_XC, &xc, sizeof(xc));

	if (rtnl_talk(&rth_xc, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
		exit(2);

	print_mpls(NULL, &req.n, stdout);

	return 0;
}

int
mpls_labelspace_modify(int cmd, unsigned flags, int argc, char **argv)
{
	__u32 labelspace = -2;
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_labelspace_req 	ls;

	memset(&req, 0, sizeof(req));
	memset(&ls, 0, sizeof(ls));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			ls.mls_ifindex = ll_name_to_index(*argv);
		} else if (strcmp(*argv, "labelspace") == 0) {
			NEXT_ARG();
			if (get_unsigned(&labelspace, *argv, 0))
				invarg(*argv, "invalid labelspace");
			ls.mls_labelspace = labelspace;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (ls.mls_ifindex == 0 || ls.mls_labelspace == -2) {
		fprintf(stderr, "Invalid arguments\n");
		exit(1);
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_LABELSPACE, &ls, sizeof(ls));

	if (rtnl_talk(&rth_labelspace, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
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

			strncpy(mtr.mt_ifname, *argv, IFNAMSIZ);
		} else if ((cmd == SIOCADDTUNNEL || cmd == SIOCCHGTUNNEL) && strcmp(*argv, "nhlfe") == 0) {
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid NHLFE key");
			mtr.mt_nhlfe_key = key;
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

void print_label(FILE *fp, struct mpls_label *label) {
	switch (label->ml_type) {
	case MPLS_LABEL_GEN:
		fprintf(fp, "gen %d ", label->u.ml_gen);
		break;
	case MPLS_LABEL_ATM:
		fprintf(fp, "atm %d/%d ", label->u.ml_atm.mla_vpi,
				label->u.ml_atm.mla_vci);
		break;
	case MPLS_LABEL_FR:
		fprintf(fp, "fr %d ", label->u.ml_fr);
		break;
	case MPLS_LABEL_KEY:
		fprintf(fp, "key 0x%08x ", label->u.ml_key);
		break;
	default:
		fprintf(fp, "<unknown label type %d> ", label->ml_type);
	}
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


	for(i = 0;i < instr->mir_instr_length;i++) {
		ci = &instr->mir_instr[i];

		switch (ci->mir_opcode) {
		case MPLS_OP_NOP:
			fprintf(fp, "noop ");
			break;
		case MPLS_OP_POP:
			fprintf(fp, "pop ");
			break;
		case MPLS_OP_PEEK:
			fprintf(fp, "peek ");
			break;
		case MPLS_OP_PUSH:
			fprintf(fp, "push ");
			print_label(fp, &ci->mir_push);
			break;
		case MPLS_OP_FWD:
			fprintf(fp, "forward ");
			print_label(fp, &ci->mir_fwd);
			break;
		case MPLS_OP_DLV:
			fprintf(fp, "deliver ");
			break;
		case MPLS_OP_SET:
			fprintf(fp, "set %s ",
					ll_index_to_name(ci->mir_set.mni_if));
			print_address(fp, &ci->mir_set.mni_addr);
			break;
		case MPLS_OP_SET_RX:
			fprintf(fp, "set-rx-if %s ",
					ll_index_to_name(ci->mir_set_rx));
			break;
		case MPLS_OP_SET_TC:
			fprintf(fp, "set-tcindex %hu ",ci->mir_set_tc);
			break;
		case MPLS_OP_SET_DS:
			fprintf(fp, "set-dscp %hu ",ci->mir_set_ds);
			break;
		case MPLS_OP_SET_EXP:
			fprintf(fp, "set-exp %hhu ",ci->mir_set_exp);
			break;
		case MPLS_OP_NF_FWD:
			fprintf(fp, "nffwd mask->0x%2.2hhx ",
					ci->mir_nf_fwd.nf_mask);
			for(j=0;j<MPLS_NFMARK_NUM;j++) {
				key = ci->mir_nf_fwd.nf_key[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_NFMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_DS_FWD:
			fprintf(fp, "dsfwd mask->0x%2.2hhx ",
					ci->mir_ds_fwd.df_mask);
			for(j=0;j<MPLS_DSMARK_NUM;j++) {
				key = ci->mir_ds_fwd.df_key[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_DSMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_EXP_FWD:
			fprintf(fp, "exp-fwd ");
			for(j=0;j<MPLS_EXP_NUM;j++) {
				key = ci->mir_exp_fwd.ef_key[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_EXP_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_EXP2TC:
			fprintf(fp, "exp2tc ");
			for(j=0;j<MPLS_EXP_NUM;j++) {
				key = ci->mir_exp2tc.e2t[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_EXP_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_EXP2DS:
			fprintf(fp, "exp2ds ");
			for(j=0;j<MPLS_EXP_NUM;j++) {
				key = ci->mir_exp2ds.e2d[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_EXP_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_TC2EXP:
			fprintf(fp, "tc2exp mask->0x%2.2hhx ",
					ci->mir_tc2exp.t2e_mask);
			for(j=0;j<MPLS_TCINDEX_NUM;j++) {
				key = ci->mir_tc2exp.t2e[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_TCINDEX_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_DS2EXP:
			fprintf(fp, "ds2exp mask->0x%2.2hhx ",
					ci->mir_ds2exp.d2e_mask);
			for(j=0;j<MPLS_DSMARK_NUM;j++) {
				key = ci->mir_ds2exp.d2e[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_DSMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		case MPLS_OP_NF2EXP:
			fprintf(fp, "nf2exp mask->0x%2.2hhx ",
					ci->mir_nf2exp.n2e_mask);
			for(j=0;j<MPLS_NFMARK_NUM;j++) {
				key = ci->mir_nf2exp.n2e[j];
				mpls_smart_print_key(fp, key,j,&first,&last,&repeating_value,MPLS_NFMARK_NUM);
			}
			fprintf(fp,"\n\t");
			break;
		default:
			fprintf(fp, "<unknown opcode %d> ",
					ci->mir_opcode);
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
	print_label(fp, &mil->mil_label);

	fprintf(fp, "labelspace %d ", mil->mil_label.ml_labelspace);

	switch(mil->mil_proto) {
	case AF_INET:
		fprintf(fp, "ipv4 ");
		break;
	case AF_INET6:
		fprintf(fp, "ipv6 ");
		break;
	case AF_PACKET:
		fprintf(fp, "packet ");
		break;
	default:
		fprintf(fp, "<unknown protocol %d> ", mil->mil_proto);
	}
	fprintf (fp,"proto %s ", lookup_proto(mil->mil_owner));
	fprintf(fp, "\n\t");
	if (instr && instr->mir_instr_length) {
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
	print_label(fp, &xc->mx_in);
	fprintf(fp, "ilm_labelspace %d ", xc->mx_in.ml_labelspace);
	fprintf(fp, "nhlfe_key 0x%08x ",xc->mx_out.u.ml_key);
	fprintf(fp, "\n");
	fflush(fp);
	return 0;
}

int print_labelspace(int cmd, const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_labelspace_req *ls;

	ls = RTA_DATA(tb[MPLS_ATTR_LABELSPACE]);

	fprintf(fp, "LABELSPACE entry ");

	fprintf(fp, "dev %s ", ll_index_to_name(ls->mls_ifindex));
	fprintf(fp, "labelspace %d ",ls->mls_labelspace);
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

	fprintf(fp, "key 0x%08x ", mol->mol_label.u.ml_key);
	fprintf(fp, "mtu %d ",mol->mol_mtu);
	if (mol->mol_propagate_ttl) {
		fprintf(fp, "propagate_ttl ");
	}
	fprintf(fp,"proto %s ", lookup_proto(mol->mol_owner));
	fprintf(fp, "\n\t");
	if (instr && instr->mir_instr_length) {
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
	fprintf(fp, "%s ", mtr->mt_ifname);
	if (cmd != SIOCDELTUNNEL)
		fprintf(fp, "0x%08x", mtr->mt_nhlfe_key);
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
	struct rtattr *tb[MPLS_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;

	if (n->nlmsg_type !=  PF_MPLS) {
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
	case MPLS_CMD_NEWILM:
	case MPLS_CMD_DELILM:
		return print_ilm(ghdr->cmd, n,arg,tb);
	case MPLS_CMD_NEWNHLFE:
	case MPLS_CMD_DELNHLFE:
		return print_nhlfe(ghdr->cmd, n,arg,tb);
	case MPLS_CMD_NEWXC:
	case MPLS_CMD_DELXC:
		return print_xc(ghdr->cmd, n,arg,tb);
	case MPLS_CMD_SETLABELSPACE:
		return print_labelspace(ghdr->cmd, n,arg,tb);
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
	req.n.nlmsg_type = PF_MPLS;
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

int do_labelspace(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
			matches(*argv, "show") == 0){
		if(NEXT_ARG_OK()){
			int args;
			args = argc-1>=2? 2: argc-1;
			return mpls_labelspace_modify(MPLS_CMD_GETLABELSPACE,0, args, argv+1);
		} else
			return mpls_list(MPLS_CMD_GETLABELSPACE,argc-1, argv+1);
	}
	if (matches(*argv, "set") == 0)
		return mpls_labelspace_modify(MPLS_CMD_SETLABELSPACE,0, argc-1, argv+1);
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

	if (tb[CTRL_ATTR_MCAST_GROUPS]) {
		struct rtattr *tb2[GENL_MAX_FAM_GRPS + 1];
		int i;

		parse_rtattr_nested(tb2, GENL_MAX_FAM_GRPS,	tb[CTRL_ATTR_MCAST_GROUPS]);
		mpls_grp_ilm = 0;
		mpls_grp_nhlfe = 0;
		mpls_grp_xc = 0;
		mpls_grp_lspace = 0;
		mpls_grp_get = 0;

		for (i = 0; i < GENL_MAX_FAM_GRPS; i++) {
			if (tb2[i]) {
				struct rtattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1];
				parse_rtattr_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, tb2[i]);
				if (tb[1]) {
					char *name = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_NAME]);
					if(strncmp(name,MPLS_GRP_ILM_NAME,strlen(MPLS_GRP_ILM_NAME))==0){
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_grp_ilm = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for ILM mcast group!\n");
							return -1;
						}
					} else if (strncmp(name,MPLS_GRP_NHLFE_NAME,strlen(MPLS_GRP_ILM_NAME))==0){
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_grp_nhlfe = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for NHLFE mcast group!\n");
							return -1;
						}
					} else if (strncmp(name,MPLS_GRP_XC_NAME,strlen(MPLS_GRP_XC_NAME))==0) {
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_grp_xc = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for XC mcast group!\n");
							return -1;
						}
					} else if (strncmp(name,MPLS_GRP_LABELSPACE_NAME,strlen(MPLS_GRP_LABELSPACE_NAME))==0) {
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_grp_lspace = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for LABELSPACE mcast group!\n");
							return -1;
						}
					} else if (strncmp(name,MPLS_GRP_GET_NAME,strlen(MPLS_GRP_GET_NAME))==0) {
						if (tb[2]) {
							__u32 *id = RTA_DATA(tb[CTRL_ATTR_MCAST_GRP_ID]);
							mpls_grp_get = _group_mask(*id);
						} else {
							fprintf(stderr,"No ID for GET mcast group!\n");
							return -1;
						}
					}
				}
			}
		}
		if(!mpls_grp_ilm && !mpls_grp_nhlfe && !mpls_grp_xc && !mpls_grp_lspace && !mpls_grp_get){
			fprintf(stderr,"Not all IDs are caught!\n");
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
		if (rtnl_open(&rth_nhlfe, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth_nhlfe);
		rtnl_close(&rth_nhlfe);

		if (rtnl_open(&rth_ilm, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth_ilm);
		rtnl_close(&rth_ilm);

		if (rtnl_open(&rth_xc, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth_xc);
		rtnl_close(&rth_xc);

		if (rtnl_open(&rth_labelspace, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			exit(-1);
		}
		ll_init_map(&rth_labelspace);
		rtnl_close(&rth_labelspace);

		if (matches(argv[1], "monitor") == 0) {
			retval = do_mplsmonitor(argc-2,argv+2,mpls_grp_nhlfe,mpls_grp_ilm,mpls_grp_xc,mpls_grp_lspace);
		} else {
			if (rtnl_open_byproto(&rth_nhlfe,mpls_grp_nhlfe | mpls_grp_get, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening NHLFE rtnl\n");
				exit(-1);
			}
			if (rtnl_open_byproto(&rth_ilm,mpls_grp_ilm | mpls_grp_get, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening ILM rtnl\n");
				rtnl_close(&rth_nhlfe);
				exit(-1);
			}
			if (rtnl_open_byproto(&rth_xc, mpls_grp_xc | mpls_grp_get, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening XC rtnl\n");
				rtnl_close(&rth_nhlfe);
				rtnl_close(&rth_ilm);
				exit(-1);
			}
			if (rtnl_open_byproto(&rth_labelspace,mpls_grp_lspace | mpls_grp_get, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening LABELSPACE rtnl\n");
				rtnl_close(&rth_nhlfe);
				rtnl_close(&rth_ilm);
				rtnl_close(&rth_xc);
				exit(-1);
			}
			if (rtnl_open(&rth, 0) < 0){
				fprintf (stderr,"Error opening rtnl\n");
				rtnl_close(&rth_nhlfe);
				rtnl_close(&rth_ilm);
				rtnl_close(&rth_xc);
				rtnl_close(&rth_labelspace);
				exit(-1);
			}

			if (matches(argv[1], "nhlfe") == 0) {
				retval = do_nhlfe(argc-2,argv+2);
			} else if (matches(argv[1], "ilm") == 0) {
				retval = do_ilm(argc-2,argv+2);
			} else if (matches(argv[1], "xc") == 0) {
				retval = do_xc(argc-2,argv+2);
			} else if (matches(argv[1], "labelspace") == 0) {
				retval = do_labelspace(argc-2,argv+2);
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
			rtnl_close(&rth_nhlfe);
			rtnl_close(&rth_ilm);
			rtnl_close(&rth_xc);
			rtnl_close(&rth_labelspace);
			rtnl_close(&rth);
		}
	} else {
		usage();
		retval = 1;
	}
	return retval;
}
