/*
 * Copyright (c) 2017, USC/ISI, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdlib.h>

#include "dnscap_common.h"

static logerr_t *logerr;
static int opt_f = 0;
static char *outfile = 0;
static FILE *out = 0;
static char *seperator = 0;

output_t regexcount_output;

typedef struct regex_list_item_s {
   char *regex;
   char *name;
} regex_list_item;

regex_list_item *regex_list;
size_t          regex_list_len = 0;
unsigned        regex_list_count = 0;

void
regexcount_usage()
{
	fprintf(stderr,
	        "\nregexcount.so options:\n"
	        "\t-o <arg>        output file name\n"
	        "\t-r name=regex   count 'regexp' patterns and put them in the ouptut stream under 'name'\n"
	        "\t-s <sep>        Use <sep> as the record separator instead of tab\n"
		);
}

void
regexcount_getopt(int *argc, char **argv[])
{
	/*
	 * The "getopt" function will be called from the parent to
	 * process plugin options.
	 */

	regex_list_len = 8;
	regex_list = calloc(regex_list_len, sizeof(regex_list_item));

	int c;
	while ((c = getopt(*argc, *argv, "o:r:s:")) != EOF) {
		switch(c) {
		case 'o':
			if (outfile)
				free(outfile);
			outfile = strdup(optarg);
			break;
		case 'r':
		{
			regex_list_item *newitem = calloc(1, sizeof(regex_list_item));
			char *equal = strchr(optarg, '=');
			newitem->regex = strdup(equal + 1);
			newitem->name = strndup(optarg, equal - optarg);
			fprintf(stderr, "here: %s + %s\n", newitem->regex, newitem->name);
			
		}
		        break;
		case 's':
			free(seperator);
			seperator = strdup(optarg);
			break;
		default:
			regexcount_usage();
			exit(1);
		}
	}
}

int
regexcount_start(logerr_t *a_logerr)
{
	if (!seperator) {
		seperator = strdup("\t");
	}

	/* called once so we open our output file */
	logerr = a_logerr;
	if (outfile) {
		out = fopen(outfile, "w");
		if (0 == out) {
			logerr("%s: %s\n", outfile, strerror(errno));
			exit(1);
		}
	} else {
		out = stdout;
	}

	fprintf(out,"#");
	for(int i = 0; i < regex_list_count; i++) {
		fprintf(out, "%s%s", regex_list[i].name, seperator);
	}
	fprintf(out,"\n");
	printf("-------------xyz--------\n");

	return 0;
}

void
regexcount_stop()
{
	/*
	 * The "start" function is called once, when the program
	 * is exiting normally.  It might be used to clean up state,
	 * free memory, etc.
	 */
	fclose(out);
}

int
regexcount_open(my_bpftimeval ts)
{
	/*
	 * The "open" function is called at the start of each
	 * collection interval, which might be based on a period
	 * of time or a number of packets.  In the original code,
	 * this is where we opened an output pcap file.
	 */
	return 0;
}

int
regexcount_close(my_bpftimeval ts)
{
	/*
	 * The "close" function is called at the end of each
	 * collection interval, which might be based on a period
	 * of time or on a number of packets.  In the original code
	 * this is where we closed an output pcap file.
	 */
	return 0;
}

void
regexcount_output(const char *descr, iaddr from, iaddr to, uint8_t proto, unsigned flags,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *payload, unsigned payloadlen)
{
	/*
	 * IP Stuff
	 */

	if (flags & DNSCAP_OUTPUT_ISDNS) {
		ns_msg msg;
		int qdcount;
		ns_rr rr;
		ns_initparse(payload, payloadlen, &msg);
		/*
		 * DNS Header
		 */
		fprintf(out, " %u", ns_msg_id(msg));
		fprintf(out, " %u", ns_msg_getflag(msg, ns_f_opcode));
		fprintf(out, " %u", ns_msg_getflag(msg, ns_f_rcode));
		fprintf(out, " |");
		if (ns_msg_getflag(msg, ns_f_qr)) fprintf(out, "QR|");
		if (ns_msg_getflag(msg, ns_f_aa)) fprintf(out, "AA|");
		if (ns_msg_getflag(msg, ns_f_tc)) fprintf(out, "TC|");
		if (ns_msg_getflag(msg, ns_f_rd)) fprintf(out, "RD|");
		if (ns_msg_getflag(msg, ns_f_ra)) fprintf(out, "RA|");
		if (ns_msg_getflag(msg, ns_f_ad)) fprintf(out, "AD|");
		if (ns_msg_getflag(msg, ns_f_cd)) fprintf(out, "CD|");

		qdcount = ns_msg_count(msg, ns_s_qd);
		if (qdcount > 0 && 0 == ns_parserr(&msg, ns_s_qd, 0, &rr)) {
			fprintf (out, " %s %s %s",
				p_class(ns_rr_class(rr)),
				p_type(ns_rr_type(rr)),
				ns_rr_name(rr));
		}
	}
	/*
	 * Done
	 */
	fprintf(out, "\n");
}
