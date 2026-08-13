// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#define ENABLE_IPV4		      1
#define ENABLE_IPV6		      1
#define SKIP_ICMPV6_HOPLIMIT_HANDLING 1
#include "common.h"
#include "pktgen.h"

#define REDIR_NEIGH_ENTERED 1002

struct redir_neigh_recorder {
	__u32 ifindex;
	struct bpf_redir_neigh *params;
	int plen;
	__u32 flags;
} redir_neigh_recorder = {0};

void reset_redir_neigh_recorder(struct redir_neigh_recorder *r)
{
	r->ifindex = 0;
	r->params = 0;
	r->plen = 0;
	r->flags = 0XFFFFFFFF;
}

#define redirect_neigh mock_redirect_neigh

long mock_redirect_neigh(__maybe_unused int ifindex,
			 __maybe_unused struct bpf_redir_neigh *params,
			 __maybe_unused int plen,
			 __maybe_unused __u32 flags)
{
	redir_neigh_recorder.ifindex = ifindex;
	redir_neigh_recorder.params = params;
	redir_neigh_recorder.plen = plen;
	redir_neigh_recorder.flags = flags;
	return REDIR_NEIGH_ENTERED;
}

struct fib_lookup_recorder {
	__u32 flags;
	__be32 flowinfo;
	__be16 sport;
	__be16 dport;
	__u8 l4_protocol;
} fib_lookup_recorder = {0};

void reset_fib_lookup_recorder(struct fib_lookup_recorder *r)
{
	r->flags = 0;
	r->flowinfo = 0;
	r->sport = 0;
	r->dport = 0;
	r->l4_protocol = 0;
}

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(void *ctx __maybe_unused,
		     struct bpf_fib_lookup *params __maybe_unused,
		     int plen __maybe_unused, __u32 flags __maybe_unused)
{
	fib_lookup_recorder.flags = flags;
	fib_lookup_recorder.flowinfo = params->flowinfo;
	fib_lookup_recorder.sport = params->sport;
	fib_lookup_recorder.dport = params->dport;
	fib_lookup_recorder.l4_protocol = params->l4_protocol;
	return 0;
}

#include "lib/dbg.h"
#include <bpf/config/global.h>
#include <bpf/config/node.h>
#include "lib/fib.h"

ASSIGN_CONFIG(bool, supports_fib_lookup_skip_neigh, true)

CHECK(PROG_TYPE, "fib_do_redirect_happy_path")
int test1_check(struct __ctx_buff *ctx)
{
	test_init();

	/* Simulate a successful fib lookup with an output interface.
	 * We expect to enter ctx_redirect with the provided ifindex.
	 */
	TEST("lookup_success", {
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_SUCCESS,
				      ifindex_good, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter ctx_redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected %x, got %d", ifindex_good,
				   redir_neigh_recorder.ifindex);

		if (!redir_neigh_recorder.params)
			test_fatal("redirect_neigh called with nil params");

		if (redir_neigh_recorder.plen != sizeof(struct bpf_redir_neigh))
			test_fatal("expected plen %d, got %d",
				   sizeof(struct bpf_redir_neigh),
				   redir_neigh_recorder.plen);

		if (redir_neigh_recorder.flags != 0)
			test_fatal("expected flags 0, got %d",
				   redir_neigh_recorder.flags);

		reset_redir_neigh_recorder(&redir_neigh_recorder);
	});

	/* Simulate fib lookup with no neighbor return.
	 * We expect to enter redirect_neigh with provided ifindex
	 * and a non-nil bpf_redir_neigh.
	 */
	TEST("lookup_no_neigh", {
		__u32 ifindex_good = 0xAAAAAAAA;
		int ret = -1;
		struct bpf_fib_lookup_padded params = {0};
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		ret = fib_do_redirect(ctx, false, &params, true,
				      BPF_FIB_LKUP_RET_NO_NEIGH,
				      ifindex_good, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected ifindex %x, got %d", ifindex_good,
				   redir_neigh_recorder.ifindex);

		if (!redir_neigh_recorder.params)
			test_fatal("redirect_neigh called with nil params");

		if (redir_neigh_recorder.plen != sizeof(struct bpf_redir_neigh))
			test_fatal("expected plen %d, got %d",
				   sizeof(struct bpf_redir_neigh),
				   redir_neigh_recorder.plen);

		if (redir_neigh_recorder.flags != 0)
			test_fatal("expected flags 0, got %d",
				   redir_neigh_recorder.flags);

		reset_redir_neigh_recorder(&redir_neigh_recorder);
	});

	/* Simulate no fib lookup.
	 * We expect to enter redirect_neigh with the oif provided in the
	 * argument to fib_do_redirect and a nil bpf_redir_neigh structure.
	 */
	TEST("lookup_no_neigh_no_fib", {
		__u32 ifindex_good = 0xBEEFDEAD;
		int ret = -1;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		ret = fib_do_redirect(ctx, false, NULL, true,
				      BPF_FIB_LKUP_RET_NO_NEIGH,
				      ifindex_good, &ext_err);
		if (ret != REDIR_NEIGH_ENTERED)
			test_fatal("did not enter redirect_neigh");

		if (redir_neigh_recorder.ifindex != ifindex_good)
			test_fatal("expected ifindex %x, got %d", ifindex_good,
				   redir_neigh_recorder.ifindex);

		if (redir_neigh_recorder.params)
			test_fatal("expected nil bpf_redir_neigh");

		if (redir_neigh_recorder.plen != 0)
			test_fatal("expected plen to be 0");

		if (redir_neigh_recorder.flags != 0)
			test_fatal("expected flags 0, got %d",
				   redir_neigh_recorder.flags);

		reset_redir_neigh_recorder(&redir_neigh_recorder);
	});
	test_finish();
}

CHECK(PROG_TYPE, "fib_redirect*_fib_lookup_flags")
int test2_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("fib_redirect", {
		struct bpf_fib_lookup_padded params = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect(ctx, false, &params, true, &ext_err, &oif);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	TEST("fib_redirect_v4", {
		struct iphdr hdr = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect_v4(ctx, 0, &hdr, true, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	TEST("fib_redirect_v6", {
		struct ipv6hdr hdr6 = { 0 };
		int oif = 0;
		__s8 ext_err;

		if (!neigh_resolver_available())
			test_fatal("expected neigh_resolver_available true");

		fib_redirect_v6(ctx, 0, &hdr6, true, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.flags != BPF_FIB_LOOKUP_SKIP_NEIGH)
			test_fatal("expected flags %x, got %d",
				   BPF_FIB_LOOKUP_SKIP_NEIGH,
				   fib_lookup_recorder.flags);

		reset_fib_lookup_recorder(&fib_lookup_recorder);
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_v6_tcp")
int fib_flow_keys_v6_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder,
				      (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)v6_pod_one, (__u8 *)v6_pod_two);
	if (!l3)
		return TEST_ERROR;

	l3->flow_lbl[0] = 0x01;
	l3->flow_lbl[1] = 0x23;
	l3->flow_lbl[2] = 0x45;

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_v6_tcp")
int fib_flow_keys_v6_tcp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int oif = 0;
	__s8 ext_err;

	test_init();

	TEST("label_and_ports", {
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			test_fatal("packet too short");

		reset_fib_lookup_recorder(&fib_lookup_recorder);
		fib_redirect_v6(ctx, ETH_HLEN, ip6, false, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.l4_protocol != IPPROTO_TCP)
			test_fatal("l4_protocol not TCP");
		if (fib_lookup_recorder.sport != tcp_src_one)
			test_fatal("sport not set");
		if (fib_lookup_recorder.dport != tcp_svc_one)
			test_fatal("dport not set");
		if (fib_lookup_recorder.flowinfo != bpf_htonl(0x12345))
			test_fatal("packet flow label not used");
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_v6_udp")
int fib_flow_keys_v6_udp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_v6_udp")
int fib_flow_keys_v6_udp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int oif = 0;
	__s8 ext_err;

	test_init();

	TEST("synthesized_label", {
		__be32 expect = bpf_htonl(jhash_2words(tcp_src_one, tcp_svc_one,
						       JHASH_INITVAL)) &
				IPV6_FLOWLABEL_MASK;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			test_fatal("packet too short");

		reset_fib_lookup_recorder(&fib_lookup_recorder);
		fib_redirect_v6(ctx, ETH_HLEN, ip6, false, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.l4_protocol != IPPROTO_UDP)
			test_fatal("l4_protocol not UDP");
		if (fib_lookup_recorder.sport != tcp_src_one)
			test_fatal("sport not set");
		if (fib_lookup_recorder.dport != tcp_svc_one)
			test_fatal("dport not set");
		if (!fib_lookup_recorder.flowinfo)
			test_fatal("no label synthesized for label-less flow");
		if (fib_lookup_recorder.flowinfo & ~IPV6_FLOWLABEL_MASK)
			test_fatal("synthesized label exceeds the label bits");
		if (fib_lookup_recorder.flowinfo != expect)
			test_fatal("synthesized label not derived from ports");
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_v6_icmp")
int fib_flow_keys_v6_icmp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder,
				      (__u8 *)mac_one, (__u8 *)mac_two,
				      (__u8 *)v6_pod_one, (__u8 *)v6_pod_two);
	if (!l3)
		return TEST_ERROR;

	if (!pktgen__push_icmp6hdr(&builder))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_v6_icmp")
int fib_flow_keys_v6_icmp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int oif = 0;
	__s8 ext_err;

	test_init();

	TEST("no_ports_no_synth", {
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			test_fatal("packet too short");

		reset_fib_lookup_recorder(&fib_lookup_recorder);
		fib_redirect_v6(ctx, ETH_HLEN, ip6, false, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.l4_protocol)
			test_fatal("l4_protocol set for ICMPv6");
		if (fib_lookup_recorder.sport || fib_lookup_recorder.dport)
			test_fatal("ports set for ICMPv6");
		if (fib_lookup_recorder.flowinfo)
			test_fatal("label synthesized without ports");
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_v4_tcp")
int fib_flow_keys_v4_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_v4_tcp")
int fib_flow_keys_v4_tcp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int oif = 0;
	__s8 ext_err;

	test_init();

	TEST("ports_only", {
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			test_fatal("packet too short");

		reset_fib_lookup_recorder(&fib_lookup_recorder);
		fib_redirect_v4(ctx, ETH_HLEN, ip4, false, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.l4_protocol != IPPROTO_TCP)
			test_fatal("l4_protocol not TCP");
		if (fib_lookup_recorder.sport != tcp_src_one)
			test_fatal("sport not set");
		if (fib_lookup_recorder.dport != tcp_svc_one)
			test_fatal("dport not set");
		if (fib_lookup_recorder.flowinfo)
			test_fatal("flowinfo set for IPv4");
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_v4_frag")
int fib_flow_keys_v4_frag_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct iphdr *l3;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv4_packet(&builder,
				      (__u8 *)mac_one, (__u8 *)mac_two,
				      v4_pod_one, v4_pod_two);
	if (!l3)
		return TEST_ERROR;

	/* Non-first fragment: the bytes after the IP header are payload,
	 * not an L4 header.
	 */
	l3->frag_off = bpf_htons(0x0002);

	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = tcp_src_one;
	l4->dest = tcp_svc_one;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_v4_frag")
int fib_flow_keys_v4_frag_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int oif = 0;
	__s8 ext_err;

	test_init();

	TEST("later_fragment_skipped", {
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			test_fatal("packet too short");

		reset_fib_lookup_recorder(&fib_lookup_recorder);
		fib_redirect_v4(ctx, ETH_HLEN, ip4, false, true, &ext_err, &oif, 0);

		if (fib_lookup_recorder.l4_protocol)
			test_fatal("l4_protocol set for a later fragment");
		if (fib_lookup_recorder.sport || fib_lookup_recorder.dport)
			test_fatal("payload bytes read as ports");
	});

	test_finish();
}

PKTGEN(PROG_TYPE, "fib_flow_keys_dispatch")
int fib_flow_keys_dispatch_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  v4_pod_one, v4_pod_two,
					  tcp_src_one, tcp_svc_one);
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK(PROG_TYPE, "fib_flow_keys_dispatch")
int fib_flow_keys_dispatch_check(struct __ctx_buff *ctx)
{
	test_init();

	TEST("family_dispatch", {
		struct bpf_fib_lookup_padded params = {0};

		params.l.family = AF_INET;
		fib_params_set_l4(&params, ctx, ETH_HLEN);

		if (params.l.l4_protocol != IPPROTO_UDP)
			test_fatal("l4_protocol not UDP");
		if (params.l.sport != tcp_src_one)
			test_fatal("sport not set");
		if (params.l.dport != tcp_svc_one)
			test_fatal("dport not set");
	});

	test_finish();
}
