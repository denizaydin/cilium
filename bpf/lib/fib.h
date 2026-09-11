/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "network_device.h"
#include "neigh.h"
#include "l3.h"
#include "l4.h"
#include "jhash.h"

static __always_inline bool
neigh_resolver_without_nh_available()
{
	/* Work around for
	 * https://lore.kernel.org/netdev/20251003073418.291171-1-daniel@iogearbox.net
	 */
	return !is_defined(IS_BPF_OVERLAY) && neigh_resolver_available();
}

static __always_inline int
add_l2_hdr(struct __ctx_buff *ctx)
{
	__be16 proto = ctx_get_protocol(ctx);

	if (ctx_change_head(ctx, __ETH_HLEN, 0))
		return DROP_INVALID;
	if (eth_store_proto(ctx, proto, 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static __always_inline int
maybe_add_l2_hdr(struct __ctx_buff *ctx, __u32 ifindex, bool *l2_hdr_required)
{
	if (device_is_l3(ifindex)) {
		/* The packet is going to be redirected to L3 dev, so
		 * skip L2 addr settings.
		 */
		*l2_hdr_required = false;
	} else if (THIS_IS_L3_DEV) {
		/* The packet is going to be redirected from L3 to L2
		 * device, so we need to create L2 header first.
		 */
		return add_l2_hdr(ctx);
	}
	return 0;
}

static __always_inline bool fib_ok(int ret)
{
	return likely(ret == CTX_ACT_TX || ret == CTX_ACT_REDIRECT);
}

 /* fib_do_redirect will redirect the ctx to a particular output interface.
  * @arg ctx			packet
  * @arg needs_l2_check		check for L3 -> L2 redirect
  * @arg fib_params		FIB lookup parameters
  * @arg allow_neigh_map	fallback to neighbour map for DMAC
  * @arg fib_result		result of a preceding FIB lookup
  * @arg oif			egress interface index
  * @arg ext_err		extended error
  *
  * Returns:
  *   - result of BPF redirect
  *   - DROP_NO_FIB when DMAC couldn't be resolved
  *   - other DROP reasons
  *
  * The redirect can occur with or without a preceding FIB lookup.
  *
  * If redirect_neigh() is available, it is always preferred. Passing
  * through the nh information from @fib_params if available.
  *
  * Otherwise:
  * If a previous FIB lookup was performed with result BPF_FIB_LKUP_RET_SUCCESS,
  * then the L2 addresses are updated from the provided @fib_params along with a
  * plain ctx_redirect().
  *
  * Without a successful FIB lookup, the `dmac` is resolved from the neighbour map.
  */
static __always_inline int
fib_do_redirect(struct __ctx_buff *ctx, const bool needs_l2_check,
		const struct bpf_fib_lookup_padded *fib_params,
		bool allow_neigh_map, int fib_result, __u32 oif, __s8 *ext_err)
{
	/* determine if we need to append layer 2 header */
	if (needs_l2_check) {
		bool l2_hdr_required = true;
		int ret;

		ret = maybe_add_l2_hdr(ctx, oif, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			goto out_send;
	}

	/* If we are able to resolve neighbors on demand, always
	 * prefer that over the BPF neighbor map since the latter
	 * might be less accurate in some asymmetric corner cases.
	 */
	if (neigh_resolver_available()) {
		if (fib_params) {
			struct bpf_redir_neigh nh_params;

			nh_params.nh_family = fib_params->l.family;
			__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &fib_params->l.ipv6_dst,
					     sizeof(nh_params.ipv6_nh));

			return (int)redirect_neigh(oif, &nh_params,
						   sizeof(nh_params), 0);
		}
	}

	if (neigh_resolver_without_nh_available())
		return (int)redirect_neigh(oif, NULL, 0, 0);

	if (fib_result == BPF_FIB_LKUP_RET_SUCCESS) {
		if (eth_store_daddr(ctx, fib_params->l.dmac, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr(ctx, fib_params->l.smac, 0) < 0)
			return DROP_WRITE_ERROR;
	} else {
		const union macaddr *smac = device_mac(oif);
		const union macaddr *dmac = NULL;

		if (allow_neigh_map) {
			/* The neigh_record_ip{4,6} locations are mainly from
			 * inbound client traffic on the load-balancer where we
			 * know that replies need to go back to them.
			 */
			dmac = fib_params->l.family == AF_INET ?
				neigh_lookup_ip4(&fib_params->l.ipv4_dst) :
				neigh_lookup_ip6((void *)&fib_params->l.ipv6_dst);
		}

		if (!dmac) {
			*ext_err = BPF_FIB_MAP_NO_NEIGH;
			return DROP_NO_FIB;
		}
		if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
		if (eth_store_saddr_aligned(ctx, smac->addr, 0) < 0)
			return DROP_WRITE_ERROR;
	}
out_send:
	return (int)ctx_redirect(ctx, oif, 0);
}

static __always_inline __u32
fib_lookup_skip_neigh() {
	if (neigh_resolver_available() &&
	    CONFIG(supports_fib_lookup_skip_neigh))
		return BPF_FIB_LOOKUP_SKIP_NEIGH;
	return 0;
}

static __always_inline int
fib_redirect(struct __ctx_buff *ctx, const bool needs_l2_check,
	     struct bpf_fib_lookup_padded *fib_params, bool use_neigh_map,
	     __s8 *ext_err, int *oif)
{
	int ret;

	ret = (int)fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l),
			      fib_lookup_skip_neigh());
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		break;
	default:
		*ext_err = (__s8)ret;
		return DROP_NO_FIB;
	}

	*oif = fib_params->l.ifindex;

	return fib_do_redirect(ctx, needs_l2_check, fib_params, use_neigh_map,
			       ret, *oif, ext_err);
}

#ifdef ENABLE_IPV6
/* fib_lookup_v6 will perform a fib lookup with the src and dest addresses
 * provided.
 *
 * after the function returns 'fib_params' will have the results of the fib lookup
 * if successful.
 */
static __always_inline int
fib_lookup_v6(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib_params,
	      const struct in6_addr *ipv6_src, const struct in6_addr *ipv6_dst,
	      int flags)
{
	fib_params->l.family	= AF_INET6;
	fib_params->l.ifindex	= ctx_get_ifindex(ctx);

	ipv6_addr_copy((union v6addr *)&fib_params->l.ipv6_src,
		       (union v6addr *)ipv6_src);
	ipv6_addr_copy((union v6addr *)&fib_params->l.ipv6_dst,
		       (union v6addr *)ipv6_dst);

	flags |= fib_lookup_skip_neigh();

	return (int)fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), flags);
};

/* fib_lookup_src_v6 will perform a source IP resolution for the given
 * destination address.
 * @ ctx - context buffer
 * @ src - output parameter to store the resolved source address
 * @ dst - destination address to resolve the source for
 *
 * If the result is any value other than BPF_FIB_LKUP_RET_SUCCESS the provided
 * src parameter will be unmodified.
 */
static __always_inline int
fib_lookup_src_v6(struct __ctx_buff *ctx, struct in6_addr *src,
		  const struct in6_addr *dst)
{
	struct bpf_fib_lookup_padded fib_params = {0};
	struct in6_addr zero = {0};
	int fib_result = 0;

	if (!CONFIG(supports_fib_lookup_src))
		return BPF_FIB_LKUP_RET_FWD_DISABLED;

	fib_result = fib_lookup_v6(ctx, &fib_params, &zero, dst,
				   BPF_FIB_LOOKUP_SRC);

	if (fib_result == BPF_FIB_LKUP_RET_SUCCESS) {
		ipv6_addr_copy((union v6addr *)src,
			       (union v6addr *)&fib_params.l.ipv6_src);
	}
	return fib_result;
}

#ifndef IPV6_FLOWLABEL_MASK
#define IPV6_FLOWLABEL_MASK	bpf_htonl(0x000fffff)
#endif

/* Fill the lookup's flow keys (flow label and L4 ports) so a multipath
 * FIB can select a per-flow nexthop. Lookup input only; the packet is
 * not modified. When the packet carries no flow label, derive one from
 * the ports so the default L3 hash policy can also spread flows.
 *
 * fib_params_set_flow_v6 takes the 5-tuple from the caller, for lookups
 * that describe a packet other than the one in the buffer - the
 * post-RevNAT one, say. flowinfo is the packet's first word.
 */
static __always_inline void
fib_params_set_flow_v6(struct bpf_fib_lookup_padded *fib_params, __be32 flowinfo,
		       __u8 proto, __be16 sport, __be16 dport)
{
	fib_params->l.l4_protocol = proto;
	fib_params->l.sport = sport;
	fib_params->l.dport = dport;

	flowinfo &= IPV6_FLOWLABEL_MASK;
	if (!flowinfo)
		flowinfo = bpf_htonl(jhash_2words(sport, dport, JHASH_INITVAL)) &
			   IPV6_FLOWLABEL_MASK;

	fib_params->l.flowinfo = flowinfo;
}

static __always_inline void
fib_params_set_l4_v6(struct bpf_fib_lookup_padded *fib_params,
		     struct __ctx_buff *ctx, const struct ipv6hdr *ip6,
		     int l3_off)
{
	__be16 ports[2];

	if (l4_proto_has_ports(ip6->nexthdr) &&
	    l4_load_ports(ctx, l3_off + sizeof(struct ipv6hdr), ports) == 0)
		fib_params_set_flow_v6(fib_params, *(const __be32 *)ip6,
				       ip6->nexthdr, ports[0], ports[1]);
	else
		fib_params->l.flowinfo = *(const __be32 *)ip6 & IPV6_FLOWLABEL_MASK;
}

static __always_inline int
fib_redirect_v6(struct __ctx_buff *ctx, int l3_off,
		struct ipv6hdr *ip6, const bool needs_l2_check,
		bool allow_neigh_map, __s8 *ext_err, int *oif, __u32 tbid)
{
	int ret;
	struct bpf_fib_lookup_padded fib_params = {0};
	int fib_result;
	int flags = 0;

	if (tbid) {
		fib_params.l.tbid = tbid;
		flags = (BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID);
	}

	fib_params_set_l4_v6(&fib_params, ctx, ip6, l3_off);

	fib_result = fib_lookup_v6(ctx, &fib_params, &ip6->saddr, &ip6->daddr, flags);
	switch (fib_result) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		break;
	default:
		*ext_err = (__s8)fib_result;
		return DROP_NO_FIB;
	}

	*oif = fib_params.l.ifindex;

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_do_redirect(ctx, needs_l2_check, &fib_params, allow_neigh_map,
			       fib_result, *oif, ext_err);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* fib_lookup_v4 will perform a fib lookup with the src and dest addresses
 * provided.
 *
 * after the function returns 'fib_params' will have the results of the fib lookup
 * if successful.
 */
static __always_inline int
fib_lookup_v4(struct __ctx_buff *ctx, struct bpf_fib_lookup_padded *fib_params,
	      __be32 ipv4_src, __be32 ipv4_dst, int flags) {
	fib_params->l.family	= AF_INET;
	fib_params->l.ifindex	= ctx_get_ifindex(ctx);
	fib_params->l.ipv4_src	= ipv4_src;
	fib_params->l.ipv4_dst	= ipv4_dst;

	flags |= fib_lookup_skip_neigh();

	return (int)fib_lookup(ctx, &fib_params->l, sizeof(fib_params->l), flags);
}

/* fib_lookup_src_v4 will perform a source IP resolution for the given
 * destination address.
 * @ ctx - context buffer
 * @ src - output parameter to store the resolved source address
 * @ dst - destination address to resolve the source for
 *
 * If the result is any value other than BPF_FIB_LKUP_RET_SUCCESS the provided
 * src parameter will be unmodified.
 */
static __always_inline int
fib_lookup_src_v4(struct __ctx_buff *ctx, __be32 *src, const __be32 dst)
{
	struct bpf_fib_lookup_padded fib_params = {0};
	int fib_result = 0;

	if (!CONFIG(supports_fib_lookup_src))
		return BPF_FIB_LKUP_RET_FWD_DISABLED;

	fib_result = fib_lookup_v4(ctx, &fib_params, 0, dst, BPF_FIB_LOOKUP_SRC);

	if (fib_result == BPF_FIB_LKUP_RET_SUCCESS)
		*src = fib_params.l.ipv4_src;

	return fib_result;
}

static __always_inline void
fib_params_set_l4_v4(struct bpf_fib_lookup_padded *fib_params,
		     struct __ctx_buff *ctx, const struct iphdr *ip4,
		     int l3_off)
{
	__be16 ports[2];

	/* No L4 header in non-first fragments. */
	if (ip4->frag_off & bpf_htons(0x1fff))
		return;

	if (l4_proto_has_ports(ip4->protocol) &&
	    l4_load_ports(ctx, l3_off + ipv4_hdrlen(ip4), ports) == 0) {
		fib_params->l.l4_protocol = ip4->protocol;
		fib_params->l.sport = ports[0];
		fib_params->l.dport = ports[1];
	}
}

static __always_inline int
fib_redirect_v4(struct __ctx_buff *ctx, int l3_off,
		struct iphdr *ip4, const bool needs_l2_check,
		bool allow_neigh_map, __s8 *ext_err, int *oif, __u32 tbid)
{
	int ret;
	struct bpf_fib_lookup_padded fib_params = {0};
	int fib_result;
	int flags = 0;

	if (tbid) {
		fib_params.l.tbid = tbid;
		flags = (BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID);
	}

	fib_params_set_l4_v4(&fib_params, ctx, ip4, l3_off);

	fib_result = fib_lookup_v4(ctx, &fib_params, ip4->saddr, ip4->daddr, flags);
	switch (fib_result) {
	case BPF_FIB_LKUP_RET_SUCCESS:
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		break;
	default:
		*ext_err = (__s8)fib_result;
		return DROP_NO_FIB;
	}

	*oif = fib_params.l.ifindex;

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return fib_do_redirect(ctx, needs_l2_check, &fib_params, allow_neigh_map,
			       fib_result, *oif, ext_err);
}
#endif /* ENABLE_IPV4 */

/* Variant for callers that pre-build fib_params: dissect the packet at
 * l3_off according to the params' address family.
 */
static __always_inline void
fib_params_set_l4(struct bpf_fib_lookup_padded *fib_params __maybe_unused,
		  struct __ctx_buff *ctx __maybe_unused, int l3_off __maybe_unused)
{
	void *data __maybe_unused, *data_end __maybe_unused;

#ifdef ENABLE_IPV4
	if (fib_params->l.family == AF_INET) {
		struct iphdr *ip4;

		if (revalidate_data(ctx, &data, &data_end, &ip4))
			fib_params_set_l4_v4(fib_params, ctx, ip4, l3_off);
		return;
	}
#endif
#ifdef ENABLE_IPV6
	if (fib_params->l.family == AF_INET6) {
		struct ipv6hdr *ip6;

		if (revalidate_data(ctx, &data, &data_end, &ip6))
			fib_params_set_l4_v6(fib_params, ctx, ip6, l3_off);
	}
#endif
}
