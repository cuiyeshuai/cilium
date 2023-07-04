/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"
#include "dbg.h"
#include "csum.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))


#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define MAX_TCP_OPT_LENGTH 15

#define MAX_TCP_HDR_LEN 60
#define MAX_TCP_LENGTH 1480

#define REDIR_OPT_TYPE 42
#define REDIR_OPT_TYPE_W_PORT 43
#define REDIR_OPT_TYPE_DOUBLE_ADDR 44
#define REDIR_OPT_TYPE_COMPLETE 45

union tcp_flags {
	struct {
		__u8 upper_bits;
		__u8 lower_bits;
		__u16 pad;
	};
	__u32 value;
};

struct __attribute__((packed)) redir_opt {
	__u8 type;
	__u8 size;
	__u32 ip;
};

struct __attribute__((packed)) redir_opt_w_port {
    __u8 type;
    __u8 size;
    __u32 ip;
    __u16 port;
};

struct __attribute__((packed)) redir_opt_double_addr {
    __u8 type;
    __u8 size;
    __u32 ip1;
    __u32 ip2;
	__u16 padding;
};

struct __attribute__((packed)) redir_opt_complete {
	__u8 type;
    __u8 size;
    __u32 ip1;
    __u32 ip2;
	__u16 port1;
	__u16 port2;
	__u8 index;
	__u8 padding;
	__u16 temp;
	__u16 padding1;
};

struct opt_parser{
	__u8 *cur_pos;
	__u8 cur_offset;
	__u8 cur_size;
	__u8 rest_len;
};

enum opt_type{
	REDIR_OPT,
	REDIR_OPT_W_PORT,
	REDIR_OPT_DOUBLE_ADDR,
	REDIR_OPT_COMPLETE,
	UNKNOWN_OPT
};

/**
 * Modify L4 port and correct checksum
 * @arg ctx:      packet
 * @arg l4_off:   offset to L4 header
 * @arg off:      offset from L4 header to source or destination port
 * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header
 * @arg port:     new port value
 * @arg old_port: old port value (for checksum correction)
 *
 * Overwrites a TCP or UDP port with new value and fixes up the checksum
 * in the L4 header and of ctx->csum.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
static __always_inline int l4_modify_port(struct __ctx_buff *ctx, int l4_off,
					  int off, struct csum_offset *csum_off,
					  __be16 port, __be16 old_port)
{
	if (csum_l4_replace(ctx, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

static __always_inline int l4_load_port(struct __ctx_buff *ctx, int off,
					__be16 *port)
{
	return ctx_load_bytes(ctx, off, port, sizeof(__be16));
}

static __always_inline int l4_load_ports(struct __ctx_buff *ctx, int off,
					 __be16 *ports)
{
	return ctx_load_bytes(ctx, off, ports, 2 * sizeof(__be16));
}

static __always_inline int l4_load_tcp_flags(struct __ctx_buff *ctx, int l4_off,
					     union tcp_flags *flags)
{
	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
}

static __always_inline int l4_parse_tcp_options(struct __ctx_buff *ctx, struct opt_parser *parser, int target_type)
{	
	int opt_type;
	void *data_end = (void *)(long)ctx->data_end;
	if (parser->rest_len <= 0) {
		cilium_dbg3(ctx, 0,10,10,10);
		return -1;
	}
	if ((void*)(parser->cur_pos) + 1 > data_end) {
		cilium_dbg3(ctx, 0,11,11,11);
		return -1;
	}
	opt_type = parser->cur_pos[0];
	if (opt_type == TCP_OPT_EOL) {
		cilium_dbg3(ctx, 0,12,12,12);
		return -1;
	}
	if (opt_type == TCP_OPT_NOP){
		parser->cur_pos++;
		parser->cur_offset++;
		parser->rest_len--;
		return 0;
	}
	
	if (opt_type == target_type){
		// if ((void*)parser->cur_pos + sizeof(struct redir_opt_double_addr) > data_end)
		// 	return -1;
		return 1;
	}
	// other options
	if ((void*)parser->cur_pos + 2 > data_end){
		cilium_dbg3(ctx, 0,13,13,13);
		return -1;
	}
	parser->cur_size = parser->cur_pos[1];
	parser->rest_len -= parser->cur_size;
	parser->cur_pos += parser->cur_size;
	parser->cur_offset += parser->cur_size;
	return 0;
}

static __always_inline void update_tcp_checksum(struct __ctx_buff *ctx, struct iphdr* iph, struct tcphdr* tcph){
	__u16 *buf;
	__u16 csum;
	
	int i = 0;
	__u32 csum_buffer = 0;
	void *data_end = (void *)(long)ctx->data_end;
	buf = (void*)tcph;
	tcph->check = 0;
	csum_buffer += (__u16)iph->saddr;
	csum_buffer += (__u16)(iph->saddr >> 16);
	csum_buffer += (__u16)iph->daddr;
	csum_buffer += (__u16)(iph->daddr >> 16);
	csum_buffer += (__u16)iph->protocol << 8;  
	csum_buffer += bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr));


	// Compute checksum on tcp header + payload
	for (i = 0; i < MAX_TCP_LENGTH; i += 2) 
	{
		if ((void *)(buf + 1) > data_end) 
		{
			break;
		}
		csum_buffer += *buf;
		buf++;
	}
	if ((void *)buf + 1 <= data_end) 
	{
		// In case payload is not 2 bytes aligned
		csum_buffer += *(__u8 *)buf;
	}
	csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
	csum = ~csum;
	tcph->check = csum;
}

static __always_inline int l4_add_tcp_option(struct __ctx_buff *ctx, __u16 ip_tot_len, struct iphdr *ip4, struct tcphdr* tcph, void* option, enum opt_type type){
	struct tcphdr tcph_old;
	__u64 flags = 0;
	__u16 adjust_len;
	void *data;
	void *data_end;
	struct iphdr *iph;
	__be32 diff;
	// __u16 csum;
	struct csum_offset csum_off = {};
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 1, 1, 1);
		return DROP_INVALID;
	}
	if ((void*)(tcph + 1) > data_end){
		cilium_dbg3(ctx, 0, 2, 2, 2);
		return DROP_INVALID;
	}

	memcpy(&tcph_old, tcph, sizeof(tcph_old));
	flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	switch(type){
		case REDIR_OPT:
			adjust_len = sizeof(struct redir_opt);
			break;
		case REDIR_OPT_W_PORT:
			adjust_len = sizeof(struct redir_opt_w_port);
			break;
		case REDIR_OPT_DOUBLE_ADDR:
			adjust_len = sizeof(struct redir_opt_double_addr);
			break;
		case REDIR_OPT_COMPLETE:
			adjust_len = sizeof(struct redir_opt_complete);
			break;
		default:
			cilium_dbg3(ctx, 0, 11, 11, 11);
			return -1;
	}

	if (ctx_adjust_hroom(ctx, adjust_len, BPF_ADJ_ROOM_NET, flags)) {
		cilium_dbg3(ctx, 0, 3, 3, 3);
		return DROP_INVALID;
	}

	// data_end = (void *)(long)ctx->data_end;
	// data = (void *)(long)ctx->data; 

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 4, 4, 4);
		return DROP_INVALID;
	}

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + adjust_len > data_end) {
		cilium_dbg3(ctx, 0, 5, 5, 5);
		return DROP_INVALID;
	}

	iph = data + sizeof(struct ethhdr);
	iph->tot_len = bpf_htons(bpf_ntohs(ip_tot_len) + adjust_len);

	iph->check = 0;
	// /* Fix IP checksum */
	iph->check = csum_fold(csum_diff(NULL, 0, iph,
						 sizeof(struct iphdr), 0));

	// iph->check = 0;
	// iph->check = csum_fold(csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));

	// use iph->ihl * 4?
	tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	//ctx_store_bytes
	memcpy(tcph, &tcph_old, sizeof(tcph_old));
	/* add redir opt to tcp header */
	memcpy((void *)(tcph+1), option, adjust_len);

	if((void*)(tcph) + adjust_len + tcph->doff*4 > data_end) {
		cilium_dbg3(ctx, 0, data_end-data, tcph->doff*4, adjust_len);
		return DROP_INVALID;
	}
	tcph->doff = tcph->doff + adjust_len / 4;
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	// csum = tcph->check;
	diff = csum_diff(&tcph_old, sizeof(tcph_old), tcph, sizeof(tcph)+adjust_len, 0);
	// csum = csum_fold(csum_add(diff, ~csum_unfold(csum)));
	// tcph->check = csum;
	// tcph->check = 0;
	cilium_dbg3(ctx, 0, diff, diff, diff);
	// csum_update(ctx, diff);

	//below is direct packet access and modification
	csum_l4_offset_and_flags(IPPROTO_TCP, &csum_off);
	if (csum_l4_replace(ctx, l4_off, &csum_off, 0, diff,
				    BPF_F_MARK_MANGLED_0) < 0) {
		cilium_dbg3(ctx, 0, 6, 6, 6);
		return DROP_CSUM_L4;
	}
	// update_tcp_checksum(ctx, iph, tcph);
	return 0;
}

static __always_inline int l4_add_tcp_option_min(struct __ctx_buff *ctx, __u16 ip_tot_len, struct iphdr *ip4, struct tcphdr* tcph, void* option, enum opt_type type){
	struct tcphdr tcph_old;
	__u64 flags = 0;
	__u16 adjust_len;
	void *data;
	void *data_end;
	struct iphdr *iph;
	// __u16 csum;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 1, 1, 1);
		return DROP_INVALID;
	}
	if ((void*)(tcph + 1) > data_end){
		cilium_dbg3(ctx, 0, 2, 2, 2);
		return DROP_INVALID;
	}

	memcpy(&tcph_old, tcph, sizeof(tcph_old));
	flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	switch(type){
		case REDIR_OPT:
			adjust_len = sizeof(struct redir_opt);
			break;
		case REDIR_OPT_W_PORT:
			adjust_len = sizeof(struct redir_opt_w_port);
			break;
		case REDIR_OPT_DOUBLE_ADDR:
			adjust_len = sizeof(struct redir_opt_double_addr);
			break;
		case REDIR_OPT_COMPLETE:
			adjust_len = sizeof(struct redir_opt_complete);
			break;
		default:
			cilium_dbg3(ctx, 0, 11, 11, 11);
			return -1;
	}

	if (ctx_adjust_hroom(ctx, adjust_len, BPF_ADJ_ROOM_NET, flags)) {
		cilium_dbg3(ctx, 0, 3, 3, 3);
		return DROP_INVALID;
	}

	// data_end = (void *)(long)ctx->data_end;
	// data = (void *)(long)ctx->data; 

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 4, 4, 4);
		return DROP_INVALID;
	}

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + adjust_len > data_end) {
		cilium_dbg3(ctx, 0, 5, 5, 5);
		return DROP_INVALID;
	}

	iph = data + sizeof(struct ethhdr);
	iph->tot_len = bpf_htons(bpf_ntohs(ip_tot_len) + adjust_len);

	iph->check = 0;
	// /* Fix IP checksum */
	iph->check = csum_fold(csum_diff(NULL, 0, iph,
						 sizeof(struct iphdr), 0));
	cilium_dbg3(ctx, 0, sizeof(option), sizeof(option), sizeof(option));
	// iph->check = 0;
	// iph->check = csum_fold(csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));
	return 0;
}

static __always_inline int crab_add_tcp_option(struct __ctx_buff *ctx, __u16 ip_tot_len, struct iphdr *ip4, struct tcphdr* tcph, void* option, enum opt_type type){
	struct tcphdr tcph_old;
	struct tcphdr tcph_buff;
	__u64 flags = 0;
	__u16 adjust_len;
	void *data;
	void *data_end;
	//struct iphdr *iph;
	__be32 diff;
	// __u16 csum;
	struct csum_offset csum_off = {};
	int l3_off = ETH_HLEN;
	int l4_off;
	__u16 old_ip_tot_len = ip_tot_len;
	__u16 new_ip_tot_len;
	int ret = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		return DROP_INVALID;
	}
	if ((void*)(tcph + 1) > data_end){
		return DROP_INVALID;
	}
	// store current tcph into tcph_old
	memcpy(&tcph_old, tcph, sizeof(tcph_old));
	flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	switch(type){
		case REDIR_OPT:
			adjust_len = sizeof(struct redir_opt);
			break;
		case REDIR_OPT_W_PORT:
			adjust_len = sizeof(struct redir_opt_w_port);
			break;
		case REDIR_OPT_DOUBLE_ADDR:
			adjust_len = sizeof(struct redir_opt_double_addr);
			break;
		case REDIR_OPT_COMPLETE:
			adjust_len = sizeof(struct redir_opt_complete);
			break;
		default:
			cilium_dbg3(ctx, 0, 11, 11, 11);
			return -1;
	}
	// add room between end of ip hdr and start of tcp hdr
	if (ctx_adjust_hroom(ctx, adjust_len, BPF_ADJ_ROOM_NET, flags)) {
		return DROP_INVALID;
	}

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		return DROP_INVALID;
	}
	if (data + l3_off + sizeof(struct iphdr) + sizeof(struct tcphdr) + adjust_len > data_end) {
		return DROP_INVALID;
	}

	// update ip total len
	new_ip_tot_len = bpf_htons(bpf_ntohs(old_ip_tot_len) + adjust_len);
	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, tot_len),
			      &new_ip_tot_len, 2, BPF_F_RECOMPUTE_CSUM);
	if (ret < 0)
		return DROP_WRITE_ERROR;
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 4, 4, 4);
		return DROP_INVALID;
	}

	// update ip checksum
	ip4->check = 0;
	diff = csum_diff(NULL, 0, ip4, sizeof(struct iphdr), 0);
	if (ipv4_csum_update_by_diff(ctx, l3_off, diff) < 0)
		return DROP_CSUM_L3;
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		return DROP_INVALID;
	}

	// update tcph pointer
	tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if ((void*)tcph + sizeof(struct tcphdr) + adjust_len > data_end) {
		cilium_dbg3(ctx, 0, 5, 5, 5);
		return DROP_INVALID;
	}
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	// copy tcph_old into new tcph
	// memcpy(tcph, &tcph_old, sizeof(tcph_old));
	ctx_store_bytes(ctx, l4_off, &tcph_old, sizeof(tcph_old), BPF_F_RECOMPUTE_CSUM);
	// fill option field with zero first
	{
		int array[20] = {0};
		ctx_store_bytes(ctx, l4_off+sizeof(tcph_old), &array, adjust_len, BPF_F_RECOMPUTE_CSUM);
	}
	// memset((void *)(tcph+1), 0, adjust_len);

	// update d_off field
	memcpy((void*)&tcph_buff, &tcph_old, sizeof(tcph_old));
	tcph_buff.doff = tcph_old.doff + adjust_len / 4;
	ctx_store_bytes(ctx, l4_off, &tcph_buff, sizeof(tcph_buff), BPF_F_RECOMPUTE_CSUM);
	csum_l4_offset_and_flags(IPPROTO_TCP, &csum_off);
	diff = csum_diff(&tcph_old, sizeof(tcph_old), &tcph_buff, sizeof(tcph_buff), 0);
	if (csum_l4_replace(ctx, l4_off, &csum_off, 0, diff,
				    BPF_F_MARK_MANGLED_0) < 0) {
		return DROP_CSUM_L4;
	}
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		return DROP_INVALID;
	}
	tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if ((void*)tcph + sizeof(struct tcphdr) > data_end) {
		cilium_dbg3(ctx, 0, 5, 5, 5);
		return DROP_INVALID;
	}
	// {
	// 	tcph->check = csum_fold(csum_add(diff, ~csum_unfold(tcph->check)));
	// }

	// write option field
	ctx_store_bytes(ctx, l4_off + sizeof(struct tcphdr), option, adjust_len, BPF_F_RECOMPUTE_CSUM);
	diff = csum_diff(NULL, 0, &option, adjust_len, 0);
	if (csum_l4_replace(ctx, l4_off, &csum_off, 0, diff,
				    BPF_F_MARK_MANGLED_0) < 0) {
		cilium_dbg3(ctx, 0, 7, 7, 7);
		return DROP_CSUM_L4;
	}
	return ret;
}


static __always_inline int crab_add_tcp_option_min(struct __ctx_buff *ctx, __u16 ip_tot_len, struct iphdr *ip4, struct tcphdr* tcph, void* option, enum opt_type type){
	struct tcphdr tcph_old;
	__u64 flags = 0;
	__u16 adjust_len;
	void *data;
	void *data_end;
	//struct iphdr *iph;
	__be32 diff;
	// __u16 csum;
	int l3_off = ETH_HLEN;
	__u16 old_ip_tot_len = ip_tot_len;
	__u16 new_ip_tot_len;
	int ret = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 1, 1, 1);
		return DROP_INVALID;
	}
	if ((void*)(tcph + 1) > data_end){
		cilium_dbg3(ctx, 0, 2, 2, 2);
		return DROP_INVALID;
	}

	memcpy(&tcph_old, tcph, sizeof(tcph_old));
	flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	switch(type){
		case REDIR_OPT:
			adjust_len = sizeof(struct redir_opt);
			break;
		case REDIR_OPT_W_PORT:
			adjust_len = sizeof(struct redir_opt_w_port);
			break;
		case REDIR_OPT_DOUBLE_ADDR:
			adjust_len = sizeof(struct redir_opt_double_addr);
			break;
		case REDIR_OPT_COMPLETE:
			adjust_len = sizeof(struct redir_opt_complete);
			break;
		default:
			cilium_dbg3(ctx, 0, 11, 11, 11);
			return -1;
	}

	if (ctx_adjust_hroom(ctx, adjust_len, BPF_ADJ_ROOM_NET, flags)) {
		cilium_dbg3(ctx, 0, 3, 3, 3);
		return DROP_INVALID;
	}

	// data_end = (void *)(long)ctx->data_end;
	// data = (void *)(long)ctx->data; 

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 4, 4, 4);
		return DROP_INVALID;
	}

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + adjust_len > data_end) {
		cilium_dbg3(ctx, 0, 5, 5, 5);
		return DROP_INVALID;
	}
	// IP total length modify
	new_ip_tot_len = bpf_htons(bpf_ntohs(old_ip_tot_len) + adjust_len);

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, tot_len),
			      &new_ip_tot_len, 2, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	diff = csum_diff(NULL, 0, &ip4, sizeof(struct iphdr), 0);
	if (ipv4_csum_update_by_diff(ctx, l3_off, diff) < 0)
		return DROP_CSUM_L3;
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
		cilium_dbg3(ctx, 0, 4, 4, 4);
		return DROP_INVALID;
	}
	ip4->check = csum_fold(csum_diff(NULL, 0, ip4,
						 sizeof(struct iphdr), 0));
	cilium_dbg3(ctx, 0, sizeof(option), sizeof(option), sizeof(option));
	return ret;
}

#endif
