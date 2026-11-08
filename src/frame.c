/*
 * lltd - frame parsing, building and decoding for logs
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdio.h>

#include "lltd_proto.h"

const mac_t MAC_BROADCAST = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

int lltd_parse(const uint8_t *buf, size_t len, struct lltd_frame *f)
{
	if (len < LLTD_HDR_LEN)
		return -1;
	if (get_be16(buf + 12) != LLTD_ETHERTYPE)
		return -1;
	if (buf[14] != LLTD_VERSION)
		return -1;

	memset(f, 0, sizeof(*f));
	f->raw = buf;
	f->len = len;
	memcpy(f->eth_dst.a, buf, ETH_ADDR_LEN);
	memcpy(f->eth_src.a, buf + 6, ETH_ADDR_LEN);
	f->tos = buf[15];
	f->function = buf[17];
	memcpy(f->real_dst.a, buf + 18, ETH_ADDR_LEN);
	memcpy(f->real_src.a, buf + 24, ETH_ADDR_LEN);
	f->seq = get_be16(buf + 30);
	f->body = buf + LLTD_HDR_LEN;
	f->body_len = len - LLTD_HDR_LEN;
	return 0;
}

void lltd_put_header(uint8_t *buf, const mac_t *eth_dst, const mac_t *eth_src,
		     uint8_t tos, uint8_t function,
		     const mac_t *real_dst, const mac_t *real_src, uint16_t seq)
{
	memcpy(buf, eth_dst->a, ETH_ADDR_LEN);
	memcpy(buf + 6, eth_src->a, ETH_ADDR_LEN);
	put_be16(buf + 12, LLTD_ETHERTYPE);
	buf[14] = LLTD_VERSION;
	buf[15] = tos;
	buf[16] = 0;
	buf[17] = function;
	memcpy(buf + 18, real_dst->a, ETH_ADDR_LEN);
	memcpy(buf + 24, real_src->a, ETH_ADDR_LEN);
	put_be16(buf + 30, seq);
}

const char *lltd_function_name(uint8_t tos, uint8_t function)
{
	static const char *const topo[] = {
		"Discover", "Hello", "Emit", "Train", "Probe", "Ack", "Query",
		"QueryResp", "Reset", "Charge", "Flat", "QueryLargeTlv",
		"QueryLargeTlvResp",
	};
	static const char *const qos[] = {
		"QosInitializeSink", "QosReady", "QosProbe", "QosQuery",
		"QosQueryResp", "QosReset", "QosError", "QosAck",
		"QosCounterSnapshot", "QosCounterResult", "QosCounterLease",
	};

	if (tos == TOS_QOS)
		return function < sizeof(qos) / sizeof(qos[0]) ? qos[function] : "Qos?";
	if (function < sizeof(topo) / sizeof(topo[0]))
		return topo[function];
	return "?";
}

void mac_format(const mac_t *m, char out[18])
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 m->a[0], m->a[1], m->a[2], m->a[3], m->a[4], m->a[5]);
}

int mac_parse(const char *s, mac_t *m)
{
	unsigned int b[6];
	char tail;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6 &&
	    sscanf(s, "%x-%x-%x-%x-%x-%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (b[i] > 0xff)
			return -1;
		m->a[i] = (uint8_t)b[i];
	}
	return 0;
}

#define APPEND(...) do { \
		if (pos < outlen) { \
			int n_ = snprintf(out + pos, outlen - pos, __VA_ARGS__); \
			if (n_ > 0) pos += (size_t)n_; \
		} \
	} while (0)

size_t lltd_describe(const struct lltd_frame *f, char *out, size_t outlen)
{
	char ed[18], es[18], rd[18], rs[18], m1[18], m2[18], m3[18];
	size_t pos = 0;
	const uint8_t *b = f->body;
	size_t bl = f->body_len;

	if (outlen)
		out[0] = '\0';
	mac_format(&f->eth_dst, ed);
	mac_format(&f->eth_src, es);
	mac_format(&f->real_dst, rd);
	mac_format(&f->real_src, rs);
	APPEND("%s tos=%u seq=%u eth %s>%s real %s>%s len=%zu",
	       lltd_function_name(f->tos, f->function), f->tos, f->seq, es, ed, rs, rd, f->len);

	if (f->tos > TOS_QUICK)
		return pos;

	switch (f->function) {
	case FN_DISCOVER:
		if (bl >= 4) {
			unsigned int n = get_be16(b + 2);
			APPEND(" gen=%u stations=%u:", get_be16(b), n);
			for (unsigned int i = 0; i < n && 4 + 6 * (i + 1) <= bl; i++) {
				mac_format((const mac_t *)(b + 4 + 6 * i), m1);
				APPEND(" %s", m1);
			}
		}
		break;
	case FN_HELLO:
		if (bl >= 14) {
			mac_format((const mac_t *)(b + 2), m1);
			mac_format((const mac_t *)(b + 8), m2);
			APPEND(" gen=%u mapper=%s apparent=%s tlvs:", get_be16(b), m1, m2);
			for (size_t i = 14; i + 2 <= bl && b[i] != TLV_END; i += 2 + b[i + 1])
				APPEND(" %02x/%u", b[i], b[i + 1]);
		}
		break;
	case FN_EMIT:
		if (bl >= 2) {
			unsigned int n = get_be16(b);
			APPEND(" descs=%u:", n);
			for (unsigned int i = 0; i < n && 2 + EMITEE_DESC_LEN * (i + 1) <= bl; i++) {
				const uint8_t *d = b + 2 + EMITEE_DESC_LEN * i;
				mac_format((const mac_t *)(d + 2), m1);
				mac_format((const mac_t *)(d + 8), m2);
				APPEND(" [%s %ums %s>%s]", d[0] == EMITEE_TRAIN ? "train" : "probe", d[1], m1, m2);
			}
		}
		break;
	case FN_QUERY_RESP:
		if (bl >= 2) {
			unsigned int h = get_be16(b), n = h & 0x3fff;
			APPEND(" more=%u error=%u descs=%u:", !!(h & QUERY_RESP_MORE), !!(h & QUERY_RESP_ERROR), n);
			for (unsigned int i = 0; i < n && 2 + RECVEE_DESC_LEN * (i + 1) <= bl; i++) {
				const uint8_t *d = b + 2 + RECVEE_DESC_LEN * i;
				mac_format((const mac_t *)(d + 2), m1);
				mac_format((const mac_t *)(d + 8), m2);
				mac_format((const mac_t *)(d + 14), m3);
				APPEND(" [real=%s %s>%s]", m1, m2, m3);
			}
		}
		break;
	case FN_FLAT:
		if (bl >= 5)
			APPEND(" ctc_bytes=%u ctc_frames=%u", get_be32(b), b[4]);
		break;
	case FN_QUERY_LARGE_TLV:
		if (bl >= 4)
			APPEND(" type=0x%02x offset=%u", b[0], (unsigned int)((b[1] << 16) | (b[2] << 8) | b[3]));
		break;
	case FN_QUERY_LARGE_TLV_RESP:
		if (bl >= 2)
			APPEND(" more=%u length=%u", !!(get_be16(b) & QLTLV_RESP_MORE), get_be16(b) & 0x3fff);
		break;
	default:
		break;
	}
	return pos;
}
