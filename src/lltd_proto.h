/*
 * lltd - Link Layer Topology Discovery responder
 *
 * Protocol constants and wire format helpers, see [MS-LLTD] section 2.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef LLTD_PROTO_H
#define LLTD_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ETH_ADDR_LEN        6
#define LLTD_ETHERTYPE      0x88D9

/* Ethernet header (14) + demultiplex header (4) + base header (14) */
#define ETH_HDR_LEN         14
#define DEMUX_HDR_LEN       4
#define BASE_HDR_LEN        14
#define LLTD_HDR_LEN        (ETH_HDR_LEN + DEMUX_HDR_LEN + BASE_HDR_LEN)  /* 32 */

#define ETH_MIN_FRAME       60      /* without FCS */
#define ETH_MAX_FRAME       1514    /* 1500 bytes payload, without FCS */

/* Demultiplex header: version and types of service (2.2.3.1) */
#define LLTD_VERSION        0x01
#define TOS_TOPOLOGY        0x00
#define TOS_QUICK           0x01
#define TOS_QOS             0x02

/* Functions for ToS 0 (topology) and ToS 1 (quick discovery) */
enum lltd_function {
	FN_DISCOVER          = 0x00,
	FN_HELLO             = 0x01,
	FN_EMIT              = 0x02,
	FN_TRAIN             = 0x03,
	FN_PROBE             = 0x04,
	FN_ACK               = 0x05,
	FN_QUERY             = 0x06,
	FN_QUERY_RESP        = 0x07,
	FN_RESET             = 0x08,
	FN_CHARGE            = 0x09,
	FN_FLAT              = 0x0A,
	FN_QUERY_LARGE_TLV   = 0x0B,
	FN_QUERY_LARGE_TLV_RESP = 0x0C,
};

/* Hello attributes (2.2.1.1) */
enum lltd_tlv {
	TLV_END              = 0x00,
	TLV_HOST_ID          = 0x01,
	TLV_CHARACTERISTICS  = 0x02,
	TLV_PHYSICAL_MEDIUM  = 0x03,
	TLV_WIRELESS_MODE    = 0x04,
	TLV_BSSID            = 0x05,
	TLV_SSID             = 0x06,
	TLV_IPV4             = 0x07,
	TLV_IPV6             = 0x08,
	TLV_MAX_RATE         = 0x09,
	TLV_PERF_FREQ        = 0x0A,
	TLV_LINK_SPEED       = 0x0C,
	TLV_RSSI             = 0x0D,
	TLV_ICON             = 0x0E,
	TLV_MACHINE_NAME     = 0x0F,
	TLV_SUPPORT_INFO     = 0x10,
	TLV_FRIENDLY_NAME    = 0x11,
	TLV_UUID             = 0x12,
	TLV_HARDWARE_ID      = 0x13,
	TLV_QOS_CHAR         = 0x14,
	TLV_80211_PHY        = 0x15,
	TLV_AP_ASSOC_TABLE   = 0x16,
	TLV_DETAILED_ICON    = 0x18,
	TLV_SEES_LIST_WS     = 0x19,
	TLV_COMPONENT_TABLE  = 0x1A,
	TLV_REPEATER_LINEAGE = 0x1B,
	TLV_REPEATER_TABLE   = 0x1C,
};

/* Characteristics bits (2.2.1.1.3), 16 bit field, MSB first */
#define CHAR_NAT_PUBLIC     0x8000  /* P */
#define CHAR_NAT_PRIVATE    0x4000  /* X */
#define CHAR_FULL_DUPLEX    0x2000  /* F */
#define CHAR_HAS_WEB_PAGE   0x1000  /* M */
#define CHAR_LOOPBACK       0x0800  /* L */

/* IANA ifType values for the Physical Medium attribute */
#define IFTYPE_ETHERNET     6
#define IFTYPE_IEEE80211    71

/* Emit descriptor types (2.2.4.4) */
#define EMITEE_TRAIN        0x00
#define EMITEE_PROBE        0x01
#define EMITEE_DESC_LEN     14
#define EMIT_MAX_DESCS      105
#define EMIT_MAX_PAUSE_MS   1000

/* QueryResp (2.2.4.9) */
#define RECVEE_DESC_LEN     20
#define RECVEE_TYPE_PROBE   0x0000
#define QUERY_RESP_MORE     0x8000
#define QUERY_RESP_ERROR    0x4000
#define QUERY_RESP_MAX_DESCS ((ETH_MAX_FRAME - LLTD_HDR_LEN - 2) / RECVEE_DESC_LEN)  /* 74 */

/* QueryLargeTlvResp (2.2.4.14) */
#define QLTLV_RESP_MORE     0x8000
#define QLTLV_RESP_MAX_DATA (ETH_MAX_FRAME - LLTD_HDR_LEN - 2)                  /* 1480 */

/* Charge accounting (3.6.5.1, 3.6.5.2) */
#define CTC_MAX_FC          64
#define CTC_MAX_BC          65536
#define CHARGE_FLAT_BC      37
#define CHARGE_FRAME_BC     32      /* Train, Probe, Ack */

/* Topology discovery address pool (2.2.4.2) */
#define LLTD_POOL_FIRST     0x000D3AD7F140ULL
#define LLTD_POOL_LAST      0x000D3AFFFFFFULL

typedef struct {
	uint8_t a[ETH_ADDR_LEN];
} mac_t;

static inline int mac_eq(const mac_t *x, const mac_t *y)
{
	return memcmp(x->a, y->a, ETH_ADDR_LEN) == 0;
}

static inline int mac_is_zero(const mac_t *m)
{
	static const mac_t zero;
	return mac_eq(m, &zero);
}

static inline int mac_is_broadcast(const mac_t *m)
{
	static const mac_t bc = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
	return mac_eq(m, &bc);
}

static inline int mac_is_multicast(const mac_t *m)
{
	return (m->a[0] & 0x01) != 0;   /* includes broadcast */
}

static inline uint64_t mac_to_u64(const mac_t *m)
{
	uint64_t v = 0;
	for (int i = 0; i < ETH_ADDR_LEN; i++)
		v = (v << 8) | m->a[i];
	return v;
}

static inline int mac_in_lltd_pool(const mac_t *m)
{
	uint64_t v = mac_to_u64(m);
	return v >= LLTD_POOL_FIRST && v <= LLTD_POOL_LAST;
}

extern const mac_t MAC_BROADCAST;

/* big endian helpers */
static inline uint16_t get_be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* Ones-complement increment of a sequence number: 0xFFFF -> 0x0001, never 0 */
static inline uint16_t seq_next(uint16_t s)
{
	s++;
	if (s == 0)
		s = 1;
	return s;
}

/* A parsed frame (pointers into the receive buffer) */
struct lltd_frame {
	const uint8_t *raw;
	size_t len;             /* whole Ethernet frame without FCS */
	mac_t eth_dst;
	mac_t eth_src;
	uint8_t tos;
	uint8_t function;
	mac_t real_dst;
	mac_t real_src;
	uint16_t seq;           /* sequence number or XID */
	const uint8_t *body;    /* upper-level header */
	size_t body_len;
};

/* Parse an Ethernet frame. Returns 0 on success, -1 if it is not a valid
 * LLTD frame (wrong EtherType, version or too short). */
int lltd_parse(const uint8_t *buf, size_t len, struct lltd_frame *f);

/* Writes Ethernet, demultiplex and base header to buf (LLTD_HDR_LEN bytes) */
void lltd_put_header(uint8_t *buf, const mac_t *eth_dst, const mac_t *eth_src,
		     uint8_t tos, uint8_t function,
		     const mac_t *real_dst, const mac_t *real_src, uint16_t seq);

/* Name helpers for logs */
const char *lltd_function_name(uint8_t tos, uint8_t function);
void mac_format(const mac_t *m, char out[18]);
int mac_parse(const char *s, mac_t *m);

/* Writes a human readable decoding of a frame (for debug logs) */
size_t lltd_describe(const struct lltd_frame *f, char *out, size_t outlen);

#endif
