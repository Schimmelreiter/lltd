/*
 * Unit tests for the lltd responder core: frame parsing, quick discovery
 * (sessions, Hello, RepeatBAND) and topology discovery (charge, emit,
 * sequence numbers, sees-list, query, large TLVs).
 *
 * Every scenario writes all frames it exchanges to tests/out/<name>.pcap
 * (open them with Wireshark or "tcpdump -r").
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lltd_proto.h"
#include "responder.h"
#include "pcap.h"

/* ------------------------------------------------------------------ */
/* test harness                                                        */
/* ------------------------------------------------------------------ */

static int failures, checks;

#define CHECK(cond) do { \
		checks++; \
		if (!(cond)) { \
			failures++; \
			fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		} \
	} while (0)

#define MAX_TX 512

struct fake {
	uint8_t tx[MAX_TX][ETH_MAX_FRAME];
	size_t tx_len[MAX_TX];
	int n_tx;
	int promisc;
	mac_t fdb[64];
	int n_fdb;
	int fdb_adds, fdb_dels;
	uint32_t rnd;
	uint64_t now;
	FILE *pcap;
	int quiet;
};

static int f_send(void *ctx, const uint8_t *frame, size_t len)
{
	struct fake *f = ctx;

	if (f->n_tx < MAX_TX) {
		memcpy(f->tx[f->n_tx], frame, len);
		f->tx_len[f->n_tx] = len;
		f->n_tx++;
	}
	pcap_write(f->pcap, f->now, frame, len);
	return 0;
}

static void f_promisc(void *ctx, int on) { ((struct fake *)ctx)->promisc = on; }

static void f_fdb_add(void *ctx, const mac_t *m)
{
	struct fake *f = ctx;

	f->fdb_adds++;
	if (f->n_fdb < 64)
		f->fdb[f->n_fdb++] = *m;
}

static void f_fdb_del(void *ctx, const mac_t *m)
{
	struct fake *f = ctx;

	f->fdb_dels++;
	for (int i = 0; i < f->n_fdb; i++)
		if (mac_eq(&f->fdb[i], m)) {
			f->fdb[i] = f->fdb[--f->n_fdb];
			return;
		}
}

static uint32_t f_random(void *ctx) { return ((struct fake *)ctx)->rnd; }

static void f_log(void *ctx, int level, const char *msg)
{
	struct fake *f = ctx;

	if (!f->quiet && level <= 3 && getenv("LLTD_TEST_VERBOSE"))
		fprintf(stderr, "    [%d] %s\n", level, msg);
}

static const mac_t ME     = { { 0x02, 0x00, 0x00, 0x00, 0x00, 0x10 } };
static const mac_t MAPPER = { { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } };
static const mac_t OTHER_MAPPER = { { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } };
static const mac_t PEER   = { { 0x02, 0x00, 0x00, 0x00, 0x00, 0x20 } };
static const mac_t SPOOF1 = { { 0x00, 0x0d, 0x3a, 0xd7, 0xf2, 0x00 } };
static const mac_t SPOOF2 = { { 0x00, 0x0d, 0x3a, 0xd7, 0xf2, 0x01 } };

static uint8_t icon_data[3000];

static struct fake F;
static struct lltd_ops OPS = {
	.ctx = &F, .send = f_send, .set_promisc = f_promisc, .fdb_add = f_fdb_add,
	.fdb_del = f_fdb_del, .random = f_random, .log = f_log,
};
static struct lltd_responder R;

static void setup(const char *name)
{
	struct lltd_hostinfo info;
	char path[256];

	if (R.sees)
		lltd_free(&R);
	pcap_close(F.pcap);
	memset(&F, 0, sizeof(F));
	F.now = 1000;
	snprintf(path, sizeof(path), "out/%s.pcap", name);
	F.pcap = pcap_open(path);

	memset(&info, 0, sizeof(info));
	info.mac = ME;
	info.host_id = ME;
	info.machine_name_len = 8;
	memcpy(info.machine_name, "t\0e\0s\0t\0", 8);
	info.characteristics = CHAR_FULL_DUPLEX;
	info.medium = IFTYPE_ETHERNET;
	info.has_ipv4 = 1;
	memcpy(info.ipv4, "\xc0\xa8\x4b\x06", 4);
	info.link_speed = 10000000;     /* 1 Gbit/s */
	for (size_t i = 0; i < sizeof(icon_data); i++)
		icon_data[i] = (uint8_t)i;
	info.icon = icon_data;
	info.icon_len = sizeof(icon_data);
	lltd_init(&R, &OPS, &info);
	printf("- %s\n", name);
}

static void advance(uint64_t ms)
{
	uint64_t end = F.now + ms;

	for (;;) {
		uint64_t d = lltd_next_deadline(&R);

		if (!d || d > end)
			break;
		if (d > F.now)
			F.now = d;
		lltd_tick(&R, F.now);
	}
	F.now = end;
	lltd_tick(&R, F.now);
}

/* frame builder for the "mapper" side */
static size_t build(uint8_t *buf, const mac_t *eth_dst, const mac_t *eth_src, uint8_t tos,
		    uint8_t fn, const mac_t *real_dst, const mac_t *real_src, uint16_t seq,
		    const uint8_t *body, size_t body_len, size_t pad_to)
{
	size_t len = LLTD_HDR_LEN + body_len;

	lltd_put_header(buf, eth_dst, eth_src, tos, fn, real_dst, real_src, seq);
	if (body_len)
		memcpy(buf + LLTD_HDR_LEN, body, body_len);
	if (len < pad_to) {
		memset(buf + len, 0, pad_to - len);
		len = pad_to;
	}
	return len;
}

static void rx(const uint8_t *buf, size_t len)
{
	pcap_write(F.pcap, F.now, buf, len);
	lltd_rx(&R, buf, len, F.now);
	lltd_tick(&R, F.now);
}

static void discover(const mac_t *mapper, uint8_t tos, uint16_t xid, uint16_t gen, int ack_me)
{
	uint8_t body[64], buf[ETH_MAX_FRAME];
	size_t bl = 4;

	put_be16(body, gen);
	put_be16(body + 2, ack_me ? 2 : 1);
	memcpy(body + 4, PEER.a, 6);
	bl += 6;
	if (ack_me) {
		memcpy(body + bl, ME.a, 6);
		bl += 6;
	}
	rx(buf, build(buf, &MAC_BROADCAST, mapper, tos, FN_DISCOVER, &MAC_BROADCAST, mapper,
		      xid, body, bl, 60));
}

static void simple(uint8_t fn, uint16_t seq, size_t pad)
{
	uint8_t buf[ETH_MAX_FRAME];

	rx(buf, build(buf, &ME, &MAPPER, TOS_TOPOLOGY, fn, &ME, &MAPPER, seq, NULL, 0, pad));
}

static void reset(const mac_t *mapper, uint8_t tos)
{
	uint8_t buf[ETH_MAX_FRAME];

	rx(buf, build(buf, &MAC_BROADCAST, mapper, tos, FN_RESET, &MAC_BROADCAST, mapper, 0, NULL, 0, 60));
}

struct desc { uint8_t type, pause; mac_t src, dst; };

static void emit(uint16_t seq, const struct desc *d, int n)
{
	uint8_t body[2 + 14 * EMIT_MAX_DESCS], buf[ETH_MAX_FRAME];

	put_be16(body, (uint16_t)n);
	for (int i = 0; i < n; i++) {
		uint8_t *p = body + 2 + 14 * i;

		p[0] = d[i].type;
		p[1] = d[i].pause;
		memcpy(p + 2, d[i].src.a, 6);
		memcpy(p + 8, d[i].dst.a, 6);
	}
	rx(buf, build(buf, &ME, &MAPPER, TOS_TOPOLOGY, FN_EMIT, &ME, &MAPPER, seq, body,
		      2 + 14 * (size_t)n, 60));
}

static void probe_seen(const mac_t *from, const mac_t *eth_src, const mac_t *eth_dst)
{
	uint8_t buf[ETH_MAX_FRAME];

	rx(buf, build(buf, eth_dst, eth_src, TOS_TOPOLOGY, FN_PROBE, eth_dst, from, 0, NULL, 0, 60));
}

/* last transmitted frame with this function, or NULL */
static const uint8_t *last_tx(uint8_t fn, size_t *len)
{
	for (int i = F.n_tx - 1; i >= 0; i--)
		if (F.tx[i][17] == fn) {
			if (len)
				*len = F.tx_len[i];
			return F.tx[i];
		}
	return NULL;
}

static int count_tx(uint8_t fn)
{
	int n = 0;

	for (int i = 0; i < F.n_tx; i++)
		n += F.tx[i][17] == fn;
	return n;
}

/* bring the responder into Command state with MAPPER */
static void associate(void)
{
	discover(&MAPPER, TOS_TOPOLOGY, 0x1234, 7, 1);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(F.promisc == 1);
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void test_parse(void)
{
	uint8_t buf[ETH_MAX_FRAME];
	struct lltd_frame f;
	size_t len;
	char text[512];

	setup("parse");
	len = build(buf, &ME, &MAPPER, TOS_TOPOLOGY, FN_QUERY, &ME, &MAPPER, 0xBEEF, NULL, 0, 60);
	CHECK(lltd_parse(buf, len, &f) == 0);
	CHECK(f.tos == TOS_TOPOLOGY && f.function == FN_QUERY && f.seq == 0xBEEF);
	CHECK(mac_eq(&f.eth_dst, &ME) && mac_eq(&f.real_src, &MAPPER));
	CHECK(lltd_parse(buf, 20, &f) == -1);
	buf[12] = 0x08;
	CHECK(lltd_parse(buf, len, &f) == -1);
	buf[12] = 0x88;
	buf[14] = 2;
	CHECK(lltd_parse(buf, len, &f) == -1);

	CHECK(seq_next(1) == 2);
	CHECK(seq_next(0xFFFF) == 1);
	CHECK(mac_in_lltd_pool(&SPOOF1));
	CHECK(!mac_in_lltd_pool(&PEER));

	buf[14] = 1;
	lltd_parse(buf, len, &f);
	lltd_describe(&f, text, sizeof(text));
	CHECK(strstr(text, "Query") != NULL);
}

static void test_hello(void)
{
	const uint8_t *h;
	size_t len, i;
	int seen[256] = { 0 };

	setup("hello");
	F.rnd = 0;                              /* Hello timer fires at once */
	discover(&MAPPER, TOS_QUICK, 0x2222, 0, 0);
	CHECK(R.estate == ENUM_PAUSING);
	advance(1);
	h = last_tx(FN_HELLO, &len);
	CHECK(h != NULL);
	if (!h)
		return;
	CHECK(h[15] == TOS_QUICK);
	CHECK(mac_is_broadcast((const mac_t *)h));
	CHECK(mac_is_broadcast((const mac_t *)(h + 18)));
	/* Hello header: generation, current mapper (no topology session: zero) */
	CHECK(get_be16(h + 32) == 0);
	CHECK(mac_is_zero((const mac_t *)(h + 34)));
	for (i = 46; i + 2 <= len && h[i] != TLV_END; i += 2 + h[i + 1])
		seen[h[i]]++;
	CHECK(i < len && h[i] == TLV_END);
	/* mandatory attributes (2.2.1.1) */
	CHECK(seen[TLV_HOST_ID] == 1);
	CHECK(seen[TLV_CHARACTERISTICS] == 1);
	CHECK(seen[TLV_PHYSICAL_MEDIUM] == 1);
	CHECK(seen[TLV_MACHINE_NAME] == 1);
	CHECK(seen[TLV_IPV4] == 1);
	CHECK(seen[TLV_LINK_SPEED] == 1);
	CHECK(seen[TLV_SEES_LIST_WS] == 1);
	CHECK(seen[TLV_ICON] == 1);
	CHECK(seen[TLV_QOS_CHAR] == 1);
	for (i = 0; i < 256; i++)
		CHECK(seen[i] <= 1);    /* no attribute twice */

	/* the session stays pending: Hello is repeated, at most TXC times */
	advance(10 * RB_TB_MS);
	CHECK(count_tx(FN_HELLO) == HELLO_TXC);
	CHECK(R.estate == ENUM_WAIT);   /* Txc exhausted -> complete */

	/* acknowledged by the station list */
	setup("hello-ack");
	discover(&MAPPER, TOS_QUICK, 0x2222, 0, 0);
	advance(1);
	CHECK(count_tx(FN_HELLO) == 1);
	discover(&MAPPER, TOS_QUICK, 0x2222, 0, 1);
	CHECK(R.estate == ENUM_WAIT);
	advance(2000);
	CHECK(count_tx(FN_HELLO) == 1);
	CHECK(R.tstate == TOPO_QUIESCENT);  /* quick discovery does not associate */

	reset(&MAPPER, TOS_QUICK);
	CHECK(R.estate == ENUM_QUIESCENT);
}

static void test_repeatband(void)
{
	setup("repeatband");
	F.rnd = 0xFFFFFFFF;                 /* never inside the first blocks */
	discover(&MAPPER, TOS_QUICK, 1, 0, 0);
	CHECK(R.n_est == RB_NMAX);
	advance(RB_TB_MS);
	/* quiet network: N drops to about N/9 per block (bound) */
	CHECK(R.n_est == (RB_NMAX * RB_GAMMA + RB_BETA * RB_ALPHA - 1) / (RB_BETA * RB_ALPHA));
	/* a new enumerator while pausing doubles N at the end of the block */
	{
		uint32_t nold, bound;

		CHECK(R.estate == ENUM_PAUSING);
		discover(&OTHER_MAPPER, TOS_QUICK, 9, 0, 0);
		CHECK(R.begun == 1);
		nold = R.n_est;
		bound = (nold * RB_GAMMA + RB_BETA * RB_ALPHA - 1) / (RB_BETA * RB_ALPHA);
		advance(RB_TB_MS);
		CHECK(R.n_est == 2 * bound);
		CHECK(R.begun == 0);
	}
	advance(10 * RB_TB_MS);
	CHECK(R.n_est >= 1 && R.n_est < 10);
}

static void test_association(void)
{
	setup("association");
	F.rnd = 0;
	discover(&MAPPER, TOS_TOPOLOGY, 0x1234, 7, 0);
	CHECK(R.tstate == TOPO_QUIESCENT);
	advance(1);
	{
		const uint8_t *h = last_tx(FN_HELLO, NULL);

		CHECK(h && h[15] == TOS_TOPOLOGY);
		CHECK(h && mac_eq((const mac_t *)(h + 34), &MAPPER));    /* current mapper */
		CHECK(h && mac_eq((const mac_t *)(h + 40), &MAPPER));    /* apparent mapper */
	}
	discover(&MAPPER, TOS_TOPOLOGY, 0x1234, 7, 1);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(R.generation == 7);
	CHECK(F.promisc == 1);

	/* a second mapper only gets a temporary session (until the next Hello) */
	F.rnd = 0xFFFFFFFF;
	discover(&OTHER_MAPPER, TOS_TOPOLOGY, 0x5555, 0, 1);
	CHECK(R.have_mapper && mac_eq(&R.mapper, &MAPPER));
	{
		int temp = 0;

		for (int i = 0; i < LLTD_MAX_SESSIONS; i++)
			temp += R.sessions[i].state == SESS_TEMPORARY;
		CHECK(temp == 1);
	}

	/* Reset of the topology session: back to quiescent, temporaries go */
	reset(&MAPPER, TOS_TOPOLOGY);
	CHECK(R.tstate == TOPO_QUIESCENT);
	CHECK(F.promisc == 0);
	CHECK(R.estate == ENUM_QUIESCENT);
}

static void test_query_sequence(void)
{
	const uint8_t *q;
	size_t len;
	int n;

	setup("query-sequence");
	associate();
	simple(FN_QUERY, 0, 60);                /* sequence 0 is ignored */
	CHECK(count_tx(FN_QUERY_RESP) == 0);
	simple(FN_QUERY, 100, 60);
	q = last_tx(FN_QUERY_RESP, &len);
	CHECK(q && get_be16(q + 30) == 100 && get_be16(q + 32) == 0);
	CHECK(R.next_seq == 101);
	n = count_tx(FN_QUERY_RESP);
	simple(FN_QUERY, 100, 60);              /* repeated: saved answer again */
	CHECK(count_tx(FN_QUERY_RESP) == n + 1);
	simple(FN_QUERY, 105, 60);              /* out of sequence: ignored */
	CHECK(count_tx(FN_QUERY_RESP) == n + 1);
	simple(FN_QUERY, 101, 60);
	CHECK(count_tx(FN_QUERY_RESP) == n + 2);
	/* a keep-alive Charge between a lost reply and the retry keeps the
	 * saved answer */
	simple(FN_CHARGE, 0, 60);
	simple(FN_QUERY, 101, 60);
	CHECK(count_tx(FN_QUERY_RESP) == n + 3);
	/* an acknowledged Charge without padding for the Flat is ignored and
	 * does not use up the sequence number */
	R.ctc_fc = 0;
	R.ctc_bc = 0;
	simple(FN_CHARGE, 102, 20);
	CHECK(count_tx(FN_FLAT) == 0 && R.next_seq == 102);

	/* ones-complement wrap */
	R.next_seq = 0xFFFF;
	simple(FN_QUERY, 0xFFFF, 60);
	CHECK(R.next_seq == 1);

	/* requests to another responder (seen in promiscuous mode) are ignored */
	{
		uint8_t buf[ETH_MAX_FRAME];

		n = count_tx(FN_QUERY_RESP);
		rx(buf, build(buf, &PEER, &MAPPER, TOS_TOPOLOGY, FN_QUERY, &PEER, &MAPPER, 1, NULL, 0, 60));
		CHECK(count_tx(FN_QUERY_RESP) == n);
	}
	/* frames from a mapper without a session are ignored */
	{
		uint8_t buf[ETH_MAX_FRAME];

		n = count_tx(FN_QUERY_RESP);
		rx(buf, build(buf, &ME, &OTHER_MAPPER, TOS_TOPOLOGY, FN_QUERY, &ME, &OTHER_MAPPER, 1, NULL, 0, 60));
		CHECK(count_tx(FN_QUERY_RESP) == n);
	}
}

static void test_charge_and_emit(void)
{
	struct desc trains[2] = {
		{ EMITEE_TRAIN, 120, SPOOF1, PEER },
		{ EMITEE_TRAIN, 5, SPOOF1, PEER },
	};
	const uint8_t *fr;
	int acks;

	setup("charge-emit");
	associate();

	/* acknowledged Emit without charge: Flat with the old (zero) CTC */
	emit(10, trains, 2);
	fr = last_tx(FN_FLAT, NULL);
	CHECK(fr && get_be16(fr + 30) == 10);
	CHECK(fr && get_be32(fr + 32) == 0 && fr[36] == 0);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(R.next_seq == 11);

	/* the mapper charges (60 byte frames) and retries with the next number */
	for (int i = 0; i < 3; i++)
		simple(FN_CHARGE, 0, 60);
	CHECK(R.ctc_fc == 3 + 0 && R.ctc_bc >= 3 * 60);
	emit(11, trains, 2);
	CHECK(R.tstate == TOPO_EMIT);
	CHECK(R.ctc_fc == 0 && R.ctc_bc == 0);      /* all charge consumed */
	CHECK(count_tx(FN_TRAIN) == 0);
	advance(119);
	CHECK(count_tx(FN_TRAIN) == 0);             /* first pause: 120 ms */
	advance(1);
	CHECK(count_tx(FN_TRAIN) == 1);
	fr = last_tx(FN_TRAIN, NULL);
	CHECK(fr && mac_eq((const mac_t *)(fr + 6), &SPOOF1));     /* Ethernet source */
	CHECK(fr && mac_eq((const mac_t *)(fr + 24), &ME));        /* real source */
	CHECK(fr && mac_eq((const mac_t *)fr, &PEER));
	CHECK(F.n_fdb == 1 && mac_eq(&F.fdb[0], &SPOOF1));         /* bridge learns X */

	/* Charges/Emits while emitting are ignored */
	emit(12, trains, 2);
	advance(5);
	CHECK(count_tx(FN_TRAIN) == 2);
	fr = last_tx(FN_ACK, NULL);
	CHECK(fr && get_be16(fr + 30) == 11);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(R.next_seq == 12);
	acks = count_tx(FN_ACK);

	/* repeated Emit: saved Ack again, nothing emitted */
	emit(11, trains, 2);
	CHECK(count_tx(FN_ACK) == acks + 1);
	CHECK(count_tx(FN_TRAIN) == 2);

	/* acknowledged Charge: Flat with the CTC before this frame */
	simple(FN_CHARGE, 0, 60);
	simple(FN_CHARGE, 12, 60);
	fr = last_tx(FN_FLAT, NULL);
	CHECK(fr && get_be16(fr + 30) == 12);
	CHECK(fr && get_be32(fr + 32) == 60 && fr[36] == 1);
	CHECK(R.next_seq == 13);

	/* charge expires after one second */
	advance(CHARGE_TIMEOUT_MS + 1);
	CHECK(R.ctc_fc == 0 && R.ctc_bc == 0);

	/* FDB entry expires after the hold time */
	advance(10000);
	CHECK(F.n_fdb == 0);
}

static void test_unacked_probe_emit(void)
{
	struct desc p = { EMITEE_PROBE, 120, ME, SPOOF2 };
	const uint8_t *fr;

	setup("probe-emit");
	associate();
	/* a single unacknowledged probe brings its own charge (60 byte frame) */
	emit(0, &p, 1);
	CHECK(R.tstate == TOPO_EMIT);
	advance(120);
	CHECK(count_tx(FN_PROBE) == 1);
	fr = last_tx(FN_PROBE, NULL);
	CHECK(fr && mac_eq((const mac_t *)(fr + 6), &ME) && mac_eq((const mac_t *)fr, &SPOOF2));
	CHECK(count_tx(FN_ACK) == 0);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(F.n_fdb == 0);    /* probes use our own address: no FDB entry */

	/* two probes need more charge than one frame carries: ignored, no Flat */
	{
		struct desc two[2] = { p, p };

		emit(0, two, 2);
		CHECK(R.tstate == TOPO_COMMAND);
		CHECK(count_tx(FN_FLAT) == 0);
	}
}

static void test_invalid_emit(void)
{
	struct desc bad_src = { EMITEE_TRAIN, 0, PEER, SPOOF2 };
	struct desc bad_dst = { EMITEE_TRAIN, 0, SPOOF1, MAC_BROADCAST };
	struct desc long_pause[5] = {
		{ EMITEE_TRAIN, 250, SPOOF1, PEER }, { EMITEE_TRAIN, 250, SPOOF1, PEER },
		{ EMITEE_TRAIN, 250, SPOOF1, PEER }, { EMITEE_TRAIN, 250, SPOOF1, PEER },
		{ EMITEE_TRAIN, 250, SPOOF1, PEER },
	};

	setup("invalid-emit");
	associate();
	for (int i = 0; i < 8; i++)
		simple(FN_CHARGE, 0, 60);
	emit(1, &bad_src, 1);
	emit(1, &bad_dst, 1);
	emit(1, long_pause, 5);
	CHECK(R.tstate == TOPO_COMMAND);
	CHECK(count_tx(FN_FLAT) == 0 && count_tx(FN_ACK) == 0);
	CHECK(R.next_seq == 0);     /* invalid frames do not consume a number */
}

static void test_sees_list(void)
{
	const uint8_t *q;
	size_t len;

	setup("sees-list");
	/* probes are only recorded in Command/Emit state */
	probe_seen(&PEER, &PEER, &SPOOF1);
	associate();
	CHECK(R.sees_count == 0);
	for (int i = 0; i < 100; i++)
		probe_seen(&PEER, &PEER, &SPOOF1);
	CHECK(R.sees_count == 100);
	simple(FN_QUERY, 1, 60);
	q = last_tx(FN_QUERY_RESP, &len);
	CHECK(q && (get_be16(q + 32) & 0x3fff) == QUERY_RESP_MAX_DESCS);
	CHECK(q && (get_be16(q + 32) & QUERY_RESP_MORE));
	CHECK(q && len == LLTD_HDR_LEN + 2 + 20 * QUERY_RESP_MAX_DESCS && len <= ETH_MAX_FRAME);
	CHECK(q && mac_eq((const mac_t *)(q + 34 + 2), &PEER));    /* real source */
	CHECK(q && mac_eq((const mac_t *)(q + 34 + 14), &SPOOF1)); /* Ethernet destination */
	simple(FN_QUERY, 2, 60);
	q = last_tx(FN_QUERY_RESP, NULL);
	CHECK(q && get_be16(q + 32) == 100 - QUERY_RESP_MAX_DESCS);
	CHECK(R.sees_count == 0);

	/* full sees-list: error flag in the next QueryResp, cleared when empty */
	R.sees_cap = 3;
	R.sees_head = 0;
	for (int i = 0; i < 5; i++)
		probe_seen(&PEER, &PEER, &SPOOF1);
	CHECK(R.error_flag == 1);
	simple(FN_QUERY, 3, 60);
	q = last_tx(FN_QUERY_RESP, NULL);
	CHECK(q && (get_be16(q + 32) & QUERY_RESP_ERROR) && (get_be16(q + 32) & 0x3fff) == 3);
	CHECK(R.error_flag == 0);
	R.sees_cap = LLTD_SEES_LIST_MAX;
}

static void test_large_tlv(void)
{
	uint8_t body[4], buf[ETH_MAX_FRAME];
	const uint8_t *r;
	size_t len, got = 0;
	uint16_t seq = 50;

	setup("large-tlv");
	associate();
	for (;;) {
		body[0] = TLV_ICON;
		body[1] = (uint8_t)(got >> 16);
		body[2] = (uint8_t)(got >> 8);
		body[3] = (uint8_t)got;
		rx(buf, build(buf, &ME, &MAPPER, TOS_TOPOLOGY, FN_QUERY_LARGE_TLV, &ME, &MAPPER, seq,
			      body, 4, 60));
		r = last_tx(FN_QUERY_LARGE_TLV_RESP, &len);
		CHECK(r && get_be16(r + 30) == seq);
		if (!r)
			return;
		CHECK(memcmp(r + 34, icon_data + got, get_be16(r + 32) & 0x3fff) == 0);
		got += get_be16(r + 32) & 0x3fff;
		seq++;
		if (!(get_be16(r + 32) & QLTLV_RESP_MORE))
			break;
	}
	CHECK(got == sizeof(icon_data));

	/* unsupported type: empty answer */
	body[0] = TLV_HARDWARE_ID;
	memset(body + 1, 0, 3);
	rx(buf, build(buf, &ME, &MAPPER, TOS_TOPOLOGY, FN_QUERY_LARGE_TLV, &ME, &MAPPER, seq, body, 4, 60));
	r = last_tx(FN_QUERY_LARGE_TLV_RESP, NULL);
	CHECK(r && get_be16(r + 32) == 0);
}

static void test_broadcast_reply(void)
{
	uint8_t buf[ETH_MAX_FRAME];
	const mac_t rewritten = { { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee } };
	const uint8_t *q;

	setup("broadcast-reply");
	associate();
	/* Ethernet source differs from the real source: answer by broadcast */
	rx(buf, build(buf, &ME, &rewritten, TOS_TOPOLOGY, FN_QUERY, &ME, &MAPPER, 9, NULL, 0, 60));
	q = last_tx(FN_QUERY_RESP, NULL);
	CHECK(q && mac_is_broadcast((const mac_t *)q));
	CHECK(q && mac_eq((const mac_t *)(q + 18), &MAPPER));
	simple(FN_QUERY, 10, 60);
	q = last_tx(FN_QUERY_RESP, NULL);
	CHECK(q && mac_eq((const mac_t *)q, &MAPPER));
}

static void test_timeouts(void)
{
	setup("timeouts");
	associate();
	/* the mapper keeps the session alive with a charge every 8 s */
	for (int i = 0; i < 10; i++) {
		advance(8000);
		simple(FN_CHARGE, 0, 60);
	}
	CHECK(R.tstate == TOPO_COMMAND);
	/* topology session in Command state: 60 s without frames */
	advance(59000);
	CHECK(R.tstate == TOPO_COMMAND);
	advance(2000);
	CHECK(R.tstate == TOPO_QUIESCENT);
	CHECK(R.estate == ENUM_QUIESCENT);

	/* quick discovery session: 30 s */
	setup("timeouts-quick");
	discover(&MAPPER, TOS_QUICK, 3, 0, 1);
	CHECK(R.estate == ENUM_WAIT);
	advance(29000);
	CHECK(R.estate == ENUM_WAIT);
	advance(2000);
	CHECK(R.estate == ENUM_QUIESCENT);
}

static void test_mapper_round(void)
{
	/* the sequence the LLTD-Netzwerkuebersicht mapper uses for one round */
	struct desc t2[2] = { { EMITEE_TRAIN, 120, SPOOF1, PEER }, { EMITEE_TRAIN, 5, SPOOF1, PEER } };
	struct desc p = { EMITEE_PROBE, 120, ME, SPOOF1 };
	uint16_t seq = 30000;
	const uint8_t *q;

	setup("mapper-round");
	F.rnd = 0;
	discover(&MAPPER, TOS_QUICK, 77, 0, 0);
	discover(&MAPPER, TOS_TOPOLOGY, 78, 0, 0);
	advance(400);
	discover(&MAPPER, TOS_QUICK, 77, 0, 1);
	discover(&MAPPER, TOS_TOPOLOGY, 78, 0, 1);
	reset(&MAPPER, TOS_QUICK);
	CHECK(R.tstate == TOPO_COMMAND);

	/* Verify: Query must be answered at once */
	simple(FN_QUERY, seq, 60);
	CHECK(last_tx(FN_QUERY_RESP, NULL) != NULL);
	seq = seq_next(seq);

	/* c role: charge, acknowledged Emit with two trains, Ack */
	for (int i = 0; i < 3; i++)
		simple(FN_CHARGE, 0, 60);
	emit(seq, t2, 2);
	advance(200);
	q = last_tx(FN_ACK, NULL);
	CHECK(q && get_be16(q + 30) == seq);
	seq = seq_next(seq);

	/* prober role: unacknowledged single probe */
	emit(0, &p, 1);
	advance(150);
	CHECK(count_tx(FN_PROBE) == 1);

	/* other responders' probes arrive at us */
	probe_seen(&PEER, &PEER, &SPOOF1);
	simple(FN_QUERY, seq, 60);
	q = last_tx(FN_QUERY_RESP, NULL);
	CHECK(q && get_be16(q + 30) == seq && get_be16(q + 32) == 1);

	/* end: Reset for ToS 0 */
	reset(&MAPPER, TOS_TOPOLOGY);
	CHECK(R.tstate == TOPO_QUIESCENT);
	CHECK(F.n_fdb == 0 && F.promisc == 0);
}


/* one "c" round: charge, acknowledged Emit with two trains, Ack (or not) */
static int train_round(uint16_t *seq)
{
	struct desc t2[2] = { { EMITEE_TRAIN, 10, SPOOF1, PEER }, { EMITEE_TRAIN, 5, SPOOF1, PEER } };
	int acks = count_tx(FN_ACK);

	for (int i = 0; i < 3; i++)
		simple(FN_CHARGE, 0, 60);
	emit(*seq, t2, 2);
	advance(50);
	if (count_tx(FN_ACK) == acks)
		return 0;
	*seq = seq_next(*seq);
	return 1;
}

static void test_observe(void)
{
	struct desc p = { EMITEE_PROBE, 10, ME, SPOOF2 };
	uint16_t seq;
	int ok = 1;

	/* deaf interface: no probe of another responder arrives */
	setup("observe-deaf");
	associate();
	seq = 100;
	for (int i = 0; i < LLTD_OBSERVE_MIN_ROUNDS; i++) {
		ok &= train_round(&seq);
		/* the mapper's own probe arrives (as in its self-test): does not count */
		probe_seen(&MAPPER, &MAPPER, &SPOOF1);
	}
	CHECK(ok);                              /* this session is not changed */
	CHECK(R.observe_deaf == 1 && R.observe_off == 0);
	CHECK(train_round(&seq) == 1);
	reset(&MAPPER, TOS_TOPOLOGY);
	CHECK(R.observe_off == 1);

	/* next session: Trains refused (no Ack, no Flat), probes still emitted */
	associate();
	seq = 200;
	{
		int flats = count_tx(FN_FLAT);

		CHECK(train_round(&seq) == 0);
		CHECK(count_tx(FN_FLAT) == flats);
	}
	emit(0, &p, 1);
	advance(20);
	CHECK(count_tx(FN_PROBE) == 1);
	reset(&MAPPER, TOS_TOPOLOGY);

	/* link loss clears the state */
	lltd_media_disconnect(&R);
	CHECK(R.observe_off == 0);

	/* healthy interface: a probe of another responder reaches X */
	setup("observe-ok");
	associate();
	seq = 300;
	for (int i = 0; i < LLTD_OBSERVE_MIN_ROUNDS + 2; i++) {
		train_round(&seq);
		if (i == 1)
			probe_seen(&PEER, &PEER, &SPOOF1);
	}
	CHECK(R.observe_deaf == 0);
	reset(&MAPPER, TOS_TOPOLOGY);
	CHECK(R.observe_off == 0);

	/* --observe yes / no */
	setup("observe-modes");
	R.observe_mode = LLTD_OBSERVE_NO;
	associate();
	seq = 400;
	CHECK(train_round(&seq) == 0);
	R.observe_mode = LLTD_OBSERVE_YES;
	R.observe_off = 1;
	CHECK(train_round(&seq) == 1);
}

int main(void)
{
	test_parse();
	test_hello();
	test_repeatband();
	test_association();
	test_query_sequence();
	test_charge_and_emit();
	test_unacked_probe_emit();
	test_invalid_emit();
	test_sees_list();
	test_large_tlv();
	test_broadcast_reply();
	test_timeouts();
	test_mapper_round();
	test_observe();
	lltd_free(&R);
	pcap_close(F.pcap);

	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
