/*
 * lltd - responder core: quick discovery ([MS-LLTD] 3.5) and topology
 * discovery ([MS-LLTD] 3.6) for one network interface.
 *
 * Timer deadlines are absolute milliseconds of a monotonic clock; 0 means
 * "not running" (callers must use a clock that never returns 0).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "responder.h"

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void logm(struct lltd_responder *r, int level, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void logm(struct lltd_responder *r, int level, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	if (!r->ops->log || level > r->log_level)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	r->ops->log(r->ops->ctx, level, buf);
}

static void log_frame(struct lltd_responder *r, const char *dir, const uint8_t *buf, size_t len)
{
	struct lltd_frame f;
	char text[1024];

	if (!r->ops->log || r->log_level < 4 || lltd_parse(buf, len, &f) != 0)
		return;
	lltd_describe(&f, text, sizeof(text));
	logm(r, 4, "%s %s", dir, text);
}

static int send_frame(struct lltd_responder *r, uint8_t *buf, size_t len)
{
	if (len < ETH_MIN_FRAME) {
		memset(buf + len, 0, ETH_MIN_FRAME - len);
		len = ETH_MIN_FRAME;
	}
	log_frame(r, "tx", buf, len);
	if (r->ops->send(r->ops->ctx, buf, len) != 0) {
		r->tx_errors++;
		return -1;
	}
	r->tx_frames++;
	return 0;
}

/* Responses go to the real source, or to broadcast if the Ethernet source
 * was rewritten on the way (3.6.5.x) */
static const mac_t *reply_dst(const struct lltd_frame *req)
{
	return mac_eq(&req->real_src, &req->eth_src) ? &req->real_src : &MAC_BROADCAST;
}

static int addressed_to_us(const struct lltd_responder *r, const struct lltd_frame *f)
{
	return mac_is_broadcast(&f->eth_dst) || mac_eq(&f->eth_dst, &r->info.mac);
}

static uint32_t rnd(struct lltd_responder *r)
{
	return r->ops->random ? r->ops->random(r->ops->ctx) : (uint32_t)rand();
}

/* ------------------------------------------------------------------ */
/* bridge FDB entries for Train sources                                */
/* ------------------------------------------------------------------ */

static void fdb_remove_at(struct lltd_responder *r, int i)
{
	if (r->ops->fdb_del)
		r->ops->fdb_del(r->ops->ctx, &r->fdb[i].mac);
	r->fdb[i] = r->fdb[--r->fdb_count];
}

static void fdb_learn(struct lltd_responder *r, const mac_t *mac, uint64_t now)
{
	int i, oldest = 0;

	if (!r->ops->fdb_add || mac_eq(mac, &r->info.mac))
		return;
	for (i = 0; i < r->fdb_count; i++) {
		if (mac_eq(&r->fdb[i].mac, mac)) {
			r->fdb[i].expires = now + (uint64_t)r->fdb_hold_ms;
			return;
		}
		if (r->fdb[i].expires < r->fdb[oldest].expires)
			oldest = i;
	}
	if (r->fdb_count == LLTD_FDB_MAX)
		fdb_remove_at(r, oldest);
	r->fdb[r->fdb_count].mac = *mac;
	r->fdb[r->fdb_count].expires = now + (uint64_t)r->fdb_hold_ms;
	r->fdb_count++;
	r->ops->fdb_add(r->ops->ctx, mac);
}

static void fdb_expire(struct lltd_responder *r, uint64_t now, int all)
{
	for (int i = 0; i < r->fdb_count;) {
		if (all || r->fdb[i].expires <= now)
			fdb_remove_at(r, i);
		else
			i++;
	}
}

/* ------------------------------------------------------------------ */
/* topology discovery state engine (3.6)                               */
/* ------------------------------------------------------------------ */

static void topo_enter_quiescent(struct lltd_responder *r)
{
	int was = r->tstate;

	r->tstate = TOPO_QUIESCENT;
	r->charge_deadline = 0;
	r->emit_deadline = 0;
	r->emit_count = r->emit_pos = 0;
	r->emit_seq = 0;
	r->ctc_fc = 0;
	r->ctc_bc = 0;
	r->sees_head = r->sees_count = 0;
	r->error_flag = 0;
	r->last_valid = 0;
	r->next_seq = 0;
	fdb_expire(r, 0, 1);
	if (was != TOPO_QUIESCENT) {
		if (r->ops->set_promisc)
			r->ops->set_promisc(r->ops->ctx, 0);
		logm(r, 2, "topology: quiescent");
	}
}

static void topo_enter_command(struct lltd_responder *r)
{
	int was = r->tstate;

	r->tstate = TOPO_COMMAND;
	r->emit_deadline = 0;
	r->emit_count = r->emit_pos = 0;
	r->ctc_fc = 0;
	r->ctc_bc = 0;
	/* 3.6.6.2: after an Emit the next request has the following number */
	if (r->emit_seq != 0) {
		r->next_seq = seq_next(r->emit_seq);
		r->emit_seq = 0;
	}
	if (was == TOPO_QUIESCENT) {
		char m[18];

		if (r->ops->set_promisc)
			r->ops->set_promisc(r->ops->ctx, 1);
		mac_format(&r->mapper, m);
		logm(r, 2, "topology: command state, mapper %s", m);
	}
}

static void topo_leave_command(struct lltd_responder *r)
{
	r->charge_deadline = 0;     /* 3.6.7.4 */
}

static struct lltd_session *topo_session(struct lltd_responder *r)
{
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		struct lltd_session *s = &r->sessions[i];

		if (s->state == SESS_COMPLETE && s->tos == TOS_TOPOLOGY &&
		    r->have_mapper && mac_eq(&s->mapper, &r->mapper))
			return s;
	}
	return NULL;
}

/* The current mapper is the sole topology session in Complete state (3.6.1) */
static void update_current_mapper(struct lltd_responder *r)
{
	const struct lltd_session *found = NULL;

	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		const struct lltd_session *s = &r->sessions[i];

		if (s->state == SESS_COMPLETE && s->tos == TOS_TOPOLOGY) {
			found = s;
			break;
		}
	}

	if (found && r->have_mapper && mac_eq(&found->mapper, &r->mapper))
		return;
	if (r->have_mapper) {
		r->have_mapper = 0;
		if (r->tstate != TOPO_QUIESCENT)
			topo_leave_command(r);
		topo_enter_quiescent(r);
	}
	if (found) {
		r->mapper = found->mapper;
		r->have_mapper = 1;
		topo_enter_command(r);
	}
}

static void save_last_response(struct lltd_responder *r, uint8_t fn, uint16_t seq,
			       const uint8_t *frame, size_t len)
{
	if (len > sizeof(r->last_frame))
		len = sizeof(r->last_frame);
	memcpy(r->last_frame, frame, len);
	r->last_len = len;
	r->last_fn = fn;
	r->last_seq = seq;
	r->last_valid = 1;
}

/* Returns 1 if the request repeats the last answered one (and resends the
 * saved answer) */
static int resend_if_repeated(struct lltd_responder *r, const struct lltd_frame *f)
{
	if (!r->last_valid || r->last_fn != f->function || r->last_seq != f->seq)
		return 0;
	logm(r, 3, "%s seq %u repeated, sending saved response again",
	     lltd_function_name(f->tos, f->function), f->seq);
	send_frame(r, r->last_frame, r->last_len);
	return 1;
}

/* Sequence check for acknowledged requests; on success the expected next
 * number is stored (3.6.5.1, 3.6.5.4, 3.6.5.5) */
static int accept_sequence(struct lltd_responder *r, const struct lltd_frame *f)
{
	if (r->next_seq != 0 && r->next_seq != f->seq) {
		logm(r, 3, "%s seq %u ignored, expected %u",
		     lltd_function_name(f->tos, f->function), f->seq, r->next_seq);
		return 0;
	}
	r->next_seq = seq_next(f->seq);
	return 1;
}

static void add_charge(struct lltd_responder *r, size_t frame_len)
{
	if (r->ctc_fc < CTC_MAX_FC)
		r->ctc_fc++;
	r->ctc_bc += (uint32_t)frame_len;
	if (r->ctc_bc > CTC_MAX_BC)
		r->ctc_bc = CTC_MAX_BC;
}

static void send_flat(struct lltd_responder *r, const struct lltd_frame *req,
		      uint32_t bc_before, uint8_t fc_before)
{
	uint8_t buf[ETH_MIN_FRAME];

	lltd_put_header(buf, reply_dst(req), &r->info.mac, TOS_TOPOLOGY, FN_FLAT,
			&req->real_src, &r->info.mac, req->seq);
	put_be32(buf + LLTD_HDR_LEN, bc_before);
	buf[LLTD_HDR_LEN + 4] = fc_before;
	send_frame(r, buf, LLTD_HDR_LEN + 5);
	save_last_response(r, req->function, req->seq, buf, ETH_MIN_FRAME);
	r->next_seq = seq_next(req->seq);
}

static void touch_topo_session(struct lltd_responder *r, uint64_t now)
{
	struct lltd_session *s = topo_session(r);

	if (s)
		s->active_ms = now;
}

static void rx_charge(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	uint8_t fc0 = r->ctc_fc;
	uint32_t bc0 = r->ctc_bc;
	uint16_t seq0 = r->next_seq;

	if (r->tstate == TOPO_QUIESCENT)
		return;
	touch_topo_session(r, now);
	if (r->tstate == TOPO_EMIT)
		return;

	if (f->seq != 0) {
		if (resend_if_repeated(r, f))
			return;
		if (!accept_sequence(r, f))
			return;
	}

	add_charge(r, f->len);

	if (f->seq == 0) {
		/* Unacknowledged (keep-alive) charges leave the last-sent response
		 * alone, so a lost reply can still be repeated when the mapper
		 * retries its last request after charging. */
		r->charge_deadline = now + CHARGE_TIMEOUT_MS;
		return;
	}

	/* a Flat frame costs 1 FC and 37 BC */
	if (r->ctc_fc < 1 || r->ctc_bc < CHARGE_FLAT_BC) {
		r->ctc_fc = fc0;
		r->ctc_bc = bc0;
		r->next_seq = seq0;     /* the frame is ignored completely */
		logm(r, 3, "acknowledged Charge without enough padding ignored");
		return;
	}
	r->last_valid = 0;
	r->charge_deadline = now + CHARGE_TIMEOUT_MS;
	r->ctc_fc -= 1;
	r->ctc_bc -= CHARGE_FLAT_BC;
	send_flat(r, f, bc0, fc0);
}

static int valid_emit(const struct lltd_responder *r, const struct lltd_frame *f,
		      int *count)
{
	unsigned int n, pause = 0;

	if (mac_is_broadcast(&f->eth_dst) || f->body_len < 2)
		return 0;
	n = get_be16(f->body);
	if (n < 1 || n > EMIT_MAX_DESCS || f->body_len < 2 + (size_t)n * EMITEE_DESC_LEN)
		return 0;
	for (unsigned int i = 0; i < n; i++) {
		const uint8_t *d = f->body + 2 + i * EMITEE_DESC_LEN;
		mac_t src, dst;

		memcpy(src.a, d + 2, ETH_ADDR_LEN);
		memcpy(dst.a, d + 8, ETH_ADDR_LEN);
		if (d[0] != EMITEE_TRAIN && d[0] != EMITEE_PROBE)
			return 0;
		if (!mac_eq(&src, &r->info.mac) && !mac_in_lltd_pool(&src))
			return 0;
		if (mac_is_multicast(&dst))
			return 0;
		pause += d[1];
	}
	if (pause > EMIT_MAX_PAUSE_MS)
		return 0;
	*count = (int)n;
	return 1;
}

static void rx_emit(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	uint8_t fc0 = r->ctc_fc;
	uint32_t bc0 = r->ctc_bc;
	int n, acked = f->seq != 0;
	uint32_t need_fc, need_bc;

	if (r->tstate == TOPO_QUIESCENT)
		return;
	touch_topo_session(r, now);
	if (r->tstate == TOPO_EMIT)
		return;

	if (acked && resend_if_repeated(r, f))
		return;
	if (!valid_emit(r, f, &n)) {
		logm(r, 1, "invalid Emit (seq %u) ignored", f->seq);
		return;
	}
	if (acked && r->next_seq != 0 && r->next_seq != f->seq) {
		logm(r, 3, "Emit seq %u ignored, expected %u", f->seq, r->next_seq);
		return;
	}

	add_charge(r, f->len);
	need_fc = (uint32_t)n + (acked ? 1 : 0);
	need_bc = CHARGE_FRAME_BC * need_fc;
	if (r->ctc_fc < need_fc || r->ctc_bc < need_bc) {
		if (!acked) {
			r->ctc_fc = fc0;
			r->ctc_bc = bc0;
			logm(r, 3, "unacknowledged Emit without enough charge ignored (FC %u BC %u)",
			     fc0, bc0);
			return;
		}
		logm(r, 3, "Emit seq %u: not enough charge (FC %u BC %u), sending Flat",
		     f->seq, fc0, bc0);
		/* the Flat frame consumes its own charge */
		r->ctc_fc = r->ctc_fc >= 1 ? r->ctc_fc - 1 : 0;
		r->ctc_bc = r->ctc_bc >= CHARGE_FLAT_BC ? r->ctc_bc - CHARGE_FLAT_BC : 0;
		r->charge_deadline = now + CHARGE_TIMEOUT_MS;
		send_flat(r, f, bc0, fc0);
		return;
	}

	/* accepted: all charge is consumed (1.3.5.5) */
	r->last_valid = 0;
	r->ctc_fc = 0;
	r->ctc_bc = 0;
	for (int i = 0; i < n; i++) {
		const uint8_t *d = f->body + 2 + i * EMITEE_DESC_LEN;

		r->emit_list[i].type = d[0];
		r->emit_list[i].pause = d[1];
		memcpy(r->emit_list[i].src.a, d + 2, ETH_ADDR_LEN);
		memcpy(r->emit_list[i].dst.a, d + 8, ETH_ADDR_LEN);
	}
	r->emit_count = n;
	r->emit_pos = 0;
	r->emit_seq = f->seq;
	r->emit_reply_dst = *reply_dst(f);
	topo_leave_command(r);
	r->tstate = TOPO_EMIT;
	r->emit_deadline = now + r->emit_list[0].pause;
	if (r->emit_deadline == 0)
		r->emit_deadline = 1;
}

static void emit_step(struct lltd_responder *r, uint64_t now)
{
	struct emitee *e = &r->emit_list[r->emit_pos];
	uint8_t buf[ETH_MIN_FRAME];
	int failed;

	if (e->type == EMITEE_TRAIN)
		fdb_learn(r, &e->src, now);
	lltd_put_header(buf, &e->dst, &e->src, TOS_TOPOLOGY,
			e->type == EMITEE_TRAIN ? FN_TRAIN : FN_PROBE,
			&e->dst, &r->info.mac, 0);
	failed = send_frame(r, buf, LLTD_HDR_LEN) != 0;
	r->emit_pos++;

	if (failed) {
		logm(r, 1, "sending %s failed, back to command state",
		     e->type == EMITEE_TRAIN ? "Train" : "Probe");
		topo_enter_command(r);
		return;
	}
	if (r->emit_pos < r->emit_count) {
		r->emit_deadline = now + r->emit_list[r->emit_pos].pause;
		if (r->emit_deadline == 0)
			r->emit_deadline = 1;
		return;
	}

	r->emit_deadline = 0;
	if (r->emit_seq != 0) {
		lltd_put_header(buf, &r->emit_reply_dst, &r->info.mac, TOS_TOPOLOGY, FN_ACK,
				&r->mapper, &r->info.mac, r->emit_seq);
		send_frame(r, buf, LLTD_HDR_LEN);
		save_last_response(r, FN_EMIT, r->emit_seq, buf, ETH_MIN_FRAME);
	}
	topo_enter_command(r);
}

static void rx_probe(struct lltd_responder *r, const struct lltd_frame *f)
{
	struct recvee *e;

	if (r->tstate == TOPO_QUIESCENT)
		return;
	if (r->sees_count >= r->sees_cap) {
		if (!r->error_flag)
			logm(r, 1, "sees-list full (%zu entries)", r->sees_cap);
		r->error_flag = 1;
		return;
	}
	e = &r->sees[(r->sees_head + r->sees_count) % r->sees_cap];
	e->real_src = f->real_src;
	e->eth_src = f->eth_src;
	e->eth_dst = f->eth_dst;
	r->sees_count++;
}

static void rx_query(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	uint8_t buf[ETH_MAX_FRAME];
	size_t n, i, len;
	uint16_t hdr;

	touch_topo_session(r, now);
	if (r->tstate != TOPO_COMMAND || f->seq == 0)
		return;
	if (resend_if_repeated(r, f))
		return;
	if (!accept_sequence(r, f))
		return;
	r->last_valid = 0;

	n = r->sees_count < QUERY_RESP_MAX_DESCS ? r->sees_count : QUERY_RESP_MAX_DESCS;
	lltd_put_header(buf, reply_dst(f), &r->info.mac, TOS_TOPOLOGY, FN_QUERY_RESP,
			&f->real_src, &r->info.mac, f->seq);
	hdr = (uint16_t)n;
	if (r->sees_count > n)
		hdr |= QUERY_RESP_MORE;
	if (r->error_flag)
		hdr |= QUERY_RESP_ERROR;
	put_be16(buf + LLTD_HDR_LEN, hdr);
	len = LLTD_HDR_LEN + 2;
	for (i = 0; i < n; i++) {
		const struct recvee *e = &r->sees[(r->sees_head + i) % r->sees_cap];
		uint8_t *d = buf + len;

		put_be16(d, RECVEE_TYPE_PROBE);
		memcpy(d + 2, e->real_src.a, ETH_ADDR_LEN);
		memcpy(d + 8, e->eth_src.a, ETH_ADDR_LEN);
		memcpy(d + 14, e->eth_dst.a, ETH_ADDR_LEN);
		len += RECVEE_DESC_LEN;
	}
	r->sees_head = (r->sees_head + n) % r->sees_cap;
	r->sees_count -= n;
	if (r->sees_count == 0)
		r->error_flag = 0;

	send_frame(r, buf, len);
	save_last_response(r, FN_QUERY, f->seq, buf, len < ETH_MIN_FRAME ? ETH_MIN_FRAME : len);
}

static void large_property(const struct lltd_responder *r, uint8_t type,
			   const uint8_t **data, size_t *len)
{
	*data = NULL;
	*len = 0;
	switch (type) {
	case TLV_ICON:
		*data = r->info.icon;
		*len = r->info.icon_len;
		break;
	case TLV_FRIENDLY_NAME:
		*data = r->info.friendly_name;
		*len = r->info.friendly_name_len;
		break;
	case TLV_DETAILED_ICON:
		*data = r->info.detailed_icon;
		*len = r->info.detailed_icon_len;
		break;
	default:
		break;
	}
	if (!*data)
		*len = 0;
}

static void rx_query_large_tlv(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	uint8_t buf[ETH_MAX_FRAME];
	const uint8_t *data;
	size_t total, offset, chunk = 0;
	uint16_t hdr;

	touch_topo_session(r, now);
	if (r->tstate != TOPO_COMMAND || f->seq == 0 || f->body_len < 4)
		return;
	if (resend_if_repeated(r, f))
		return;
	if (!accept_sequence(r, f))
		return;
	r->last_valid = 0;

	large_property(r, f->body[0], &data, &total);
	offset = ((size_t)f->body[1] << 16) | ((size_t)f->body[2] << 8) | f->body[3];
	if (data && offset < total) {
		chunk = total - offset;
		if (chunk > QLTLV_RESP_MAX_DATA)
			chunk = QLTLV_RESP_MAX_DATA;
	}

	lltd_put_header(buf, reply_dst(f), &r->info.mac, TOS_TOPOLOGY, FN_QUERY_LARGE_TLV_RESP,
			&f->real_src, &r->info.mac, f->seq);
	hdr = (uint16_t)chunk;
	if (data && offset + chunk < total)
		hdr |= QLTLV_RESP_MORE;
	put_be16(buf + LLTD_HDR_LEN, hdr);
	if (chunk)
		memcpy(buf + LLTD_HDR_LEN + 2, data + offset, chunk);
	send_frame(r, buf, LLTD_HDR_LEN + 2 + chunk);
	save_last_response(r, FN_QUERY_LARGE_TLV, f->seq, buf,
			   LLTD_HDR_LEN + 2 + chunk < ETH_MIN_FRAME ? ETH_MIN_FRAME : LLTD_HDR_LEN + 2 + chunk);
}

static void topo_rx(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	if (f->function == FN_PROBE) {
		rx_probe(r, f);
		return;
	}
	if (f->function != FN_CHARGE && f->function != FN_EMIT &&
	    f->function != FN_QUERY && f->function != FN_QUERY_LARGE_TLV)
		return;
	/* in promiscuous mode we also see requests for other responders */
	if (!mac_eq(&f->real_dst, &r->info.mac))
		return;
	if (!r->have_mapper || !mac_eq(&f->real_src, &r->mapper)) {
		char m[18];

		mac_format(&f->real_src, m);
		logm(r, 3, "%s from %s ignored: no topology session with this mapper",
		     lltd_function_name(f->tos, f->function), m);
		return;
	}

	switch (f->function) {
	case FN_CHARGE:
		rx_charge(r, f, now);
		break;
	case FN_EMIT:
		rx_emit(r, f, now);
		break;
	case FN_QUERY:
		rx_query(r, f, now);
		break;
	case FN_QUERY_LARGE_TLV:
		rx_query_large_tlv(r, f, now);
		break;
	}
}

/* ------------------------------------------------------------------ */
/* quick discovery / enumeration state engine (3.5)                    */
/* ------------------------------------------------------------------ */

static uint64_t div_round_up(uint64_t a, uint64_t b)
{
	return (a + b - 1) / b;
}

static void schedule_hello(struct lltd_responder *r, uint64_t now)
{
	/* uniformly distributed in [0, N * I) */
	uint64_t range_us = (uint64_t)r->n_est * RB_I_US;
	uint64_t t_us = range_us ? (((uint64_t)rnd(r) << 32) | rnd(r)) % range_us : 0;

	if (t_us < (uint64_t)RB_TB_MS * 1000)
		r->hello_deadline = now + t_us / 1000;
	else
		r->hello_deadline = 0;
	if (r->hello_deadline == 0 && t_us < (uint64_t)RB_TB_MS * 1000)
		r->hello_deadline = 1;
}

static void enter_pausing(struct lltd_responder *r, uint64_t now)
{
	r->begun = 0;
	r->n_est = RB_NMAX;
	r->r_count = 0;
	r->block_start_ms = now;
	r->block_deadline = now + RB_TB_MS;
	if (!r->inactivity_deadline)
		r->inactivity_deadline = now + INACTIVITY_CHECK_MS;
	schedule_hello(r, now);
}

static void update_enum_state(struct lltd_responder *r, uint64_t now)
{
	int any = 0, all_complete = 1;
	enum enum_state ns;

	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		if (r->sessions[i].state == SESS_FREE)
			continue;
		any = 1;
		if (r->sessions[i].state != SESS_COMPLETE)
			all_complete = 0;
	}
	ns = !any ? ENUM_QUIESCENT : all_complete ? ENUM_WAIT : ENUM_PAUSING;

	if (ns != r->estate) {
		static const char *const names[] = { "quiescent", "pausing", "wait" };

		logm(r, 3, "enumeration: %s -> %s", names[r->estate], names[ns]);
		r->estate = ns;
		switch (ns) {
		case ENUM_QUIESCENT:
			r->block_deadline = 0;
			r->hello_deadline = 0;
			r->inactivity_deadline = 0;
			break;
		case ENUM_PAUSING:
			enter_pausing(r, now);
			break;
		case ENUM_WAIT:
			r->block_deadline = 0;
			r->hello_deadline = 0;
			if (!r->inactivity_deadline)
				r->inactivity_deadline = now + INACTIVITY_CHECK_MS;
			break;
		}
	}
	update_current_mapper(r);
}

static struct lltd_session *find_session(struct lltd_responder *r, const mac_t *mapper, uint8_t tos)
{
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		struct lltd_session *s = &r->sessions[i];

		if (s->state != SESS_FREE && s->tos == tos && mac_eq(&s->mapper, mapper))
			return s;
	}
	return NULL;
}

static int other_topology_session(const struct lltd_responder *r, const struct lltd_session *self)
{
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		const struct lltd_session *s = &r->sessions[i];

		if (s != self && s->tos == TOS_TOPOLOGY &&
		    (s->state == SESS_PENDING || s->state == SESS_COMPLETE))
			return 1;
	}
	return 0;
}

static void rx_discover(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	struct lltd_session *s;
	uint16_t gen, n;
	int acked = 0, created = 0;
	enum enum_state before = r->estate;
	char m[18];

	if (f->body_len < 4)
		return;
	gen = get_be16(f->body);
	n = get_be16(f->body + 2);
	for (unsigned int i = 0; i < n && 4 + 6 * (i + 1) <= f->body_len; i++)
		if (memcmp(f->body + 4 + 6 * i, r->info.mac.a, ETH_ADDR_LEN) == 0)
			acked = 1;

	s = find_session(r, &f->real_src, f->tos);
	if (!s || s->xid != f->seq) {
		if (!s) {
			for (int i = 0; i < LLTD_MAX_SESSIONS && !s; i++)
				if (r->sessions[i].state == SESS_FREE)
					s = &r->sessions[i];
			if (!s)
				return;     /* no memory: ignore silently */
		}
		created = 1;
		s->mapper = f->real_src;
		s->tos = f->tos;
		s->xid = f->seq;
		s->state = acked ? SESS_COMPLETE : SESS_PENDING;
		s->txc = HELLO_TXC;
		if (f->tos == TOS_TOPOLOGY && other_topology_session(r, s))
			s->state = SESS_TEMPORARY;
		mac_format(&f->real_src, m);
		logm(r, 2, "new %s session with %s (xid %u)%s",
		     f->tos == TOS_TOPOLOGY ? "topology" : "quick discovery", m, f->seq,
		     s->state == SESS_TEMPORARY ? ", temporary: another mapper is active" : "");
	} else if (acked && s->state == SESS_PENDING) {
		s->state = SESS_COMPLETE;
	}
	s->active_ms = now;
	s->apparent = f->eth_src;
	/* generation 0 means "none yet": keep a negotiated value */
	if (s->state == SESS_COMPLETE && f->tos == TOS_TOPOLOGY && gen != 0)
		r->generation = gen;

	r->r_count++;
	update_enum_state(r, now);
	if (created && before == ENUM_PAUSING && r->estate == ENUM_PAUSING)
		r->begun = 1;
}

static void rx_reset(struct lltd_responder *r, const struct lltd_frame *f, uint64_t now)
{
	struct lltd_session *s = find_session(r, &f->real_src, f->tos);
	int current;
	char m[18];

	if (!s)
		return;
	current = f->tos == TOS_TOPOLOGY && r->have_mapper && mac_eq(&s->mapper, &r->mapper);
	mac_format(&f->real_src, m);
	logm(r, 2, "reset of %s session by %s", f->tos == TOS_TOPOLOGY ? "topology" : "quick discovery", m);
	s->state = SESS_FREE;
	if (current) {
		for (int i = 0; i < LLTD_MAX_SESSIONS; i++)
			if (r->sessions[i].state == SESS_TEMPORARY)
				r->sessions[i].state = SESS_FREE;
	}
	update_enum_state(r, now);
}

static void put_tlv(uint8_t *buf, size_t *pos, uint8_t type, const void *val, size_t len)
{
	buf[(*pos)++] = type;
	buf[(*pos)++] = (uint8_t)len;
	if (len)
		memcpy(buf + *pos, val, len);
	*pos += len;
}

size_t lltd_build_hello(struct lltd_responder *r, uint8_t *buf, uint8_t tos)
{
	const struct lltd_hostinfo *in = &r->info;
	const struct lltd_session *ts = NULL;
	uint8_t v[16];
	size_t pos;

	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		const struct lltd_session *s = &r->sessions[i];

		if (s->tos == TOS_TOPOLOGY && (s->state == SESS_PENDING || s->state == SESS_COMPLETE))
			ts = s;
	}

	lltd_put_header(buf, &MAC_BROADCAST, &in->mac, tos, FN_HELLO,
			&MAC_BROADCAST, &in->mac, 0);
	pos = LLTD_HDR_LEN;
	put_be16(buf + pos, r->generation);
	pos += 2;
	if (ts) {
		memcpy(buf + pos, ts->mapper.a, ETH_ADDR_LEN);
		memcpy(buf + pos + 6, ts->apparent.a, ETH_ADDR_LEN);
	} else {
		memset(buf + pos, 0, 12);
	}
	pos += 12;

	put_tlv(buf, &pos, TLV_HOST_ID, in->host_id.a, ETH_ADDR_LEN);
	put_be16(v, in->characteristics);
	put_tlv(buf, &pos, TLV_CHARACTERISTICS, v, 2);
	put_be32(v, in->medium);
	put_tlv(buf, &pos, TLV_PHYSICAL_MEDIUM, v, 4);
	if (in->wireless) {
		put_tlv(buf, &pos, TLV_WIRELESS_MODE, &in->wireless_mode, 1);
		put_tlv(buf, &pos, TLV_BSSID, in->bssid.a, ETH_ADDR_LEN);
		put_tlv(buf, &pos, TLV_SSID, in->ssid, in->ssid_len);
	}
	if (in->has_ipv4)
		put_tlv(buf, &pos, TLV_IPV4, in->ipv4, 4);
	if (in->has_ipv6)
		put_tlv(buf, &pos, TLV_IPV6, in->ipv6, 16);
	if (in->link_speed) {
		put_be32(v, in->link_speed);
		put_tlv(buf, &pos, TLV_LINK_SPEED, v, 4);
	}
	put_tlv(buf, &pos, TLV_MACHINE_NAME, in->machine_name, in->machine_name_len);
	/* QoS characteristics: E = no layer 2 forwarding by this host */
	put_be32(v, in->bridge ? 0 : 0x80000000u);
	put_tlv(buf, &pos, TLV_QOS_CHAR, v, 4);
	if (in->icon)
		put_tlv(buf, &pos, TLV_ICON, NULL, 0);
	if (in->friendly_name)
		put_tlv(buf, &pos, TLV_FRIENDLY_NAME, NULL, 0);
	if (in->detailed_icon)
		put_tlv(buf, &pos, TLV_DETAILED_ICON, NULL, 0);
	put_be16(v, (uint16_t)r->sees_cap);
	put_tlv(buf, &pos, TLV_SEES_LIST_WS, v, 2);
	buf[pos++] = TLV_END;
	return pos;
}

static void send_hello(struct lltd_responder *r)
{
	uint8_t buf[ETH_MAX_FRAME];
	uint8_t tos = TOS_QUICK;
	size_t len;

	/* one Hello per timer; answer a pending topology session first */
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		const struct lltd_session *s = &r->sessions[i];

		if (s->tos == TOS_TOPOLOGY && (s->state == SESS_PENDING || s->state == SESS_TEMPORARY))
			tos = TOS_TOPOLOGY;
	}
	if (r->ops->refresh)
		r->ops->refresh(r->ops->ctx, &r->info);
	len = lltd_build_hello(r, buf, tos);
	send_frame(r, buf, len);
}

static void hello_timer(struct lltd_responder *r, uint64_t now)
{
	r->hello_deadline = 0;
	send_hello(r);
	r->r_count++;       /* our own Hello counts as well */
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		struct lltd_session *s = &r->sessions[i];

		if (s->state == SESS_PENDING) {
			if (--s->txc <= 0)
				s->state = SESS_COMPLETE;
		} else if (s->state == SESS_TEMPORARY) {
			s->state = SESS_FREE;
		}
	}
	update_enum_state(r, now);
}

static void block_timer(struct lltd_responder *r, uint64_t now)
{
	uint64_t ta = now > r->block_start_ms ? now - r->block_start_ms : 1;
	uint64_t nold = r->n_est, value, bound, nnew;

	/* RepeatBAND (3.5.6.2), I in microseconds, 64 bit to avoid overflow */
	value = div_round_up((uint64_t)r->r_count * nold * RB_I_US, ta * 1000);
	bound = div_round_up(nold * RB_GAMMA, RB_BETA * RB_ALPHA);
	nnew = value < 100 * nold ? value : 100 * nold;
	if (nnew < bound)
		nnew = bound;
	if (r->begun) {
		nnew = nnew * 2 > RB_NMAX ? RB_NMAX : nnew * 2;
		r->begun = 0;
	}
	/* a flood of Hello/Discover frames must not wrap the estimate */
	if (nnew > 100 * (uint64_t)RB_NMAX)
		nnew = 100 * (uint64_t)RB_NMAX;
	if (nnew < 1)
		nnew = 1;
	r->n_est = (uint32_t)nnew;
	r->r_count = 0;
	r->block_start_ms = now;
	r->block_deadline = now + RB_TB_MS;
	if (!r->hello_deadline)
		schedule_hello(r, now);
}

static void inactivity_timer(struct lltd_responder *r, uint64_t now)
{
	int changed = 0;
	char m[18];

	for (int i = 0; i < LLTD_MAX_SESSIONS; i++) {
		struct lltd_session *s = &r->sessions[i];
		uint64_t limit = SESSION_TIMEOUT_MS;

		if (s->state == SESS_FREE)
			continue;
		if (s->tos == TOS_TOPOLOGY && s->state != SESS_TEMPORARY && r->tstate != TOPO_QUIESCENT)
			limit = SESSION_TIMEOUT_CMD_MS;
		if (now - s->active_ms >= limit) {
			mac_format(&s->mapper, m);
			logm(r, 2, "%s session with %s timed out",
			     s->tos == TOS_TOPOLOGY ? "topology" : "quick discovery", m);
			s->state = SESS_FREE;
			changed = 1;
		}
	}
	r->inactivity_deadline = r->estate != ENUM_QUIESCENT ? now + INACTIVITY_CHECK_MS : 0;
	if (changed)
		update_enum_state(r, now);
}

/* ------------------------------------------------------------------ */
/* public interface                                                     */
/* ------------------------------------------------------------------ */

int lltd_init(struct lltd_responder *r, const struct lltd_ops *ops,
	      const struct lltd_hostinfo *info)
{
	memset(r, 0, sizeof(*r));
	r->ops = ops;
	r->info = *info;
	r->fdb_hold_ms = 5000;
	r->log_level = 3;
	r->sees_cap = LLTD_SEES_LIST_MAX;
	r->sees = calloc(r->sees_cap, sizeof(*r->sees));
	if (!r->sees)
		return -1;
	r->estate = ENUM_QUIESCENT;
	r->tstate = TOPO_QUIESCENT;
	return 0;
}

void lltd_free(struct lltd_responder *r)
{
	topo_enter_quiescent(r);
	free(r->sees);
	r->sees = NULL;
}

void lltd_set_info(struct lltd_responder *r, const struct lltd_hostinfo *info)
{
	r->info = *info;
}

void lltd_rx(struct lltd_responder *r, const uint8_t *buf, size_t len, uint64_t now)
{
	struct lltd_frame f;

	if (lltd_parse(buf, len, &f) != 0)
		return;
	r->rx_frames++;
	log_frame(r, "rx", buf, len);

	if (mac_eq(&f.real_src, &r->info.mac))
		return;     /* our own frame */
	if (f.tos != TOS_TOPOLOGY && f.tos != TOS_QUICK)
		return;     /* QoS diagnostics are not supported */

	switch (f.function) {
	case FN_DISCOVER:
		if (addressed_to_us(r, &f))
			rx_discover(r, &f, now);
		return;
	case FN_HELLO:
		if (addressed_to_us(r, &f))
			r->r_count++;
		return;
	case FN_RESET:
		if (addressed_to_us(r, &f))
			rx_reset(r, &f, now);
		return;
	default:
		break;
	}
	if (f.tos == TOS_TOPOLOGY)
		topo_rx(r, &f, now);
}

void lltd_tick(struct lltd_responder *r, uint64_t now)
{
	if (r->emit_deadline && r->emit_deadline <= now && r->tstate == TOPO_EMIT)
		emit_step(r, now);
	if (r->charge_deadline && r->charge_deadline <= now) {
		r->charge_deadline = 0;
		r->ctc_fc = 0;
		r->ctc_bc = 0;
	}
	if (r->hello_deadline && r->hello_deadline <= now)
		hello_timer(r, now);
	if (r->block_deadline && r->block_deadline <= now)
		block_timer(r, now);
	if (r->inactivity_deadline && r->inactivity_deadline <= now)
		inactivity_timer(r, now);
	if (r->fdb_count)
		fdb_expire(r, now, 0);
}

uint64_t lltd_next_deadline(const struct lltd_responder *r)
{
	uint64_t d[6] = { r->emit_deadline, r->charge_deadline, r->hello_deadline,
			  r->block_deadline, r->inactivity_deadline, 0 };
	uint64_t best = 0;

	for (int i = 0; i < r->fdb_count; i++)
		if (!d[5] || r->fdb[i].expires < d[5])
			d[5] = r->fdb[i].expires;
	for (int i = 0; i < 6; i++)
		if (d[i] && (!best || d[i] < best))
			best = d[i];
	return best;
}

void lltd_media_disconnect(struct lltd_responder *r)
{
	for (int i = 0; i < LLTD_MAX_SESSIONS; i++)
		r->sessions[i].state = SESS_FREE;
	r->estate = ENUM_QUIESCENT;
	r->block_deadline = r->hello_deadline = r->inactivity_deadline = 0;
	r->have_mapper = 0;
	topo_enter_quiescent(r);
	logm(r, 2, "link down, all sessions cleared");
}
