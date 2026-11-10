/*
 * lltd - responder core: quick discovery ([MS-LLTD] 3.5) and topology
 * discovery ([MS-LLTD] 3.6) state engines for one network interface.
 *
 * The core is free of OS calls: frames come in through lltd_rx(), time is
 * passed in explicitly, and everything it needs from the system goes
 * through struct lltd_ops. This keeps it unit-testable.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef LLTD_RESPONDER_H
#define LLTD_RESPONDER_H

#include <stdint.h>
#include <stddef.h>

#include "lltd_proto.h"

#define LLTD_MAX_SESSIONS       32
#define LLTD_SEES_LIST_MAX      10000
#define LLTD_FDB_MAX            64
/* observation self-check: rounds with own Train frames before deciding */
#define LLTD_OBSERVE_MIN_ROUNDS 8

/* RepeatBAND constants (3.5.1) */
#define RB_ALPHA                45
#define RB_BETA                 2
#define RB_GAMMA                10
#define RB_NMAX                 10000
#define RB_I_US                 6670    /* ideal Hello spacing 6.67 ms */
#define RB_TB_MS                300     /* block time */
#define HELLO_TXC               4       /* Hello retransmissions per session */

#define SESSION_TIMEOUT_MS      30000
#define SESSION_TIMEOUT_CMD_MS  60000   /* topology session while in Command */
#define CHARGE_TIMEOUT_MS       1000
#define INACTIVITY_CHECK_MS     1000

enum enum_state { ENUM_QUIESCENT, ENUM_PAUSING, ENUM_WAIT };
enum topo_state { TOPO_QUIESCENT, TOPO_COMMAND, TOPO_EMIT };

/* Observation of probes to test addresses (the "c" role):
 * auto: execute Train emits, warn if no probe of another responder ever
 *       reaches a trained address (the interface cannot observe);
 * yes:  execute Train emits, no check;
 * no:   refuse Emits with Train frames. */
enum lltd_observe { LLTD_OBSERVE_AUTO, LLTD_OBSERVE_YES, LLTD_OBSERVE_NO };
enum sess_state { SESS_FREE, SESS_PENDING, SESS_COMPLETE, SESS_TEMPORARY };

/* Information about this host/interface used in Hello frames */
struct lltd_hostinfo {
	mac_t mac;                      /* interface MAC (real address) */
	mac_t host_id;                  /* Host ID attribute */
	uint8_t machine_name[32];       /* UCS-2LE, 2..32 bytes */
	size_t machine_name_len;
	uint16_t characteristics;
	uint32_t medium;                /* IANA ifType */
	int has_ipv4;
	uint8_t ipv4[4];
	int has_ipv6;
	uint8_t ipv6[16];
	uint32_t link_speed;            /* units of 100 bit/s, 0 = unknown */
	int bridge;                     /* host forwards layer 2 (bridge/AP) */
	/* 802.11 station interface */
	int wireless;
	uint8_t wireless_mode;          /* 0 ad hoc, 1 infrastructure */
	mac_t bssid;
	uint8_t ssid[32];
	size_t ssid_len;
	/* large data properties (QueryLargeTlv), NULL = not offered */
	const uint8_t *icon;
	size_t icon_len;
	const uint8_t *friendly_name;   /* UCS-2LE */
	size_t friendly_name_len;
	const uint8_t *detailed_icon;
	size_t detailed_icon_len;
};

struct lltd_ops {
	void *ctx;
	/* send a complete Ethernet frame (without FCS); returns 0 on success */
	int (*send)(void *ctx, const uint8_t *frame, size_t len);
	/* promiscuous mode on/off (Command/Emit state) */
	void (*set_promisc)(void *ctx, int on);
	/* make the local bridge deliver frames for this address to us
	 * (optional, may be NULL) */
	void (*fdb_add)(void *ctx, const mac_t *mac);
	void (*fdb_del)(void *ctx, const mac_t *mac);
	/* 32 bit random number */
	uint32_t (*random)(void *ctx);
	/* refresh dynamic host information (addresses, speed) before a Hello */
	void (*refresh)(void *ctx, struct lltd_hostinfo *info);
	/* log a message (level: 0 error .. 3 debug, 4 frame dump) */
	void (*log)(void *ctx, int level, const char *msg);
};

struct lltd_session {
	enum sess_state state;
	mac_t mapper;           /* Real_Source_Address of the Discover */
	mac_t apparent;         /* Ethernet source of the Discover */
	uint8_t tos;
	uint16_t xid;
	uint64_t active_ms;
	int txc;
};

struct recvee {
	mac_t real_src, eth_src, eth_dst;
};

struct emitee {
	uint8_t type, pause;
	mac_t src, dst;
};

struct lltd_responder {
	const struct lltd_ops *ops;
	struct lltd_hostinfo info;
	int fdb_hold_ms;        /* how long a Train source stays in the bridge FDB */
	int log_level;          /* highest level passed to ops->log (4 = frames) */

	/* quick discovery (3.5) */
	enum enum_state estate;
	struct lltd_session sessions[LLTD_MAX_SESSIONS];
	uint16_t generation;
	uint32_t n_est;         /* N */
	uint32_t r_count;       /* r */
	int begun;
	uint64_t block_start_ms;
	uint64_t block_deadline;        /* 0 = off */
	uint64_t hello_deadline;        /* 0 = off */
	uint64_t inactivity_deadline;   /* 0 = off */

	/* topology discovery (3.6) */
	enum topo_state tstate;
	mac_t mapper;                   /* current mapper (valid if have_mapper) */
	int have_mapper;
	uint16_t next_seq;
	uint8_t ctc_fc;
	uint32_t ctc_bc;
	uint64_t charge_deadline;
	struct recvee *sees;            /* ring buffer */
	size_t sees_cap, sees_head, sees_count;
	int error_flag;
	/* last sent response */
	int last_valid;
	uint8_t last_fn;
	uint16_t last_seq;
	uint8_t last_frame[ETH_MAX_FRAME];
	size_t last_len;
	/* Emit processing */
	struct emitee emit_list[EMIT_MAX_DESCS];
	int emit_count, emit_pos;
	uint16_t emit_seq;
	mac_t emit_reply_dst;           /* Ethernet destination for the Ack */
	uint64_t emit_deadline;
	/* bridge FDB entries for Train sources */
	struct { mac_t mac; uint64_t expires; } fdb[LLTD_FDB_MAX];
	int fdb_count;

	/* observation self-check (see enum lltd_observe) */
	enum lltd_observe observe_mode;
	int observe_deaf;               /* auto: warned in this session */
	unsigned int obs_rounds;        /* accepted Emits with Train frames */
	unsigned int obs_hits;          /* probes from other responders to trained addresses */
	int obs_refused_logged;

	/* statistics */
	unsigned long rx_frames, tx_frames, tx_errors;
};

int lltd_init(struct lltd_responder *r, const struct lltd_ops *ops,
	      const struct lltd_hostinfo *info);
void lltd_free(struct lltd_responder *r);

/* a received Ethernet frame (EtherType 0x88D9) */
void lltd_rx(struct lltd_responder *r, const uint8_t *buf, size_t len, uint64_t now_ms);

/* run expired timers */
void lltd_tick(struct lltd_responder *r, uint64_t now_ms);

/* absolute time of the next timer, or 0 if none is running */
uint64_t lltd_next_deadline(const struct lltd_responder *r);

/* link lost: back to quiescent (3.5.7.1, 3.6.7.1) */
void lltd_media_disconnect(struct lltd_responder *r);

/* update host information (e.g. new name) */
void lltd_set_info(struct lltd_responder *r, const struct lltd_hostinfo *info);

/* builds a Hello frame into buf, returns its length (exported for tests) */
size_t lltd_build_hello(struct lltd_responder *r, uint8_t *buf, uint8_t tos);

#endif
