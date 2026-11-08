/*
 * lltd - Link Layer Topology Discovery (LLTD) responder for Linux/OpenWrt
 *
 * Makes this host appear in the Windows network map and in LLTD mappers.
 * Implements [MS-LLTD] quick discovery and topology discovery tests.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "responder.h"
#include "sysinfo.h"

#ifndef LLTD_VERSION_STRING
#define LLTD_VERSION_STRING "1.0"
#endif

#define MAX_IFACES 8

extern const uint8_t lltd_default_icon[];
extern const size_t lltd_default_icon_len;

struct iface {
	char name[IFNAMSIZ];
	int ifindex;
	int fd;
	int promisc;
	int bridge;
	int vlan_filtering;
	uint16_t pvid;
	int carrier;
	struct lltd_ops ops;
	struct lltd_responder resp;
};

static struct {
	struct iface ifs[MAX_IFACES];
	int n_ifs;
	int verbose;
	int use_syslog;
	int foreground;
	int use_fdb;
	int fdb_hold_ms;
	int speed_mbit;
	int web;
	int nat_private;
	const char *hostname;
	const char *friendly_name;
	const char *icon_path;
	const char *detailed_icon_path;
	int no_icon;
	const char *pidfile;
	int nl_fd;
	uint32_t nl_seq;
	uint8_t *icon;
	size_t icon_len;
	uint8_t *detailed_icon;
	size_t detailed_icon_len;
	uint8_t friendly_ucs2[64];
	size_t friendly_len;
} g;   /* zero initialised (bss); defaults are set in main() */

static volatile sig_atomic_t stop_requested, reload_requested;

/* ------------------------------------------------------------------ */
/* logging                                                             */
/* ------------------------------------------------------------------ */

static void vlog(int level, const char *ifname, const char *fmt, va_list ap)
{
	static const int prio[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG, LOG_DEBUG };
	char msg[1200];

	if (level > g.verbose && level > 0)
		return;
	vsnprintf(msg, sizeof(msg), fmt, ap);
	if (g.use_syslog) {
		if (ifname)
			syslog(prio[level > 4 ? 4 : level], "%s: %s", ifname, msg);
		else
			syslog(prio[level > 4 ? 4 : level], "%s", msg);
	} else {
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		fprintf(stderr, "%02ld:%02ld:%02ld.%03ld %s%s%s\n",
			(long)(ts.tv_sec / 3600 % 24), (long)(ts.tv_sec / 60 % 60), (long)(ts.tv_sec % 60),
			ts.tv_nsec / 1000000, ifname ? ifname : "", ifname ? ": " : "", msg);
	}
}

static void logx(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void logx(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(level, NULL, fmt, ap);
	va_end(ap);
}

static void core_log(void *ctx, int level, const char *msg)
{
	const struct iface *ifc = ctx;

	logx(level, "%s: %s", ifc->name, msg);
}

/* ------------------------------------------------------------------ */
/* time                                                                */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	/* +1: the responder core uses 0 for "timer not running" */
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u + 1;
}

/* ------------------------------------------------------------------ */
/* bridge FDB via rtnetlink                                            */
/* ------------------------------------------------------------------ */

/* "bridge fdb replace MAC dev BRIDGE self local [vlan PVID]": frames for
 * MAC are then delivered to the host instead of being flooded, and DSA
 * switches install the address on their CPU port. */
static int fdb_request(const struct iface *ifc, int type, const mac_t *mac, uint16_t vid)
{
	struct {
		struct nlmsghdr nh;
		struct ndmsg ndm;
		char attrs[64];
	} req;
	struct rtattr *rta;
	char ack[512];
	struct nlmsghdr *h;
	ssize_t n;

	if (g.nl_fd < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.nh.nlmsg_type = (uint16_t)type;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (type == RTM_NEWNEIGH)
		req.nh.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	req.nh.nlmsg_seq = ++g.nl_seq;
	req.ndm.ndm_family = AF_BRIDGE;
	req.ndm.ndm_ifindex = ifc->ifindex;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_flags = NTF_SELF;

	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = NDA_LLADDR;
	rta->rta_len = RTA_LENGTH(ETH_ADDR_LEN);
	memcpy(RTA_DATA(rta), mac->a, ETH_ADDR_LEN);
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
	if (vid) {
		rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
		rta->rta_type = NDA_VLAN;
		rta->rta_len = RTA_LENGTH(sizeof(uint16_t));
		memcpy(RTA_DATA(rta), &vid, sizeof(vid));
		req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
	}

	if (send(g.nl_fd, &req, req.nh.nlmsg_len, 0) < 0)
		return -1;
	n = recv(g.nl_fd, ack, sizeof(ack), 0);
	if (n < 0)
		return -1;
	for (h = (struct nlmsghdr *)ack; NLMSG_OK(h, (unsigned int)n); h = NLMSG_NEXT(h, n)) {
		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = NLMSG_DATA(h);

			if (e->error) {
				errno = -e->error;
				return -1;
			}
			return 0;
		}
	}
	return 0;
}

static void fdb_add(void *ctx, const mac_t *mac)
{
	struct iface *ifc = ctx;
	char m[18];

	if (!ifc->bridge || !g.use_fdb)
		return;
	mac_format(mac, m);
	if (fdb_request(ifc, RTM_NEWNEIGH, mac, ifc->vlan_filtering ? ifc->pvid : 0) != 0)
		logx(1, "%s: bridge fdb add %s failed: %s", ifc->name, m, strerror(errno));
	else
		logx(3, "%s: bridge fdb add %s (local)", ifc->name, m);
}

static void fdb_del(void *ctx, const mac_t *mac)
{
	struct iface *ifc = ctx;
	char m[18];

	if (!ifc->bridge || !g.use_fdb)
		return;
	mac_format(mac, m);
	if (fdb_request(ifc, RTM_DELNEIGH, mac, ifc->vlan_filtering ? ifc->pvid : 0) != 0 && errno != ENOENT)
		logx(3, "%s: bridge fdb del %s failed: %s", ifc->name, m, strerror(errno));
	else
		logx(3, "%s: bridge fdb del %s", ifc->name, m);
}

/* ------------------------------------------------------------------ */
/* packet socket                                                       */
/* ------------------------------------------------------------------ */

static int open_socket(struct iface *ifc)
{
	struct sockaddr_ll sll;
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(LLTD_ETHERTYPE));

	if (fd < 0) {
		logx(0, "%s: packet socket: %s (root or CAP_NET_RAW required)", ifc->name, strerror(errno));
		return -1;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(LLTD_ETHERTYPE);
	sll.sll_ifindex = ifc->ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
		logx(0, "%s: bind: %s", ifc->name, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int sock_send(void *ctx, const uint8_t *frame, size_t len)
{
	struct iface *ifc = ctx;
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(LLTD_ETHERTYPE);
	sll.sll_ifindex = ifc->ifindex;
	sll.sll_halen = ETH_ADDR_LEN;
	memcpy(sll.sll_addr, frame, ETH_ADDR_LEN);
	if (sendto(ifc->fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) != (ssize_t)len) {
		logx(1, "%s: send: %s", ifc->name, strerror(errno));
		return -1;
	}
	return 0;
}

static void set_promisc(void *ctx, int on)
{
	struct iface *ifc = ctx;
	struct packet_mreq mr;

	if (ifc->promisc == on)
		return;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifc->ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(ifc->fd, SOL_PACKET, on ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mr, sizeof(mr)) != 0) {
		logx(1, "%s: promiscuous mode %s: %s", ifc->name, on ? "on" : "off", strerror(errno));
		return;
	}
	ifc->promisc = on;
	logx(3, "%s: promiscuous mode %s", ifc->name, on ? "on" : "off");
}

static uint32_t random32(void *ctx)
{
	(void)ctx;
	return ((uint32_t)random() << 16) ^ (uint32_t)random();
}

static void refresh(void *ctx, struct lltd_hostinfo *info)
{
	struct iface *ifc = ctx;

	sys_refresh_info(ifc->name, info, g.speed_mbit);
}

/* ------------------------------------------------------------------ */
/* setup                                                               */
/* ------------------------------------------------------------------ */

static void build_info(struct lltd_hostinfo *info, const struct iface *ifc, const mac_t *host_id)
{
	char host[256];

	memset(info, 0, sizeof(*info));
	sys_if_mac(ifc->name, &info->mac);
	info->host_id = *host_id;
	if (g.hostname)
		snprintf(host, sizeof(host), "%s", g.hostname);
	else
		sys_short_hostname(host, sizeof(host));
	info->machine_name_len = utf8_to_ucs2le(host, info->machine_name, 16);
	if (info->machine_name_len == 0)
		info->machine_name_len = utf8_to_ucs2le("lltd", info->machine_name, 16);
	if (g.web)
		info->characteristics |= CHAR_HAS_WEB_PAGE;
	if (g.nat_private)
		info->characteristics |= CHAR_NAT_PRIVATE;
	info->bridge = ifc->bridge;
	if (g.icon) {
		info->icon = g.icon;
		info->icon_len = g.icon_len;
	}
	if (g.detailed_icon) {
		info->detailed_icon = g.detailed_icon;
		info->detailed_icon_len = g.detailed_icon_len;
	}
	if (g.friendly_len) {
		info->friendly_name = g.friendly_ucs2;
		info->friendly_name_len = g.friendly_len;
	}
	sys_refresh_info(ifc->name, info, g.speed_mbit);
}

static mac_t lowest_mac(void)
{
	mac_t best;

	memset(best.a, 0xff, sizeof(best.a));
	for (int i = 0; i < g.n_ifs; i++) {
		mac_t m;

		if (sys_if_mac(g.ifs[i].name, &m) == 0 && !mac_is_zero(&m) &&
		    mac_to_u64(&m) < mac_to_u64(&best))
			best = m;
	}
	return best;
}

static int setup_iface(struct iface *ifc, const mac_t *host_id)
{
	struct lltd_hostinfo info;
	char m[18];

	if (strcmp(ifc->name, "auto") == 0 && sys_default_route_if(ifc->name, sizeof(ifc->name)) != 0) {
		logx(0, "auto: no default route, give the interface with -i");
		return -1;
	}
	ifc->ifindex = (int)if_nametoindex(ifc->name);
	if (!ifc->ifindex) {
		logx(0, "%s: no such interface", ifc->name);
		return -1;
	}
	ifc->bridge = sys_if_is_bridge(ifc->name);
	ifc->vlan_filtering = ifc->bridge && sys_bridge_vlan(ifc->name, &ifc->pvid);
	ifc->carrier = sys_if_carrier(ifc->name);
	ifc->fd = open_socket(ifc);
	if (ifc->fd < 0)
		return -1;

	ifc->ops.ctx = ifc;
	ifc->ops.send = sock_send;
	ifc->ops.set_promisc = set_promisc;
	ifc->ops.fdb_add = fdb_add;
	ifc->ops.fdb_del = fdb_del;
	ifc->ops.random = random32;
	ifc->ops.refresh = refresh;
	ifc->ops.log = core_log;

	build_info(&info, ifc, host_id);
	if (lltd_init(&ifc->resp, &ifc->ops, &info) != 0) {
		logx(0, "%s: out of memory", ifc->name);
		return -1;
	}
	ifc->resp.fdb_hold_ms = g.fdb_hold_ms;
	mac_format(&info.mac, m);
	logx(2, "%s: responding as %s%s%s", ifc->name, m,
	     ifc->bridge ? " (bridge" : "",
	     ifc->bridge ? (g.use_fdb ? ", fdb learning on)" : ", fdb learning off)") : "");
	return 0;
}

static void reload_info(void)
{
	mac_t host_id = lowest_mac();

	for (int i = 0; i < g.n_ifs; i++) {
		struct lltd_hostinfo info;

		build_info(&info, &g.ifs[i], &host_id);
		lltd_set_info(&g.ifs[i].resp, &info);
	}
	logx(2, "host information reloaded");
}

static void load_files(void)
{
	if (g.icon_path) {
		g.icon = sys_read_file(g.icon_path, 32768, &g.icon_len);
		if (!g.icon)
			logx(1, "icon %s not used: %s (max. 32768 bytes)", g.icon_path, strerror(errno));
	} else if (!g.no_icon) {
		g.icon = (uint8_t *)lltd_default_icon;
		g.icon_len = lltd_default_icon_len;
	}
	if (g.detailed_icon_path) {
		g.detailed_icon = sys_read_file(g.detailed_icon_path, 262144, &g.detailed_icon_len);
		if (!g.detailed_icon)
			logx(1, "detailed icon %s not used: %s (max. 262144 bytes)",
			     g.detailed_icon_path, strerror(errno));
	}
	if (g.friendly_name)
		g.friendly_len = utf8_to_ucs2le(g.friendly_name, g.friendly_ucs2, 32);
}

static void on_signal(int sig)
{
	if (sig == SIGHUP)
		reload_requested = 1;
	else
		stop_requested = 1;
}

static void usage(FILE *out)
{
	fprintf(out,
		"Usage: lltd [options] -i <interface> [-i <interface> ...]\n"
		"Link Layer Topology Discovery (LLTD) responder, version " LLTD_VERSION_STRING "\n"
		"\n"
		"  -i, --interface IF       answer on this interface (repeatable, max. %d);\n"
		"                           \"auto\" = interface of the default route\n"
		"  -H, --hostname NAME      machine name to report (default: host name)\n"
		"  -F, --friendly-name TXT  friendly name offered to the mapper\n"
		"  -I, --icon FILE          icon image (ICO/PNG/GIF/JPEG, max. 32 KiB)\n"
		"      --detailed-icon FILE high resolution icon (max. 256 KiB)\n"
		"      --no-icon            do not offer the built-in icon\n"
		"  -w, --web                announce a management web page (http://<ip>/)\n"
		"      --nat-private        interface is the private side of a NAT router\n"
		"      --speed MBIT         report this link speed instead of the detected one\n"
		"      --no-fdb             do not add Train sources to the bridge FDB\n"
		"      --fdb-hold MS        how long a Train source stays in the FDB (default 5000)\n"
		"  -f, --foreground         do not daemonize, log to stderr\n"
		"  -s, --syslog             log to syslog (default when daemonized)\n"
		"  -p, --pidfile FILE       write the process ID to FILE\n"
		"  -v, --verbose            more output: -v info, -vv debug, -vvv frame dump\n"
		"  -V, --version            show version and exit\n"
		"  -h, --help               show this help and exit\n",
		MAX_IFACES);
}

int main(int argc, char **argv)
{
	enum { OPT_DETAILED = 256, OPT_NO_ICON, OPT_NAT, OPT_SPEED, OPT_NO_FDB, OPT_FDB_HOLD };
	static const struct option opts[] = {
		{ "interface", required_argument, NULL, 'i' },
		{ "hostname", required_argument, NULL, 'H' },
		{ "friendly-name", required_argument, NULL, 'F' },
		{ "icon", required_argument, NULL, 'I' },
		{ "detailed-icon", required_argument, NULL, OPT_DETAILED },
		{ "no-icon", no_argument, NULL, OPT_NO_ICON },
		{ "web", no_argument, NULL, 'w' },
		{ "nat-private", no_argument, NULL, OPT_NAT },
		{ "speed", required_argument, NULL, OPT_SPEED },
		{ "no-fdb", no_argument, NULL, OPT_NO_FDB },
		{ "fdb-hold", required_argument, NULL, OPT_FDB_HOLD },
		{ "foreground", no_argument, NULL, 'f' },
		{ "syslog", no_argument, NULL, 's' },
		{ "pidfile", required_argument, NULL, 'p' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct pollfd pfd[MAX_IFACES];
	mac_t host_id;
	int c, force_syslog = 0;
	uint64_t next_carrier = 0;

	g.use_fdb = 1;
	g.fdb_hold_ms = 5000;
	g.nl_fd = -1;

	while ((c = getopt_long(argc, argv, "i:H:F:I:wfsp:vVh", opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			if (g.n_ifs == MAX_IFACES) {
				fprintf(stderr, "lltd: too many interfaces\n");
				return 2;
			}
			snprintf(g.ifs[g.n_ifs++].name, IFNAMSIZ, "%s", optarg);
			break;
		case 'H': g.hostname = optarg; break;
		case 'F': g.friendly_name = optarg; break;
		case 'I': g.icon_path = optarg; break;
		case OPT_DETAILED: g.detailed_icon_path = optarg; break;
		case OPT_NO_ICON: g.no_icon = 1; break;
		case 'w': g.web = 1; break;
		case OPT_NAT: g.nat_private = 1; break;
		case OPT_SPEED: g.speed_mbit = atoi(optarg); break;
		case OPT_NO_FDB: g.use_fdb = 0; break;
		case OPT_FDB_HOLD: g.fdb_hold_ms = atoi(optarg); break;
		case 'f': g.foreground = 1; break;
		case 's': force_syslog = 1; break;
		case 'p': g.pidfile = optarg; break;
		case 'v': g.verbose++; break;
		case 'V': printf("lltd " LLTD_VERSION_STRING "\n"); return 0;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}
	if (g.n_ifs == 0 || optind < argc) {
		usage(stderr);
		return 2;
	}
	if (g.verbose < 1)
		g.verbose = 1;      /* errors and warnings */
	else
		g.verbose++;        /* -v -> 2 (info) ... -vvv -> 4 (frames) */
	if (g.fdb_hold_ms < 100)
		g.fdb_hold_ms = 100;

	g.use_syslog = force_syslog || !g.foreground;
	if (g.use_syslog)
		openlog("lltd", LOG_PID, LOG_DAEMON);

	srandom((unsigned int)(time(NULL) ^ getpid()));
	load_files();

	g.nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (g.nl_fd >= 0) {
		struct timeval tv = { 1, 0 };

		setsockopt(g.nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	host_id = lowest_mac();
	for (int i = 0; i < g.n_ifs; i++)
		if (setup_iface(&g.ifs[i], &host_id) != 0)
			return 1;

	if (!g.foreground && daemon(0, 0) != 0) {
		logx(0, "daemon: %s", strerror(errno));
		return 1;
	}
	if (g.pidfile) {
		FILE *pf = fopen(g.pidfile, "w");

		if (pf) {
			fprintf(pf, "%d\n", (int)getpid());
			fclose(pf);
		}
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGHUP, on_signal);
	signal(SIGPIPE, SIG_IGN);

	while (!stop_requested) {
		uint64_t now = now_ms(), next = now + 1000;
		int timeout;

		if (reload_requested) {
			reload_requested = 0;
			reload_info();
		}
		/* link state (media connect/disconnect) */
		if (now >= next_carrier) {
			next_carrier = now + 2000;
			for (int i = 0; i < g.n_ifs; i++) {
				int up = sys_if_carrier(g.ifs[i].name);

				if (g.ifs[i].carrier && !up)
					lltd_media_disconnect(&g.ifs[i].resp);
				g.ifs[i].carrier = up;
			}
		}
		for (int i = 0; i < g.n_ifs; i++) {
			uint64_t d = lltd_next_deadline(&g.ifs[i].resp);

			if (d && d < next)
				next = d;
			pfd[i].fd = g.ifs[i].fd;
			pfd[i].events = POLLIN;
			pfd[i].revents = 0;
		}
		timeout = next > now ? (int)(next - now) : 0;
		if (poll(pfd, (nfds_t)g.n_ifs, timeout) < 0 && errno != EINTR) {
			logx(0, "poll: %s", strerror(errno));
			break;
		}

		for (int i = 0; i < g.n_ifs; i++) {
			struct iface *ifc = &g.ifs[i];

			if (pfd[i].revents & POLLIN) {
				for (int k = 0; k < 64; k++) {
					uint8_t buf[2048];
					struct sockaddr_ll from;
					socklen_t fl = sizeof(from);
					ssize_t n = recvfrom(ifc->fd, buf, sizeof(buf), 0,
							     (struct sockaddr *)&from, &fl);

					if (n < 0)
						break;
					if (from.sll_pkttype == PACKET_OUTGOING)
						continue;   /* our own transmissions */
					lltd_rx(&ifc->resp, buf, (size_t)n, now_ms());
					lltd_tick(&ifc->resp, now_ms());
				}
			}
			lltd_tick(&ifc->resp, now_ms());
		}
	}

	logx(2, "shutting down");
	for (int i = 0; i < g.n_ifs; i++) {
		lltd_free(&g.ifs[i].resp);
		set_promisc(&g.ifs[i], 0);
		close(g.ifs[i].fd);
	}
	if (g.nl_fd >= 0)
		close(g.nl_fd);
	if (g.pidfile)
		unlink(g.pidfile);
	return 0;
}
