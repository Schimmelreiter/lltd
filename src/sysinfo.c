/*
 * lltd - Linux specific information about interfaces and the host
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/wireless.h>

#include "sysinfo.h"

static int read_sysfs(const char *ifname, const char *attr, char *buf, size_t len)
{
	char path[256];
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, attr);
	f = fopen(path, "r");
	if (!f)
		return -1;
	n = fread(buf, 1, len - 1, f);
	fclose(f);
	buf[n] = '\0';
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return (int)n;
}

static int sysfs_exists(const char *ifname, const char *attr)
{
	char path[256];
	struct stat st;

	snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, attr);
	return stat(path, &st) == 0;
}

int sys_if_mac(const char *ifname, mac_t *mac)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int rc = -1;

	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(mac->a, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
		rc = 0;
	}
	close(fd);
	return rc;
}

int sys_if_is_bridge(const char *ifname)
{
	return sysfs_exists(ifname, "bridge");
}

int sys_if_is_wireless(const char *ifname)
{
	return sysfs_exists(ifname, "wireless") || sysfs_exists(ifname, "phy80211");
}

int sys_if_carrier(const char *ifname)
{
	char buf[8];

	if (read_sysfs(ifname, "carrier", buf, sizeof(buf)) <= 0)
		return 1;   /* unknown: assume up */
	return buf[0] == '1';
}

int sys_bridge_vlan(const char *ifname, uint16_t *pvid)
{
	char buf[16];

	*pvid = 0;
	if (read_sysfs(ifname, "bridge/vlan_filtering", buf, sizeof(buf)) <= 0 || buf[0] != '1')
		return 0;
	if (read_sysfs(ifname, "bridge/default_pvid", buf, sizeof(buf)) > 0)
		*pvid = (uint16_t)atoi(buf);
	return 1;
}

static long if_speed_mbit(const char *ifname)
{
	char buf[32];
	long v;

	if (read_sysfs(ifname, "speed", buf, sizeof(buf)) <= 0)
		return 0;
	v = atol(buf);
	return v > 0 ? v : 0;
}

/* a bridge has no speed of its own: use the fastest member port */
static long bridge_speed_mbit(const char *ifname)
{
	char path[256];
	struct dirent *de;
	long best = 0;
	DIR *d;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", ifname);
	d = opendir(path);
	if (!d)
		return 0;
	while ((de = readdir(d))) {
		long s;

		if (de->d_name[0] == '.')
			continue;
		s = if_speed_mbit(de->d_name);
		if (s > best)
			best = s;
	}
	closedir(d);
	return best;
}

/* /proc/net/if_inet6: addr ifindex plen scope flags name */
static int pick_ipv6(const char *ifname, uint8_t out[16])
{
	char line[256], hex[33], name[IFNAMSIZ + 1];
	unsigned int idx, plen, scope, flags;
	int best_rank = -1;
	FILE *f = fopen("/proc/net/if_inet6", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		uint8_t a[16];
		int rank;

		if (sscanf(line, "%32s %x %x %x %x %16s", hex, &idx, &plen, &scope, &flags, name) != 6)
			continue;
		if (strcmp(name, ifname) != 0)
			continue;
		/* skip temporary (0x01), deprecated (0x20) and tentative (0x40) */
		if (flags & (0x01 | 0x20 | 0x40))
			continue;
		for (int i = 0; i < 16; i++) {
			unsigned int b;

			sscanf(hex + 2 * i, "%2x", &b);
			a[i] = (uint8_t)b;
		}
		if (scope == 0x00 && (a[0] & 0xe0) == 0x20)
			rank = 3;       /* global unicast */
		else if (scope == 0x00 && (a[0] & 0xfe) == 0xfc)
			rank = 2;       /* unique local */
		else if (scope == 0x20)
			rank = 1;       /* link local */
		else
			continue;
		if (rank > best_rank) {
			best_rank = rank;
			memcpy(out, a, 16);
		}
	}
	fclose(f);
	return best_rank >= 0;
}

static int pick_ipv4(const char *ifname, uint8_t out[4])
{
	struct ifaddrs *ifa, *p;
	int found = 0;

	if (getifaddrs(&ifa) != 0)
		return 0;
	for (p = ifa; p && !found; p = p->ifa_next) {
		if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET || strcmp(p->ifa_name, ifname) != 0)
			continue;
		memcpy(out, &((struct sockaddr_in *)p->ifa_addr)->sin_addr, 4);
		found = 1;
	}
	freeifaddrs(ifa);
	return found;
}

static void wireless_info(const char *ifname, struct lltd_hostinfo *info)
{
	struct iwreq wrq;
	char essid[IW_ESSID_MAX_SIZE + 1];
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	info->wireless = 0;
	if (fd < 0)
		return;
	memset(&wrq, 0, sizeof(wrq));
	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIWMODE, &wrq) == 0 &&
	    (wrq.u.mode == IW_MODE_INFRA || wrq.u.mode == IW_MODE_ADHOC)) {
		info->wireless_mode = wrq.u.mode == IW_MODE_INFRA ? 1 : 0;
		memset(&wrq, 0, sizeof(wrq));
		snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
		if (ioctl(fd, SIOCGIWAP, &wrq) == 0)
			memcpy(info->bssid.a, wrq.u.ap_addr.sa_data, ETH_ADDR_LEN);
		memset(&wrq, 0, sizeof(wrq));
		memset(essid, 0, sizeof(essid));
		snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
		wrq.u.essid.pointer = essid;
		wrq.u.essid.length = IW_ESSID_MAX_SIZE;
		if (ioctl(fd, SIOCGIWESSID, &wrq) == 0) {
			size_t n = strnlen(essid, IW_ESSID_MAX_SIZE);

			if (n > sizeof(info->ssid))
				n = sizeof(info->ssid);
			memcpy(info->ssid, essid, n);
			info->ssid_len = n;
			info->wireless = 1;
		}
	}
	close(fd);
}

void sys_refresh_info(const char *ifname, struct lltd_hostinfo *info, int speed_override_mbit)
{
	char buf[16];
	long mbit;
	int bridge = sys_if_is_bridge(ifname);

	info->has_ipv4 = pick_ipv4(ifname, info->ipv4);
	info->has_ipv6 = pick_ipv6(ifname, info->ipv6);

	mbit = speed_override_mbit > 0 ? speed_override_mbit :
	       bridge ? bridge_speed_mbit(ifname) : if_speed_mbit(ifname);
	/* units of 100 bit/s; 400 Gbit/s still fits into 32 bits */
	info->link_speed = (uint32_t)(mbit * 10000L);

	info->characteristics &= (uint16_t)~CHAR_FULL_DUPLEX;
	if (bridge || (read_sysfs(ifname, "duplex", buf, sizeof(buf)) > 0 && strcmp(buf, "full") == 0))
		info->characteristics |= CHAR_FULL_DUPLEX;

	info->medium = IFTYPE_ETHERNET;
	info->wireless = 0;
	if (!bridge && sys_if_is_wireless(ifname)) {
		info->medium = IFTYPE_IEEE80211;
		wireless_info(ifname, info);
	}
}

size_t utf8_to_ucs2le(const char *in, uint8_t *out, size_t max_chars)
{
	const unsigned char *p = (const unsigned char *)in;
	size_t n = 0;

	while (*p && n < max_chars) {
		unsigned int c;

		if (*p < 0x80) {
			c = *p++;
		} else if ((*p & 0xe0) == 0xc0 && (p[1] & 0xc0) == 0x80) {
			c = ((p[0] & 0x1fu) << 6) | (p[1] & 0x3fu);
			p += 2;
		} else if ((*p & 0xf0) == 0xe0 && (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80) {
			c = ((p[0] & 0x0fu) << 12) | ((p[1] & 0x3fu) << 6) | (p[2] & 0x3fu);
			p += 3;
		} else {
			/* invalid or outside the BMP: skip the sequence */
			p++;
			while ((*p & 0xc0) == 0x80)
				p++;
			c = '?';
		}
		out[2 * n] = (uint8_t)(c & 0xff);
		out[2 * n + 1] = (uint8_t)(c >> 8);
		n++;
	}
	return 2 * n;
}

int sys_default_route_if(char *buf, size_t len)
{
	char line[256], name[IFNAMSIZ];
	unsigned long dest, gw, flags;
	FILE *f = fopen("/proc/net/route", "r");
	int found = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%15s %lx %lx %lx", name, &dest, &gw, &flags) == 4 &&
		    dest == 0 && (flags & 0x1 /* RTF_UP */)) {
			snprintf(buf, len, "%s", name);
			found = 0;
			break;
		}
	}
	fclose(f);
	return found;
}

void sys_short_hostname(char *buf, size_t len)
{
	char *dot;

	if (gethostname(buf, len) != 0 || !buf[0])
		snprintf(buf, len, "lltd");
	buf[len - 1] = '\0';
	dot = strchr(buf, '.');
	if (dot)
		*dot = '\0';
}

uint8_t *sys_read_file(const char *path, size_t max, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	size_t n;

	if (!f)
		return NULL;
	buf = malloc(max + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	n = fread(buf, 1, max + 1, f);
	fclose(f);
	if (n == 0 || n > max) {
		free(buf);
		errno = n ? EFBIG : EINVAL;
		return NULL;
	}
	*len = n;
	return buf;
}
