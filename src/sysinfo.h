/*
 * lltd - Linux specific information about interfaces and the host
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef LLTD_SYSINFO_H
#define LLTD_SYSINFO_H

#include <stddef.h>
#include <stdint.h>

#include "responder.h"

int sys_if_mac(const char *ifname, mac_t *mac);
int sys_if_is_bridge(const char *ifname);
int sys_if_is_wireless(const char *ifname);
int sys_if_carrier(const char *ifname);
int sys_bridge_vlan(const char *ifname, uint16_t *pvid);    /* 1 if vlan filtering */

/* Fills addresses, link speed, duplex and wireless data of info.
 * speed_override_mbit > 0 replaces the detected speed. */
void sys_refresh_info(const char *ifname, struct lltd_hostinfo *info, int speed_override_mbit);

/* UTF-8 to UCS-2LE (BMP only), at most max_chars characters; returns bytes */
size_t utf8_to_ucs2le(const char *in, uint8_t *out, size_t max_chars);

/* interface of the IPv4 default route ("auto"); returns 0 on success */
int sys_default_route_if(char *buf, size_t len);

/* short host name (up to the first dot) */
void sys_short_hostname(char *buf, size_t len);

/* reads a whole file into a new buffer (max bytes); returns NULL on error */
uint8_t *sys_read_file(const char *path, size_t max, size_t *len);

#endif
