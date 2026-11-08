/* Minimal pcap writer for the tests (classic libpcap format, Ethernet). */
#ifndef LLTD_TEST_PCAP_H
#define LLTD_TEST_PCAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

FILE *pcap_open(const char *path);
void pcap_write(FILE *f, uint64_t time_ms, const uint8_t *frame, size_t len);
void pcap_close(FILE *f);

#endif
