/* Minimal pcap writer for the tests (classic libpcap format, Ethernet). */
#include "pcap.h"

FILE *pcap_open(const char *path)
{
	/* magic, version 2.4, thiszone, sigfigs, snaplen, linktype 1 (Ethernet) */
	static const uint32_t hdr[6] = { 0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1 };
	FILE *f = fopen(path, "wb");

	if (f)
		fwrite(hdr, sizeof(hdr), 1, f);
	return f;
}

void pcap_write(FILE *f, uint64_t time_ms, const uint8_t *frame, size_t len)
{
	uint32_t rec[4];

	if (!f)
		return;
	rec[0] = (uint32_t)(time_ms / 1000);
	rec[1] = (uint32_t)((time_ms % 1000) * 1000);
	rec[2] = (uint32_t)len;
	rec[3] = (uint32_t)len;
	fwrite(rec, sizeof(rec), 1, f);
	fwrite(frame, 1, len, f);
}

void pcap_close(FILE *f)
{
	if (f)
		fclose(f);
}
