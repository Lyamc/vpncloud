#include "vpncloud_forward.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int main(int argc, char **argv)
{
	const char *hex;
	size_t n, len, i;
	uint8_t *pkt;
	uint8_t out[2048];
	uint32_t out_len = 0;
	int rc;

	if (argc != 2)
		return 2;
	hex = argv[1];
	n = strlen(hex);
	if (n % 2)
		return 2;
	len = n / 2;
	pkt = calloc(len ? len : 1, 1);
	if (!pkt)
		return 2;
	for (i = 0; i < len; i++) {
		int hi = hexval(hex[i * 2]);
		int lo = hexval(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return 2;
		pkt[i] = (uint8_t)((hi << 4) | lo);
	}
	rc = vpncloud_forward(pkt, (uint32_t)len, out, sizeof(out), &out_len);
	if (rc == 0) {
		printf("FORWARD ");
		for (i = 0; i < out_len; i++)
			printf("%02x", out[i]);
		printf("\n");
	} else {
		printf("DROP\n");
	}
	free(pkt);
	return 0;
}
