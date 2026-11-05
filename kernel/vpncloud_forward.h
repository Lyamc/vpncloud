#ifndef VPNCLOUD_FORWARD_H
#define VPNCLOUD_FORWARD_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
#endif

/* 0 forwarded, 1 dropped. IPv4 (first byte 0x45, at least 20 bytes) is copied. */
int vpncloud_forward(const u8 *pkt, u32 len, u8 *out, u32 out_cap, u32 *out_len);

#endif
