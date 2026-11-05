#include "vpncloud_forward.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

int vpncloud_forward(const u8 *pkt, u32 len, u8 *out, u32 out_cap, u32 *out_len)
{
	if (!pkt || !out || !out_len)
		return -1;
	*out_len = 0;
	if (len >= 20 && pkt[0] == 0x45 && out_cap >= len) {
		memcpy(out, pkt, len);
		*out_len = len;
		return 0;
	}
	return 1;
}
