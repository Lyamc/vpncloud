#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "vpncloud_forward.h"

static int __init vpncloud_fwd_init(void)
{
	u8 pkt[20];
	u8 out[20];
	u32 n = 0;
	int i;

	for (i = 0; i < 20; i++)
		pkt[i] = 0;
	pkt[0] = 0x45;
	if (vpncloud_forward(pkt, 20, out, 20, &n) != 0 || n != 20)
		return -EINVAL;
	return 0;
}

static void __exit vpncloud_fwd_exit(void)
{
}

module_init(vpncloud_fwd_init);
module_exit(vpncloud_fwd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vpncloud in-tree overlay forward");
MODULE_AUTHOR("vpncloud");
