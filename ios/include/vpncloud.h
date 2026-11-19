#ifndef VPNCLOUD_H
#define VPNCLOUD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start VpnCloud with YAML and a Packet Tunnel utun fd. Blocks until vpncloud_stop.
   Returns 0 on clean shutdown, -1 on setup error (see vpncloud_last_error). */
int32_t vpncloud_start(const char *_Nonnull yaml, int32_t tun_fd);

/* Signal vpncloud_start to exit. */
void vpncloud_stop(void);

/* Last error from vpncloud_start, or NULL. Returns a heap copy that must be
   released with vpncloud_free_error; it stays valid across later calls. */
const char *_Nullable vpncloud_last_error(void);

/* Free a string returned by vpncloud_last_error. Passing NULL is safe. */
void vpncloud_free_error(const char *_Nullable message);

#ifdef __cplusplus
}
#endif

#endif
