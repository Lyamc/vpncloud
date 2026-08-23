package ca.witherow.vpncloud

import android.net.VpnService

object NativeEngine {
    init {
        System.loadLibrary("vpncloud")
    }

    @JvmStatic
    external fun nativeStart(configYaml: String, tunFd: Int, service: VpnService)

    @JvmStatic
    external fun nativeStop()
}
