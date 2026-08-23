package ca.witherow.vpncloud

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class VpnCloudService : VpnService() {
    private var worker: Thread? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        val yaml = intent?.getStringExtra(EXTRA_YAML) ?: return START_NOT_STICKY
        val overlay = intent.getStringExtra(EXTRA_OVERLAY) ?: "10.0.0.2/24"
        val mtu = intent.getIntExtra(EXTRA_MTU, 1400)
        val tap = intent.getBooleanExtra(EXTRA_TAP, false)
        if (tap) {
            startRootedTap(yaml)
        } else {
            startVpn(yaml, overlay, mtu)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startRootedTap(yaml: String) {
        if (running.getAndSet(true)) {
            return
        }
        if (!NativeEngine.nativeIsRooted()) {
            Log.e(TAG, "TAP requires a rooted device")
            running.set(false)
            stopSelf()
            return
        }
        startForeground(NOTIF_ID, notification())
        worker = thread(name = "vpncloud-native-tap") {
            try {
                NativeEngine.nativeStart(yaml, -1, this)
            } catch (e: Throwable) {
                Log.e(TAG, "nativeStart TAP failed", e)
            } finally {
                running.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun startVpn(yaml: String, overlay: String, mtu: Int) {
        if (running.getAndSet(true)) {
            return
        }
        startForeground(NOTIF_ID, notification())
        val (addr, prefix) = parseOverlay(overlay)
        val builder = Builder()
            .setSession("VpnCloud")
            .setMtu(mtu)
            .addAddress(addr, prefix)
            .addRoute(networkAddress(addr, prefix), prefix)
            .allowFamily(android.system.OsConstants.AF_INET)
        if (addr.contains(':')) {
            builder.allowFamily(android.system.OsConstants.AF_INET6)
        }
        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null")
            running.set(false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        val fd = pfd.detachFd()
        try {
            pfd.close()
        } catch (_: Exception) {
        }
        worker = thread(name = "vpncloud-native") {
            try {
                NativeEngine.nativeStart(yaml, fd, this)
            } catch (e: Throwable) {
                Log.e(TAG, "nativeStart failed", e)
            } finally {
                running.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun stopVpn() {
        NativeEngine.nativeStop()
        worker?.join(2000)
        worker = null
        running.set(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "ca.witherow.vpncloud.STOP"
        const val EXTRA_YAML = "yaml"
        const val EXTRA_OVERLAY = "overlay"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_TAP = "tap"
        private const val TAG = "VpnCloudService"
        private const val CHANNEL_ID = "vpncloud"
        private const val NOTIF_ID = 1

        fun parseOverlay(spec: String): Pair<String, Int> {
            val parts = spec.trim().split('/', limit = 2)
            val addr = parts[0]
            val prefix = parts.getOrNull(1)?.toIntOrNull() ?: if (addr.contains(':')) 64 else 24
            return addr to prefix
        }

        fun networkAddress(addr: String, prefix: Int): String {
            if (addr.contains(':')) {
                return addr
            }
            val oct = addr.split('.').map { it.toInt() }
            require(oct.size == 4)
            val ip = (oct[0] shl 24) or (oct[1] shl 16) or (oct[2] shl 8) or oct[3]
            val mask = if (prefix == 0) 0 else -1 shl (32 - prefix)
            val net = ip and mask
            return "${(net ushr 24) and 0xff}.${(net ushr 16) and 0xff}.${(net ushr 8) and 0xff}.${net and 0xff}"
        }
    }
}
