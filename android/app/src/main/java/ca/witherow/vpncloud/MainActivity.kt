package ca.witherow.vpncloud

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputEditText

class MainActivity : AppCompatActivity() {
    private var connected = false

    private val prepareVpn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<Button>(R.id.toggle).setOnClickListener { toggle() }
    }

    private fun toggle() {
        if (connected) {
            startService(Intent(this, VpnCloudService::class.java).setAction(VpnCloudService.ACTION_STOP))
            connected = false
            findViewById<Button>(R.id.toggle).text = getString(R.string.connect)
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            prepareVpn.launch(prepare)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val password = text(R.id.password)
        val overlay = text(R.id.overlay_ip).ifBlank { "10.0.0.2/24" }
        val peer = text(R.id.peer)
        val listen = text(R.id.listen).ifBlank { "3210" }
        if (password.isBlank()) {
            Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
            return
        }
        val yaml = buildString {
            appendLine("crypto:")
            appendLine("  password: \"${password.replace("\"", "\\\"")}\"")
            appendLine("ip: $overlay")
            appendLine("listen: $listen")
            appendLine("device:")
            appendLine("  type: tun")
            if (peer.isNotBlank()) {
                appendLine("peers:")
                appendLine("  - $peer")
            }
        }
        val intent = Intent(this, VpnCloudService::class.java)
            .putExtra(VpnCloudService.EXTRA_YAML, yaml)
            .putExtra(VpnCloudService.EXTRA_OVERLAY, overlay)
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        connected = true
        findViewById<Button>(R.id.toggle).text = getString(R.string.disconnect)
    }

    private fun text(id: Int): String =
        findViewById<TextInputEditText>(id).text?.toString()?.trim().orEmpty()
}
