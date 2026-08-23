import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VpnManager
    @AppStorage("password") private var password = ""
    @AppStorage("overlay") private var overlay = "10.0.0.2/24"
    @AppStorage("peer") private var peer = ""
    @AppStorage("listen") private var listen = "3210"

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("iOS is TUN/L3 only. TAP/Ethernet is not available. Overlay routes only — the UDP mesh does not hairpin.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section("Config") {
                    SecureField("Password", text: $password)
                    TextField("Overlay IP", text: $overlay)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Peer host:port", text: $peer)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("Listen port", text: $listen)
                        .keyboardType(.numberPad)
                }
                Section {
                    Button(vpn.isConnected ? "Disconnect" : "Connect") {
                        toggle()
                    }
                    .disabled(vpn.busy)
                }
                if let status = vpn.statusText {
                    Section {
                        Text(status)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("VpnCloud")
        }
    }

    private func toggle() {
        if vpn.isConnected {
            vpn.disconnect()
            return
        }
        let pwd = password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pwd.isEmpty else {
            vpn.statusText = "Password is required"
            return
        }
        let overlayIP = overlay.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "10.0.0.2/24"
            : overlay.trimmingCharacters(in: .whitespacesAndNewlines)
        let listenPort = listen.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "3210"
            : listen.trimmingCharacters(in: .whitespacesAndNewlines)
        let escaped = pwd.replacingOccurrences(of: "\"", with: "\\\"")
        var yaml = """
        crypto:
          password: "\(escaped)"
        ip: \(overlayIP)
        listen: \(listenPort)
        device:
          type: tun
        """
        let peerHost = peer.trimmingCharacters(in: .whitespacesAndNewlines)
        if !peerHost.isEmpty {
            yaml += "\npeers:\n  - \(peerHost)\n"
        }
        vpn.connect(yaml: yaml, overlay: overlayIP, peer: peerHost)
    }
}
