import Foundation
import NetworkExtension

final class VpnManager: ObservableObject {
    static let providerBundleId = "ca.witherow.vpncloud.PacketTunnel"

    @Published var isConnected = false
    @Published var busy = false
    @Published var statusText: String?

    private var manager: NETunnelProviderManager?

    init() {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.refreshStatus()
        }
        load()
    }

    func connect(yaml: String, overlay: String, peer: String) {
        busy = true
        statusText = nil
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            guard let self else { return }
            if let error {
                self.finish(error.localizedDescription)
                return
            }
            let mgr = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleId
            proto.serverAddress = peer.isEmpty ? overlay : peer
            proto.providerConfiguration = [
                "yaml": yaml,
                "overlay": overlay,
                "mtu": 1400
            ]
            mgr.protocolConfiguration = proto
            mgr.localizedDescription = "VpnCloud"
            mgr.isEnabled = true
            mgr.saveToPreferences { error in
                if let error {
                    self.finish(error.localizedDescription)
                    return
                }
                mgr.loadFromPreferences { error in
                    if let error {
                        self.finish(error.localizedDescription)
                        return
                    }
                    do {
                        try mgr.connection.startVPNTunnel()
                        self.manager = mgr
                        self.busy = false
                        self.refreshStatus()
                    } catch {
                        self.finish(error.localizedDescription)
                    }
                }
            }
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func load() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            self?.manager = managers?.first
            self?.refreshStatus()
        }
    }

    private func refreshStatus() {
        let status = manager?.connection.status
        isConnected = status == .connected || status == .connecting || status == .reasserting
        if let status {
            statusText = String(describing: status)
        }
    }

    private func finish(_ message: String) {
        busy = false
        statusText = message
    }
}
