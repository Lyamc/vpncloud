import Darwin
import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "ca.witherow.vpncloud", category: "tunnel")

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnelQueue: DispatchQueue?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let conf = proto?.providerConfiguration
        guard let yaml = conf?["yaml"] as? String else {
            completionHandler(Self.error("missing YAML config"))
            return
        }
        let overlay = (conf?["overlay"] as? String) ?? "10.0.0.2/24"
        let mtu = (conf?["mtu"] as? Int) ?? 1400

        if yaml.contains("type: tap") || yaml.contains("type:tap") {
            completionHandler(Self.error("TAP/L2 is not available on iOS. Packet Tunnel Provider is TUN-only."))
            return
        }

        let settings: NEPacketTunnelNetworkSettings
        do {
            settings = try Self.overlaySettings(overlay: overlay, mtu: mtu, remote: proto?.serverAddress)
        } catch {
            completionHandler(error)
            return
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(Self.error("tunnel deallocated"))
                return
            }
            if let error {
                completionHandler(error)
                return
            }
            guard let tunFd = self.tunnelFileDescriptor() else {
                completionHandler(Self.error("cannot locate utun file descriptor"))
                return
            }
            os_log("starting vpncloud on tun fd %d", log: log, type: .info, tunFd)
            let queue = DispatchQueue(label: "ca.witherow.vpncloud.tunnel", qos: .userInitiated)
            self.tunnelQueue = queue
            queue.async {
                yaml.withCString { ptr in
                    let rc = vpncloud_start(ptr, tunFd)
                    if rc != 0 {
                        let msg = vpncloud_last_error().map { String(cString: $0) } ?? "vpncloud_start failed"
                        os_log("vpncloud_start: %{public}@", log: log, type: .error, msg)
                    }
                }
            }
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("stopping tunnel, reason %d", log: log, type: .info, reason.rawValue)
        vpncloud_stop()
        tunnelQueue = nil
        completionHandler()
    }

    /// WireGuard-style scan for the Packet Tunnel utun control socket (iOS 16+).
    private func tunnelFileDescriptor() -> Int32? {
        if let kvo = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32, kvo >= 0 {
            return kvo
        }
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != UInt8(AF_SYSTEM) {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                if ioctl(fd, CTLIOCGINFO, &ctlInfo) != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Overlay subnet only — never the default route, so UDP mesh traffic stays off the tunnel.
    static func overlaySettings(overlay: String, mtu: Int, remote: String?) throws -> NEPacketTunnelNetworkSettings {
        let parsed = try parseOverlay(overlay)
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote?.isEmpty == false ? remote! : "127.0.0.1")
        settings.mtu = NSNumber(value: mtu)
        if parsed.ipv6 {
            let v6 = NEIPv6Settings(addresses: [parsed.addr], networkPrefixLengths: [NSNumber(value: parsed.prefix)])
            v6.includedRoutes = [
                NEIPv6Route(destinationAddress: parsed.network, networkPrefixLength: NSNumber(value: parsed.prefix))
            ]
            settings.ipv6Settings = v6
        } else {
            let v4 = NEIPv4Settings(addresses: [parsed.addr], subnetMasks: [parsed.mask])
            v4.includedRoutes = [NEIPv4Route(destinationAddress: parsed.network, subnetMask: parsed.mask)]
            settings.ipv4Settings = v4
        }
        return settings
    }

    static func parseOverlay(_ spec: String) throws -> (addr: String, prefix: Int, mask: String, network: String, ipv6: Bool) {
        let parts = spec.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/", maxSplits: 1)
        let addr = String(parts[0])
        let ipv6 = addr.contains(":")
        let prefix = parts.count > 1 ? Int(parts[1]) ?? (ipv6 ? 64 : 24) : (ipv6 ? 64 : 24)
        if ipv6 {
            return (addr, prefix, "", ipv6Network(addr, prefix: prefix), true)
        }
        let mask = ipv4Mask(prefix: prefix)
        return (addr, prefix, mask, ipv4Network(addr, prefix: prefix), false)
    }

    static func ipv4Mask(prefix: Int) -> String {
        let clamped = min(max(prefix, 0), 32)
        let mask: UInt32 = clamped == 0 ? 0 : UInt32.max << (32 - clamped)
        return "\((mask >> 24) & 0xff).\((mask >> 16) & 0xff).\((mask >> 8) & 0xff).\(mask & 0xff)"
    }

    static func ipv4Network(_ addr: String, prefix: Int) -> String {
        let oct = addr.split(separator: ".").compactMap { UInt32($0) }
        guard oct.count == 4 else { return addr }
        let ip = (oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3]
        let clamped = min(max(prefix, 0), 32)
        let mask: UInt32 = clamped == 0 ? 0 : UInt32.max << (32 - clamped)
        let net = ip & mask
        return "\((net >> 24) & 0xff).\((net >> 16) & 0xff).\((net >> 8) & 0xff).\(net & 0xff)"
    }

    static func ipv6Network(_ addr: String, prefix: Int) -> String {
        var addr6 = in6_addr()
        let ok = addr.withCString { inet_pton(AF_INET6, $0, &addr6) }
        guard ok == 1 else { return addr }
        var bytes = withUnsafeBytes(of: addr6) { Array($0) }
        let clamped = min(max(prefix, 0), 128)
        for i in 0..<16 {
            let bitIndex = i * 8
            if bitIndex >= clamped {
                bytes[i] = 0
            } else if bitIndex + 8 > clamped {
                let keep = clamped - bitIndex
                bytes[i] &= UInt8(0xff << (8 - keep))
            }
        }
        var result = in6_addr()
        _ = bytes.withUnsafeBufferPointer { ptr in
            memcpy(&result, ptr.baseAddress, 16)
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &result, &buf, socklen_t(INET6_ADDRSTRLEN))
        return String(cString: buf)
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "ca.witherow.vpncloud", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
