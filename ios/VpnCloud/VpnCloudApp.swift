import SwiftUI

@main
struct VpnCloudApp: App {
    @StateObject private var vpn = VpnManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpn)
        }
    }
}
