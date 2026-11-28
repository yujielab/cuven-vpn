import NetworkExtension

@available(macOS 13.3, *)
extension NETunnelProviderProtocol {
    func applyRouting(for profile: VPNProfile) {
        includeAllNetworks = profile.usesFullRouting
        enforceRoutes = profile.blockLAN && !includeAllNetworks
        excludeLocalNetworks = !profile.requiresEncryptedDNS && !profile.blockLAN
        if profile.requiresStrictRouting {
            excludeAPNs = false
            excludeCellularServices = false
        }
    }

    func hasRequiredRouting(for profile: VPNProfile) -> Bool {
        (!profile.usesFullRouting || includeAllNetworks) &&
            (!profile.requiresEncryptedDNS || !excludeLocalNetworks) &&
            (!profile.requiresStrictRouting || (!excludeAPNs && !excludeCellularServices))
    }
}
