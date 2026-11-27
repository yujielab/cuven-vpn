import NetworkExtension
import SwiftUI

@main
struct CuvenApp: App {
    var body: some Scene {
        WindowGroup {
            ConnectionView()
        }
    }
}

private struct ConnectionView: View {
    @StateObject private var vpn = VPNController()
    @Environment(\.scenePhase) private var scenePhase

    private let accent = Color(red: 0.05, green: 0.48, blue: 0.41)

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: statusIcon)
                            .font(.system(size: 39, weight: .semibold))
                            .foregroundStyle(accent)
                            .frame(width: 84, height: 84)
                            .background(accent.opacity(0.12), in: Circle())
                            .accessibilityHidden(true)
                        Text(statusTitle)
                            .font(.title2.bold())
                        Text(VPNTransport.cuven.title)
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.secondary)
                        if !vpn.host.isEmpty {
                            Text(vpn.host)
                                .font(.subheadline.monospaced())
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .textSelection(.enabled)
                        }
                        if let rtt = vpn.tunnelRTT {
                            Text("到网关 \(rtt) ms")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        if vpn.busy {
                            ProgressView().accessibilityLabel("正在更新 VPN 配置")
                        }
                        mainButton
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 20)
                    .accessibilityElement(children: .contain)
                }

                if let error = vpn.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.circle")
                            .foregroundStyle(.red)
                            .font(.subheadline)
                            .accessibilityAddTraits(.updatesFrequently)
                    }
                }

                Section("服务器") {
                    TextField("服务器地址", text: $vpn.host)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .accessibilityLabel("服务器地址")

                    TextField("端口", text: $vpn.port)
                        .keyboardType(.numberPad)
                        .accessibilityLabel("端口")

                    TextField("TLS 证书域名（可选）", text: $vpn.serverName)
                        .cuvenPlainInput()
                        .keyboardType(.URL)
                    SecureField(vpn.hasCredential ? "令牌已保存，输入以替换" : "网关接入令牌", text: $vpn.credential)
                        .cuvenSecureInput()
                        .accessibilityLabel("Cuven IP 接入令牌")
                    if vpn.requiresAppStart {
                        Text("签名未授权共享钥匙串。令牌已存入 App 钥匙串，请从 Cuven 内手动连接。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Toggle("网关支持 IPv6", isOn: $vpn.enableIPv6)
                }
                .disabled(!vpn.canEdit)

                Section {
                    NavigationLink {
                        NetworkSettingsView(vpn: vpn)
                    } label: {
                        Label("连接设置", systemImage: "slider.horizontal.3")
                    }
                    .accessibilityIdentifier("connection-settings")
                    if vpn.canSave {
                        Button(vpn.autoConnectPaused && vpn.autoConnect != .off ? "保存并恢复自动连接" : "保存设置") {
                            Task { await vpn.save(connect: false) }
                        }
                    }
                }
            }
            .navigationTitle("Cuven")
            .scrollDismissesKeyboard(.interactively)
            .tint(accent)
            .task { await vpn.load() }
            .task(id: vpn.status) {
                guard vpn.status == .connected else { return }
                while !Task.isCancelled {
                    vpn.refreshTunnelRTT()
                    try? await Task.sleep(for: .seconds(5))
                }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { vpn.refreshStatus() }
            }
            .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
                vpn.refreshStatus()
            }
        }
    }

    @ViewBuilder
    private var mainButton: some View {
        if !vpn.loaded && !vpn.busy {
            Button("重新读取配置") { Task { await vpn.load() } }
        } else if vpn.canStop {
            Button("断开连接", role: .destructive) { Task { await vpn.disconnect() } }
        } else {
            Button("连接 VPN") { Task { await vpn.save(connect: true) } }
                .disabled(!vpn.canStart)
        }
    }

    private var statusTitle: String {
        if !vpn.loaded { return "读取 VPN 配置" }
        switch vpn.status {
        case .invalid, .disconnected: return "未连接"
        case .connecting: return "正在连接"
        case .connected: return "已连接"
        case .reasserting: return "正在重新连接"
        case .disconnecting: return "正在断开"
        @unknown default: return "连接状态未知"
        }
    }

    private var statusIcon: String {
        switch vpn.status {
        case .connected: "lock.shield.fill"
        case .connecting, .reasserting, .disconnecting: "arrow.clockwise"
        default: "shield"
        }
    }
}

private struct NetworkSettingsView: View {
    @ObservedObject var vpn: VPNController

    var body: some View {
        Form {
            Section {
                Picker("自动连接", selection: $vpn.autoConnect) {
                    ForEach(AutoConnect.allCases) { mode in Text(mode.title).tag(mode) }
                }
            } footer: {
                if vpn.autoConnectPaused && vpn.autoConnect != .off {
                    Text("手动断开已暂停自动连接。保存设置或重新连接即可恢复。")
                } else {
                    Text("在所选网络类型上，由 iOS 按需连接当前配置的服务器。")
                }
            }
            .disabled(!vpn.canEdit)

            Section {
                Toggle("高安全模式", isOn: $vpn.highSecurity)
                if !vpn.highSecurity {
                    Toggle("阻止局域网访问", isOn: $vpn.blockLAN)
                }
            } footer: {
                if vpn.highSecurity {
                    Text("强制路由和隧道内加密 DNS。WebRTC 随 VPN 出口通行。服务器需填写 IP。")
                } else {
                    Text("Cuven IP 使用全流量路由，部分系统流量仍由 iOS 处理。")
                }
            }
            .disabled(!vpn.canEdit)

            Section {
                Toggle("自定义加密 DNS", isOn: $vpn.useEncryptedDNS)
                if vpn.useEncryptedDNS {
                    Picker("加密协议", selection: $vpn.useDNSOverTLS) {
                        Text("DNS over HTTPS").tag(false)
                        Text("DNS over TLS").tag(true)
                    }
                    if vpn.useDNSOverTLS {
                        TextField("DoT 证书域名", text: $vpn.encryptedDNSTLSName)
                            .cuvenPlainInput()
                            .keyboardType(.URL)
                    } else {
                        TextField("HTTPS DNS URL", text: $vpn.encryptedDNSURL)
                            .cuvenPlainInput()
                            .keyboardType(.URL)
                    }
                    TextField("解析器公网 IP，逗号分隔", text: $vpn.encryptedDNSBootstrap)
                        .cuvenPlainInput()
                } else {
                    LabeledContent("DNS", value: "Cloudflare HTTPS")
                }
            } footer: {
                Text("加密 DNS 经过 VPN 隧道并校验解析器证书。DNS over TLS 使用 TCP 853。")
            }
            .disabled(!vpn.canEdit)

            if let error = vpn.error {
                Section {
                    Label(error, systemImage: "exclamationmark.circle")
                        .foregroundStyle(.red)
                        .accessibilityAddTraits(.updatesFrequently)
                }
            }

            if vpn.canSave {
                Button(vpn.autoConnectPaused && vpn.autoConnect != .off ? "保存并恢复自动连接" : "保存设置") {
                    Task { await vpn.save(connect: false) }
                }
            }
        }
        .navigationTitle("连接设置")
        .navigationBarTitleDisplayMode(.inline)
        .scrollDismissesKeyboard(.interactively)
    }
}

private extension View {
    func cuvenPlainInput() -> some View {
        textInputAutocapitalization(.never).autocorrectionDisabled()
    }

    func cuvenSecureInput() -> some View {
        cuvenPlainInput().textContentType(.password).privacySensitive()
    }
}
