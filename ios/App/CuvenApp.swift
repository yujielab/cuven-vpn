import NetworkExtension
import SwiftUI
import UIKit

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
    @State private var showingSettings = false
    @Environment(\.scenePhase) private var scenePhase

    private let accent = Color(red: 0.05, green: 0.48, blue: 0.41)

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 12) {
                        Image(systemName: statusIcon)
                            .font(.system(size: 39, weight: .semibold))
                            .foregroundStyle(vpn.status == .connected ? accent : Color.secondary)
                            .frame(width: 84, height: 84)
                            .background((vpn.status == .connected ? accent : Color.secondary).opacity(0.12), in: Circle())
                            .accessibilityHidden(true)
                        Text(statusTitle)
                            .font(.title2.bold())
                        if vpn.showsConnectedPrivacyPolicy {
                            LabeledContent("连接策略", value: "全隧道 · 加密 DNS")
                                .font(.subheadline)
                        } else if vpn.canEdit && !vpn.hasSavedGateway {
                            Text("添加自有 VPS 的地址和接入令牌。")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        } else if vpn.status == .reasserting {
                            Text("正在重新验证网关连接。")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        if vpn.autoConnectPaused && vpn.canEdit {
                            Text("自动连接已暂停")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        if let rtt = vpn.tunnelRTT {
                            Text(rtt == 0 ? "到网关不足 1 ms" : "到网关 \(rtt) ms")
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

                Section {
                    NavigationLink {
                        PrivateBrowserView(vpn: vpn)
                    } label: {
                        Label("隐私浏览器", systemImage: "globe")
                    }
                    .accessibilityIdentifier("private-browser")
                }

                if !vpn.shouldReviewBeforeConnecting {
                    Section {
                        Button {
                            showingSettings = true
                        } label: {
                            Label("连接设置", systemImage: "slider.horizontal.3")
                        }
                        .accessibilityIdentifier("connection-settings")
                    }
                }
            }
            .navigationTitle("Cuven")
            .navigationDestination(isPresented: $showingSettings) {
                NetworkSettingsView(vpn: vpn)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .tint(accent)
        .task { await vpn.load() }
        .task(id: scenePhase == .active && vpn.status == .connected) {
            guard scenePhase == .active, vpn.status == .connected else { return }
            while !Task.isCancelled {
                vpn.refreshTunnelRTT()
                try? await Task.sleep(for: .seconds(5))
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                vpn.retryCredentialAfterUnlock()
                vpn.refreshStatus()
            } else {
                vpn.clearTunnelRTT()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataDidBecomeAvailableNotification)) { _ in
            vpn.retryCredentialAfterUnlock()
        }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            vpn.refreshStatus()
        }
        .accessibilityHidden(scenePhase != .active)
        .overlay {
            if scenePhase != .active {
                ZStack {
                    Color(uiColor: .systemBackground).ignoresSafeArea()
                    Label("Cuven", systemImage: "lock.shield")
                        .font(.title2.weight(.semibold))
                }
            }
        }
    }

    @ViewBuilder
    private var mainButton: some View {
        if !vpn.loaded {
            if vpn.error != nil && !vpn.busy {
                Button("重新读取配置") { Task { await vpn.load() } }
            }
        } else if [.connecting, .connected, .reasserting].contains(vpn.status) {
            Button("断开连接", role: .destructive) { Task { await vpn.disconnect() } }
                .disabled(!vpn.canStop)
        } else if vpn.shouldReviewBeforeConnecting {
            Button(vpn.reviewTitle) { showingSettings = true }
                .accessibilityIdentifier("connection-settings")
        } else if vpn.status != .disconnecting {
            Button(vpn.autoConnectPaused && vpn.autoConnect != .off ? "连接并恢复自动连接" : "连接 VPN") {
                Task { await vpn.save(connect: true) }
            }
            .disabled(!vpn.canStart)
        }
    }

    private var statusTitle: String {
        if !vpn.loaded { return vpn.error == nil ? "正在读取配置" : "无法读取配置" }
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
    @Environment(\.dismiss) private var dismiss

    @State private var showingSaveError = false

    private func submit(connect: Bool, once: Bool = false) {
        Task {
            if await vpn.save(connect: connect, once: once) {
                dismiss()
            } else if vpn.error != nil {
                showingSaveError = true
            }
        }
    }

    var body: some View {
        Form {
            Section("服务器") {
                TextField("服务器地址", text: $vpn.host)
                    .textContentType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .accessibilityLabel("服务器地址")

                SecureField(vpn.hasCredential ? "令牌已保存，输入以替换" : "网关接入令牌", text: $vpn.credential)
                    .cuvenSecureInput()
                    .accessibilityLabel("Cuven IP 接入令牌")
                if vpn.credentialAwaitsUnlock {
                    Text("钥匙串暂时不可访问。解锁设备后，Cuven 会重新读取已保存的令牌。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if vpn.offersOneTimeStart && !vpn.hasCredential && vpn.autoConnect == .off {
                    Text("可仅为本次连接使用令牌。下次从 Cuven 连接时需要重新输入。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("仅本次连接，不保存令牌") {
                        submit(connect: true, once: true)
                    }
                    .disabled(!vpn.canStartOnce)
                } else if vpn.requiresAppStart {
                    Text("此配置使用 App 启动凭据，请从 Cuven 内手动连接。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                DisclosureGroup("高级服务器设置") {
                    TextField("端口", text: $vpn.port)
                        .keyboardType(.numberPad)
                        .accessibilityLabel("端口")

                    TextField("TLS 证书域名（可选）", text: $vpn.serverName)
                        .cuvenPlainInput()
                        .keyboardType(.URL)
                    Toggle("网关支持 IPv6", isOn: $vpn.enableIPv6)
                }
            }
            .disabled(!vpn.canEdit)

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
                Toggle("Cuven 封锁模式", isOn: $vpn.lockdown)
                    .accessibilityIdentifier("cuven-lockdown")
                if vpn.lockdown {
                    TextField("网关公钥指纹（SHA-256）", text: $vpn.gatewayKeyPin)
                        .cuvenPlainInput()
                        .accessibilityIdentifier("gateway-key-pin")
                } else {
                    Toggle("高安全模式", isOn: $vpn.highSecurity)
                    if !vpn.highSecurity {
                        Toggle("阻止局域网访问", isOn: $vpn.blockLAN)
                    }
                }
            } footer: {
                if vpn.lockdown {
                    Text("请填写网关 IP，并从可信的 VPS 管理终端取得公钥指纹。连接时会同时校验证书和指纹，强制全隧道路由、加密 DNS 并阻止局域网访问。更换网关密钥后需要更新指纹。")
                } else if vpn.highSecurity {
                    Text("强制路由和隧道内加密 DNS。WebRTC 随 VPN 出口通行。服务器需填写 IP。")
                } else {
                    Text("若你面临定向网络攻击，可开启 Cuven 封锁模式，并通过自有 VPS 核对证书公钥。部分系统流量仍由 iOS 处理。")
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

            if vpn.canSave {
                Button(vpn.autoConnectPaused && vpn.autoConnect != .off ? "保存并恢复自动连接" : "保存设置") {
                    submit(connect: false)
                }
            }
        }
        .navigationTitle("连接设置")
        .alert("未能应用连接设置", isPresented: $showingSaveError) {
            Button("好", role: .cancel) {}
        } message: {
            Text(vpn.error ?? "请核对设置后重试。")
        }
        .toolbar {
            if vpn.canEdit {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("连接") { submit(connect: true) }
                        .disabled(!vpn.canStart)
                        .accessibilityIdentifier("connect-from-settings")
                }
            }
        }
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
