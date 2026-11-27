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
    @State private var showsImport = false
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
                        Text((vpn.activeTransport ?? vpn.transport).title)
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.secondary)
                        if !vpn.displayedHost.isEmpty {
                            Text(vpn.displayedHost)
                                .font(.subheadline.monospaced())
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                                .textSelection(.enabled)
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
                    Picker("协议", selection: Binding(get: { vpn.transport }, set: { vpn.selectTransport($0) })) {
                        ForEach(VPNTransport.allCases) { transport in
                            Text(transport.title).tag(transport)
                        }
                    }

                    TextField("服务器地址", text: $vpn.host)
                        .textContentType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .accessibilityLabel("服务器地址")

                    TextField("端口", text: $vpn.port)
                        .keyboardType(.numberPad)
                        .accessibilityLabel("端口")

                    if vpn.transport == .hy2 {
                        SecureField(vpn.hasCredential ? "凭据已保存，输入以替换" : "连接凭据", text: $vpn.credential)
                            .cuvenSecureInput()
                            .accessibilityLabel("HY2 连接凭据")

                        Button {
                            showsImport = true
                        } label: {
                            Label("导入 HY2 链接", systemImage: "link")
                        }
                    } else {
                        TextField("隧道地址，例如 10.66.0.2/32", text: $vpn.tunnelAddresses)
                            .cuvenPlainInput()
                            .accessibilityLabel("Cuven WG 隧道地址")
                        TextField("服务端 WireGuard 公钥", text: $vpn.peerPublicKey)
                            .cuvenPlainInput()
                            .accessibilityLabel("服务端 WireGuard 公钥")
                        SecureField(vpn.hasCredential ? "客户端私钥已保存" : "客户端 WireGuard 私钥", text: $vpn.privateKey)
                            .cuvenSecureInput()
                            .accessibilityLabel("客户端 WireGuard 私钥")
                        SecureField(vpn.hasCredential ? "封装密钥已保存" : "Cuven 封装密钥", text: $vpn.relayKey)
                            .cuvenSecureInput()
                            .accessibilityLabel("Cuven 封装密钥")
                        SecureField("WireGuard 预共享密钥（可选）", text: $vpn.presharedKey)
                            .cuvenSecureInput()
                            .accessibilityLabel("可选的 WireGuard 预共享密钥")
                        Text("Cuven WG 连接配套中继。替换密钥时，请重新填写私钥和封装密钥。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .disabled(!vpn.canEdit)

                Section {
                    NavigationLink {
                        NetworkSettingsView(vpn: vpn)
                    } label: {
                        Label("连接设置", systemImage: "slider.horizontal.3")
                    }
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
            .sheet(isPresented: $showsImport) {
                ImportView { vpn.importURI($0) }
            }
            .task { await vpn.load() }
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
                Toggle("自动回退协议", isOn: $vpn.automaticFallback)
                    .disabled(!vpn.hasAlternateTransport || vpn.requirePostQuantum)
            } footer: {
                Text("保存两种协议的服务器设置后可启用。首选服务器连接失败时尝试另一种协议；要求后量子密钥交换时保持 HY2。")
            }
            .disabled(!vpn.canEdit)

            if vpn.transport == .hy2 {
                Section {
                    TextField("TLS 服务器名称（可选）", text: $vpn.serverName)
                        .cuvenPlainInput()
                        .keyboardType(.URL)
                    Toggle("要求后量子密钥交换", isOn: $vpn.requirePostQuantum)
                } footer: {
                    Text("启用后，HY2 只接受 TLS 1.3 的 X25519MLKEM768 混合密钥交换。服务器需要支持该算法。")
                }
                .disabled(!vpn.canEdit)
            }

            Section {
                Toggle("阻止局域网访问", isOn: $vpn.blockLAN)
                Toggle("防止应用绕过 VPN", isOn: $vpn.preventBypass)
            } footer: {
                Text("局域网开关控制隧道期间的本地网络访问。防绕过由 iOS 强制路由，部分系统流量仍由 iOS 处理。")
            }
            .disabled(!vpn.canEdit)

            Section {
                Toggle("自定义 DNS", isOn: $vpn.useCustomDNS)
                if vpn.useCustomDNS {
                    TextField("DNS 地址，逗号分隔", text: $vpn.dns)
                        .cuvenPlainInput()
                        .accessibilityLabel("自定义 DNS 服务器地址")
                }
            } footer: {
                Text("支持 IPv4 和 IPv6 DNS。关闭时使用 Cuven 的默认 DNS。启用局域网阻止时请使用公网 DNS。查询通过隧道传输。")
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

private struct ImportView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var uri = ""
    let onImport: (String) -> Bool

    var body: some View {
        NavigationStack {
            Form {
                TextField("hysteria2://…", text: $uri)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .privacySensitive()
                    .accessibilityLabel("HY2 链接")
            }
            .navigationTitle("导入 HY2 链接")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("导入") {
                        _ = onImport(uri)
                        uri = ""
                        dismiss()
                    }
                    .disabled(uri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
