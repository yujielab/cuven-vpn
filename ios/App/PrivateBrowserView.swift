import Network
import SwiftUI
import WebKit

private enum BrowserMode: String, CaseIterable, Identifiable {
    case tunnel = "VPN 出口"
    case proxy = "HTTPS 代理"
    case preview = "本地预览"
    var id: Self { self }
}

enum BrowserPage {
    case website(URL, BrowserProxy?)
    case preview(String)

    var isLive: Bool {
        if case .website = self { return true }
        return false
    }
}

private struct BrowserSession: Identifiable {
    let id = UUID()
    let page: BrowserPage
}

struct PrivateBrowserView: View {
    @ObservedObject var vpn: VPNController
    @State private var mode = BrowserMode.tunnel
    @State private var address = ""
    @State private var proxyAddress = ""
    @State private var username = ""
    @State private var password = ""
    @State private var simulatedIP = ""
    @State private var session: BrowserSession?
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                Picker("浏览方式", selection: $mode) {
                    ForEach(BrowserMode.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
            }
            if mode == .preview {
                Section {
                    TextField("模拟 IPv4 或 IPv6", text: $simulatedIP)
                        .browserAddressInput()
                    Button("预览 IP") { open() }
                } footer: {
                    Text("只在本机示例网页中显示这个地址。预览可以离线使用。")
                }
            } else {
                if mode == .proxy {
                    Section {
                        TextField("代理 IP 或域名，可带端口", text: $proxyAddress)
                            .browserAddressInput()
                        TextField("代理用户名（可选）", text: $username)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("代理密码（可选）", text: $password)
                            .privacySensitive()
                    } header: {
                        Text("自有 HTTPS CONNECT 代理")
                    } footer: {
                        Text("代理需提供与地址匹配的受信任证书。默认端口 443。网站看到的代理出口取决于服务器的实际路由。")
                    }
                }
                Section {
                    TextField("网站域名或 HTTPS 地址", text: $address)
                        .browserAddressInput()
                        .onSubmit { open() }
                    Button("打开网页") { open() }
                        .disabled(!vpn.showsConnectedPrivacyPolicy)
                } footer: {
                    Text(vpn.showsConnectedPrivacyPolicy
                         ? "关闭网页即结束本次临时浏览会话。"
                         : "请先回到首页连接 Cuven。隧道恢复后可重新打开网页。")
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("隐私浏览器")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: mode) { _, _ in error = nil; password = "" }
        .onChange(of: vpn.showsConnectedPrivacyPolicy) { _, connected in
            if !connected, session?.page.isLive == true {
                session = nil
                error = "VPN 连接已中断，本次网页会话已关闭。"
            }
        }
        .sheet(item: $session) { item in
            BrowserWindow(page: item.page, permit: { [weak vpn] in vpn?.browserTunnelIsConnected == true })
        }
    }

    private func open() {
        error = nil
        if mode == .preview {
            guard let ip = BrowserAddress.ip(simulatedIP) else {
                error = "请输入有效的 IPv4 或 IPv6 地址。"
                return
            }
            session = BrowserSession(page: .preview(ip))
            return
        }
        guard vpn.browserTunnelIsConnected else {
            error = "请在 Cuven 隧道连接后打开网页。"
            return
        }
        guard let url = BrowserAddress.httpsURL(address) else {
            error = "请输入 HTTPS 网址或网站域名。"
            return
        }
        var proxy: BrowserProxy?
        if mode == .proxy {
            guard let configured = BrowserProxy(address: proxyAddress, username: username, password: password) else {
                error = "请核对代理地址和端口。如果代理需要认证，请同时填写用户名和密码。"
                return
            }
            proxy = configured
            password = ""
        }
        session = BrowserSession(page: .website(url, proxy))
    }
}

private extension View {
    func browserAddressInput() -> some View {
        keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled().privacySensitive()
    }
}
