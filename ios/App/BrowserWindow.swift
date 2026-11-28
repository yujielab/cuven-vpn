import Network
import NetworkExtension
import SwiftUI
import WebKit

@MainActor
final class BrowserTab: NSObject, ObservableObject, WKNavigationDelegate {
    let webView: WKWebView
    let page: BrowserPage
    private let permit: @MainActor () -> Bool
    private var started = false
    private var closed = false
    @Published var address = ""
    @Published var error: String?
    @Published private(set) var canGoBack = false
    @Published private(set) var canGoForward = false

    init(page: BrowserPage, permit: @escaping @MainActor () -> Bool) {
        self.page = page
        self.permit = permit
        let config = WKWebViewConfiguration()
        let store = WKWebsiteDataStore.nonPersistent()
        if case let .website(_, proxy?) = page {
            let endpoint = NWEndpoint.hostPort(host: .init(proxy.host), port: .init(rawValue: proxy.port)!)
            var relay = ProxyConfiguration(httpCONNECTProxy: endpoint, tlsOptions: NWProtocolTLS.Options())
            relay.allowFailover = false
            if !proxy.username.isEmpty {
                relay.applyCredential(username: proxy.username, password: proxy.password)
            }
            store.proxyConfigurations = [relay]
        }
        config.websiteDataStore = store
        config.defaultWebpagePreferences.allowsContentJavaScript = page.isLive
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        webView = WKWebView(frame: .zero, configuration: config)
        super.init()
        webView.navigationDelegate = self
        webView.allowsLinkPreview = false
        webView.allowsBackForwardNavigationGestures = page.isLive
    }

    func start() {
        guard !started, !closed else { return }
        started = true
        switch page {
        case .website(let url, _):
            address = url.absoluteString
            navigate()
        case .preview(let value):
            guard let ip = BrowserAddress.ip(value) else { return }
            webView.loadHTMLString("""
                <!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
                <style>:root{color-scheme:light dark}body{font:1.1rem -apple-system,sans-serif;padding:1rem}code{overflow-wrap:anywhere}</style>
                <title>本地 IP 预览</title></head><body><h1>本地 IP 预览</h1>
                <p>此页显示你输入的模拟地址。</p><p><code>\(ip)</code></p></body></html>
                """, baseURL: nil)
        }
    }

    func navigate() {
        guard !closed, page.isLive, permit() else { return }
        guard let url = BrowserAddress.httpsURL(address) else {
            error = "请输入有效的 HTTPS 地址。"
            return
        }
        error = nil
        webView.load(URLRequest(url: url))
    }

    func close() {
        guard !closed else { return }
        closed = true
        webView.stopLoading()
        webView.navigationDelegate = nil
        // A finished document can still run scripts while its sheet is dismissing.
        webView.loadHTMLString("""
            <!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'none'">
            <title>浏览已结束</title>
            """, baseURL: nil)
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard !closed, let url = action.request.url else { decisionHandler(.cancel); return }
        if !page.isLive {
            decisionHandler(url.absoluteString == "about:blank" ? .allow : .cancel)
            return
        }
        guard permit(), action.targetFrame != nil, url.scheme?.lowercased() == "https",
              url.user == nil, url.password == nil else {
            if action.targetFrame?.isMainFrame == true { error = "当前连接或网址不符合 HTTPS 浏览条件。" }
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) {
        if page.isLive, let url = webView.url { address = url.absoluteString }
        canGoBack = webView.canGoBack
        canGoForward = webView.canGoForward
        error = nil
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        showFailure(error)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        showFailure(error)
    }

    private func showFailure(_ failure: Error) {
        let ns = failure as NSError
        guard !closed, !(ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled) else { return }
        error = "网页未能载入。请核对网址、VPN 或代理设置。"
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        error = "网页进程已停止。可点「前往」重新载入。"
    }
}

private struct BrowserSurface: UIViewRepresentable {
    let tab: BrowserTab
    func makeUIView(context: Context) -> WKWebView { tab.webView }
    func updateUIView(_ view: WKWebView, context: Context) {}
}

struct BrowserWindow: View {
    @StateObject private var tab: BrowserTab
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @FocusState private var editing: Bool
    private let permit: @MainActor () -> Bool

    init(page: BrowserPage, permit: @escaping @MainActor () -> Bool) {
        self.permit = permit
        _tab = StateObject(wrappedValue: BrowserTab(page: page, permit: permit))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if tab.page.isLive {
                    HStack {
                        TextField("HTTPS 地址", text: $tab.address)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .focused($editing).onSubmit { tab.navigate() }
                            .privacySensitive()
                        Button("前往") { editing = false; tab.navigate() }
                    }
                    .padding(.horizontal).padding(.vertical, 8)
                    Divider()
                }
                if let error = tab.error { Text(error).font(.footnote).padding(8) }
                BrowserSurface(tab: tab)
            }
            .navigationTitle(tab.page.isLive ? "隐私浏览器" : "本地预览")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { tab.close(); dismiss() }
                }
                if tab.page.isLive {
                    ToolbarItemGroup(placement: .bottomBar) {
                        Button { tab.webView.goBack() } label: { Image(systemName: "chevron.backward") }
                            .accessibilityLabel("上一页").disabled(!tab.canGoBack)
                        Spacer()
                        Button { tab.webView.goForward() } label: { Image(systemName: "chevron.forward") }
                            .accessibilityLabel("下一页").disabled(!tab.canGoForward)
                    }
                }
            }
        }
        .onAppear { tab.start() }
        .onDisappear { tab.close() }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            if tab.page.isLive && !permit() { tab.close(); dismiss() }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { tab.close(); dismiss() }
        }
        .accessibilityHidden(scenePhase != .active)
        .overlay {
            if scenePhase != .active {
                Color(uiColor: .systemBackground).ignoresSafeArea()
                    .overlay { Label("Cuven", systemImage: "lock.shield") }
            }
        }
    }
}
