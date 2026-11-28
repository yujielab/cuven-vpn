import Foundation
import XCTest
@testable import Cuven

final class SigningKeychainGroupTests: XCTestCase {
    private let custom = "TEST123456.signer-selected"
    private let identity = "TEST123456.org.example.cuven"

    private func word(_ value: Int, little: Bool = false) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * (little ? $0 : (3 - $0)))) }
    }

    private func image(slot: Int, body: [UInt8]) -> Data {
        let blob = word(slot == 7 ? 0xfade7172 : 0xfade7171) + word(8 + body.count) + body
        let signature = word(0xfade0cc0) + word(20 + blob.count) + word(1) + word(slot) + word(20) + blob
        let header = [0xfeedfacf, 0x0100000c, 0, 2, 1, 16, 0, 0].flatMap { word($0, little: true) }
        let command = [0x1d, 16, 48, signature.count].flatMap { word($0, little: true) }
        return Data(header + command + signature)
    }

    func testXMLNamesComeFromTheSignatureAndKeepSignerOrder() throws {
        let values: [String: Any] = [
            "keychain-access-groups": [custom, custom, "TEST123456.*"],
            "application-identifier": identity
        ]
        let plist = try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
        let signed = image(slot: 5, body: Array(plist))
        XCTAssertEqual(KeychainAccessGroup.signedGroups(in: signed), [custom, identity])
        for length in [0, 4, 31, 47, signed.count - 1] {
            XCTAssertTrue(KeychainAccessGroup.signedGroups(in: signed.prefix(length)).isEmpty)
        }
    }

    func testDEROnlySignaturesAndMalformedLengths() {
        func element(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] { [tag, UInt8(body.count)] + body }
        func string(_ text: String) -> [UInt8] { element(0x0c, Array(text.utf8)) }
        let pair = element(0x30, string("keychain-access-groups") + element(0x30, string(custom)))
        let legacy = element(0x31, pair)
        let wrapped = element(0x70, element(2, [1]) + element(0xb0, pair))
        for body in [legacy, wrapped] {
            XCTAssertEqual(KeychainAccessGroup.signedGroups(in: image(slot: 7, body: body)), [custom])
        }
        XCTAssertTrue(KeychainAccessGroup.signedGroups(in: image(slot: 7, body: [0x31, 0x84, 255, 255, 255, 255])).isEmpty)
    }

    #if os(macOS)
    func testActualAppleCodeSignature() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let values: [String: Any] = ["keychain-access-groups": [custom], "application-identifier": identity]
        let plist = dir.appendingPathComponent("grants.plist")
        try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0).write(to: plist)
        let source = dir.appendingPathComponent("plain.c")
        try Data("int main(void) { return 0; }".utf8).write(to: source)
        let exe = dir.appendingPathComponent("fixture")
        for args in [["/usr/bin/xcrun", "clang", source.path, "-o", exe.path],
                     ["/usr/bin/codesign", "-f", "-s", "-", "--generate-entitlement-der", "--entitlements", plist.path, exe.path]] {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: args[0])
            task.arguments = Array(args.dropFirst())
            try task.run()
            task.waitUntilExit()
            XCTAssertEqual(task.terminationStatus, 0)
        }
        XCTAssertEqual(KeychainAccessGroup.signedGroups(in: try Data(contentsOf: exe)), [custom, identity])
    }
    #endif
}
