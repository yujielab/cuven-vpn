import Foundation

/// Only used to choose shared storage. Security.framework enforces the actual write grant.
enum KeychainAccessGroup {
    static func shared(between app: Bundle, and provider: Bundle) -> [String] {
        func groups(_ bundle: Bundle) -> [String] {
            guard let url = bundle.executableURL,
                  let image = try? Data(contentsOf: url, options: .mappedIfSafe) else { return [] }
            return signedGroups(in: image)
        }
        let providerGroups = Set(groups(provider))
        return groups(app).filter(providerGroups.contains)
    }

    static func signedGroups(in image: Data) -> [String] {
        let slices = nativeSlices(in: image)
        guard let first = slices.first else { return [] }
        var common = groups(inSlice: first)
        for slice in slices.dropFirst() {
            let allowed = Set(groups(inSlice: slice))
            common = common.filter(allowed.contains)
        }
        return common
    }

    private static func groups(inSlice slice: Data) -> [String] {
        guard let headerSize = slice.word(20, little: true), headerSize <= slice.count - 32,
              let commands = slice.word(16, little: true), commands <= headerSize / 8 else { return [] }
        var offset = 32
        for _ in 0..<commands {
            guard let type = slice.word(offset, little: true), let size = slice.word(offset + 4, little: true),
                  size >= 8, size <= 32 + headerSize - offset else { return [] }
            if type == 0x1d { // LC_CODE_SIGNATURE
                guard size >= 16, let start = slice.word(offset + 8, little: true),
                      let count = slice.word(offset + 12, little: true),
                      let signature = slice.part(start, count) else { return [] }
                return groups(inSignature: signature)
            }
            offset += size
        }
        return []
    }

    private static func nativeSlices(in image: Data) -> [Data] {
        if image.word(0) == 0xcffaedfe && image.count >= 32 { return [image] }
        guard let magic = image.word(0), magic == 0xcafebabe || magic == 0xcafebabf,
              let count = image.word(4) else { return [] }
        let stride = magic == 0xcafebabe ? 20 : 32
        guard count <= (image.count - 8) / stride else { return [] }
        #if arch(x86_64)
        let nativeCPU = 0x01000007
        #else
        let nativeCPU = 0x0100000c
        #endif
        var result: [Data] = []
        for i in 0..<count {
            let record = 8 + i * stride
            guard image.word(record) == nativeCPU else { continue }
            guard let start = image.word(record + (stride == 20 ? 8 : 12)),
                  let length = image.word(record + (stride == 20 ? 12 : 20)),
                  stride == 20 || (image.word(record + 8) == 0 && image.word(record + 16) == 0),
                  let slice = image.part(start, length), slice.count >= 32,
                  slice.word(0) == 0xcffaedfe, slice.word(4, little: true) == nativeCPU else { return [] }
            result.append(slice)
        }
        return result
    }

    private static func groups(inSignature signature: Data) -> [String] {
        guard signature.word(0) == 0xfade0cc0, let length = signature.word(4),
              length >= 12, length <= signature.count, let count = signature.word(8),
              count <= (length - 12) / 8 else { return [] }
        var xml: Data?
        var der: Data?
        for i in 0..<count {
            let record = 12 + i * 8
            guard let slot = signature.word(record), slot == 5 || slot == 7 else { continue }
            guard let offset = signature.word(record + 4), offset >= 12 + count * 8,
                  signature.word(offset) == (slot == 5 ? 0xfade7171 : 0xfade7172),
                  let size = signature.word(offset + 4), size >= 8, size <= 1_048_576, size <= length - offset,
                  let body = signature.part(offset + 8, size - 8) else { return [] }
            if slot == 7 {
                guard der == nil else { return [] }
                der = body
            } else {
                guard xml == nil else { return [] }
                xml = body
            }
        }
        let fields: [String: Any]
        if let der {
            guard let grants = DERGrants.fields(der) else { return [] }
            fields = grants
        } else {
            guard let xml, let grants = try? PropertyListSerialization.propertyList(from: xml, format: nil)
                    as? [String: Any] else { return [] }
            fields = grants
        }
        var candidates = fields["keychain-access-groups"] as? [String] ?? []
        if let identity = fields["application-identifier"] as? String { candidates.append(identity) }
        candidates += fields["com.apple.security.application-groups"] as? [String] ?? []
        var seen = Set<String>()
        return candidates.filter { !$0.isEmpty && !$0.contains("*") && !$0.contains("$(") && seen.insert($0).inserted }
    }
}

private extension Data {
    func word(_ offset: Int, little: Bool = false) -> Int? {
        guard offset >= 0, offset <= count - 4 else { return nil }
        var value = 0
        for i in 0..<4 {
            value = (value << 8) | Int(self[startIndex + offset + (little ? 3 - i : i)])
        }
        return value
    }

    func part(_ offset: Int, _ length: Int) -> Data? {
        guard offset >= 0, offset <= count, length >= 0, length <= count - offset else { return nil }
        return self[(startIndex + offset)..<(startIndex + offset + length)]
    }
}

/// Read the three string-valued signing grants without interpreting unrelated entitlements.
private enum DERGrants {
    private struct Element {
        let tag: UInt8
        let body: ArraySlice<UInt8>
    }

    private static func take(_ input: inout ArraySlice<UInt8>) -> Element? {
        guard let tag = input.popFirst(), let first = input.popFirst() else { return nil }
        var length = Int(first)
        if first >= 128 {
            let count = Int(first & 0x7f)
            guard (1...4).contains(count), input.count >= count else { return nil }
            length = 0
            for byte in input.prefix(count) { length = (length << 8) | Int(byte) }
            input = input.dropFirst(count)
        }
        guard length <= input.count else { return nil }
        let body = input.prefix(length)
        input = input.dropFirst(length)
        return Element(tag: tag, body: body)
    }

    static func fields(_ data: Data) -> [String: Any]? {
        var source = Array(data)[...]
        guard var dict = take(&source), source.isEmpty else { return nil }
        if dict.tag == 0x70 { // Versioned Apple DER entitlement dictionary
            var wrapped = dict.body
            guard let version = take(&wrapped), version.tag == 2, version.body.elementsEqual([1]),
                  let payload = take(&wrapped), wrapped.isEmpty else { return nil }
            dict = payload
        }
        guard dict.tag == 0x31 || dict.tag == 0xb0 else { return nil }
        var pairs = dict.body
        var fields: [String: Any] = [:]
        while !pairs.isEmpty {
            guard let pair = take(&pairs), pair.tag == 0x30 else { return nil }
            var contents = pair.body
            guard let key = take(&contents), key.tag == 0x0c,
                  let name = String(bytes: key.body, encoding: .utf8),
                  let value = take(&contents), contents.isEmpty else { return nil }
            switch name {
            case "application-identifier":
                guard fields[name] == nil, value.tag == 0x0c,
                      let id = String(bytes: value.body, encoding: .utf8) else { return nil }
                fields[name] = id
            case "keychain-access-groups", "com.apple.security.application-groups":
                guard fields[name] == nil, value.tag == 0x30 else { return nil }
                var list = value.body
                var names: [String] = []
                while !list.isEmpty {
                    guard let member = take(&list), member.tag == 0x0c,
                          let group = String(bytes: member.body, encoding: .utf8) else { return nil }
                    names.append(group)
                }
                fields[name] = names
            default: continue
            }
        }
        return fields
    }
}
