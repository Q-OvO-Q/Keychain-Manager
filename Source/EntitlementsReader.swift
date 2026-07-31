import Foundation

/// 从应用自身的 Mach-O 代码签名里读取 entitlements。
///
/// `embedded.mobileprovision` 只包含**申请签名时**声明的 keychain-access-groups。
/// 重签名工具在签名阶段注入的组（例如 LiveContainer 的 128 个
/// `TEAMID.com.kdt.livecontainer.shared.N`）不会写回描述文件，
/// 因此只解析描述文件永远列不全，用户只能手动逐个输入组名。
///
/// 代码签名里的 entitlements 才是内核实际执行的那一份，直接读它可以拿到完整列表。
enum EntitlementsReader {

    // Mach-O
    private static let magic64: UInt32 = 0xfeed_facf
    private static let magic32: UInt32 = 0xfeed_face
    private static let fatMagicSwapped: UInt32 = 0xbeba_feca   // 0xcafebabe 按小端读出的结果
    private static let fatMagic: UInt32 = 0xcafe_babe
    private static let loadCommandCodeSignature: UInt32 = 0x1d

    // 代码签名（全部为大端）
    private static let superBlobMagic: UInt32 = 0xfade_0cc0
    private static let entitlementsMagic: UInt32 = 0xfade_7171

    /// 防御性上限，避免文件损坏时进入超长循环
    private static let maxLoadCommands = 512
    private static let maxBlobs = 64
    private static let maxFatArchitectures = 16

    // MARK: - 对外接口

    /// 完整的 entitlements 字典；解析失败返回 nil
    static func parse() -> [String: Any]? {
        guard let url = Bundle.main.executableURL,
              let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            return nil
        }
        return entitlements(inMachO: data)
    }

    /// 可用作 `kSecAttrAccessGroup` 的全部取值，按 entitlements 里的原始顺序去重。
    ///
    /// 除 `keychain-access-groups` 外，`application-identifier` 本身就是应用的默认组，
    /// 而 iOS 上 App Group 标识符同样可以当作 keychain access group 使用。
    static func accessGroups(from entitlements: [String: Any]) -> [String] {
        var groups: [String] = []

        if let declared = entitlements["keychain-access-groups"] as? [String] {
            groups += declared
        }
        if let identifier = entitlements["application-identifier"] as? String {
            groups.append(identifier)
        }
        if let appGroups = entitlements["com.apple.security.application-groups"] as? [String] {
            groups += appGroups
        }

        var seen = Set<String>()
        return groups.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    // MARK: - Mach-O

    private static func entitlements(inMachO data: Data) -> [String: Any]? {
        guard let magic = data.readUInt32(at: 0) else { return nil }

        switch magic {
        case magic64:
            return entitlements(inThinImage: data, headerSize: 32)
        case magic32:
            return entitlements(inThinImage: data, headerSize: 28)
        case fatMagicSwapped, fatMagic:
            return entitlements(inFatImage: data)
        default:
            return nil
        }
    }

    /// 通用二进制：逐个架构切片尝试，取第一个能解析出 entitlements 的
    private static func entitlements(inFatImage data: Data) -> [String: Any]? {
        guard let count = data.readUInt32(at: 4, bigEndian: true) else { return nil }

        for index in 0..<Int(min(count, UInt32(maxFatArchitectures))) {
            let entry = 8 + index * 20   // fat_arch: cputype, cpusubtype, offset, size, align
            guard let offset = data.readUInt32(at: entry + 8, bigEndian: true),
                  let size = data.readUInt32(at: entry + 12, bigEndian: true),
                  let slice = data.slice(from: Int(offset), length: Int(size)) else {
                continue
            }
            if let found = entitlements(inMachO: slice) { return found }
        }
        return nil
    }

    private static func entitlements(inThinImage data: Data, headerSize: Int) -> [String: Any]? {
        guard let commandCount = data.readUInt32(at: 16) else { return nil }

        var cursor = headerSize
        for _ in 0..<Int(min(commandCount, UInt32(maxLoadCommands))) {
            guard let command = data.readUInt32(at: cursor),
                  let commandSize = data.readUInt32(at: cursor + 4),
                  commandSize >= 8 else {
                return nil
            }

            if command == loadCommandCodeSignature {
                // linkedit_data_command: cmd, cmdsize, dataoff, datasize
                guard let offset = data.readUInt32(at: cursor + 8),
                      let size = data.readUInt32(at: cursor + 12) else {
                    return nil
                }
                return entitlements(inSignature: data, offset: Int(offset), size: Int(size))
            }

            cursor += Int(commandSize)
        }
        return nil
    }

    // MARK: - 代码签名

    /// 代码签名是一个 SuperBlob：头部之后是若干 (type, offset) 索引，
    /// 各 blob 自带 magic。entitlements 是其中 magic 为 0xfade7171 的那一个，
    /// 内容是 8 字节头 + XML plist。所有整数均为大端。
    private static func entitlements(inSignature data: Data,
                                    offset: Int,
                                    size: Int) -> [String: Any]? {
        guard size > 0, data.slice(from: offset, length: size) != nil,
              let magic = data.readUInt32(at: offset, bigEndian: true),
              magic == superBlobMagic,
              let count = data.readUInt32(at: offset + 8, bigEndian: true) else {
            return nil
        }

        for index in 0..<Int(min(count, UInt32(maxBlobs))) {
            let indexEntry = offset + 12 + index * 8   // (type, offset)
            guard let blobOffset = data.readUInt32(at: indexEntry + 4, bigEndian: true) else { continue }

            let blobStart = offset + Int(blobOffset)
            guard let blobMagic = data.readUInt32(at: blobStart, bigEndian: true),
                  blobMagic == entitlementsMagic,
                  let blobLength = data.readUInt32(at: blobStart + 4, bigEndian: true),
                  blobLength > 8,
                  let plistData = data.slice(from: blobStart + 8, length: Int(blobLength) - 8) else {
                continue
            }

            if let object = try? PropertyListSerialization.propertyList(from: plistData, format: nil),
               let plist = object as? [String: Any] {
                return plist
            }
        }
        return nil
    }
}

// MARK: - 带边界检查的二进制读取

private extension Data {

    /// 读 4 字节整数。越界返回 nil —— 解析的是磁盘文件，任何字段都不可信。
    func readUInt32(at offset: Int, bigEndian: Bool = false) -> UInt32? {
        guard offset >= 0, offset &+ 4 <= count else { return nil }

        let base = startIndex + offset
        var value: UInt32 = 0
        for position in 0..<4 {
            let byte = UInt32(self[base + position])
            if bigEndian {
                value = (value << 8) | byte
            } else {
                value |= byte << (8 * position)
            }
        }
        return value
    }

    func slice(from offset: Int, length: Int) -> Data? {
        guard offset >= 0, length > 0, offset &+ length <= count else { return nil }
        let base = startIndex + offset
        return subdata(in: base..<(base + length))
    }
}
