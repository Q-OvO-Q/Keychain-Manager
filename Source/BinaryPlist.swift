import Foundation

/// NSKeyedArchiver 里的对象引用。
///
/// Foundation 没有能在 Swift 侧读写 UID 的公开类型：`PropertyListSerialization`
/// 读出来的 UID 是不透明对象，取不到里面的整数；试过「转成 XML 再读回来把 UID 摊成
/// `CF$UID` 字典」这条路，实机上整份归档全都解不开。所以 binary plist 的读写整个自己来，
/// UID 就是这里这个普通结构体。
struct ArchiveUID: Hashable {
    let value: UInt64
}

/// binary plist 里的 16 字节整数。
///
/// Swift 侧没有能装下它的数值类型：`NSNumber` 最宽到 64 位，CoreFoundation 内部
/// 那个 `kCFNumberSInt128Type` 没有公开出来。所以原始字节原样留着，写回时照抄，
/// 显示时自己算成十进制 —— 只读，因为编辑框里的值没法转回 128 位。
///
/// 实测语料 314 份 plist、13375 个对象里一次都没出现过。留着它不是为了支持编辑，
/// 是为了别让一个不认识的对象把整份负载的解析拖垮 —— 那会让整条条目退回只剩十六进制。
struct WideInteger {

    /// 16 字节，大端，二进制补码
    let bytes: Data

    var decimalDescription: String {
        var magnitude = [UInt8](bytes)
        let negative = (magnitude.first ?? 0) & 0x80 != 0

        if negative {
            // 取绝对值：按位取反再加一
            for index in magnitude.indices { magnitude[index] = ~magnitude[index] }
            var carry = 1
            for index in magnitude.indices.reversed() {
                let sum = Int(magnitude[index]) + carry
                magnitude[index] = UInt8(sum & 0xFF)
                carry = sum >> 8
            }
        }

        // 反复除以 10 取余数。余数 < 10，所以中间量不会溢出
        var digits = ""
        while magnitude.contains(where: { $0 != 0 }) {
            var remainder = 0
            for index in magnitude.indices {
                let current = remainder << 8 | Int(magnitude[index])
                magnitude[index] = UInt8(current / 10)
                remainder = current % 10
            }
            digits.append(Character(UnicodeScalar(UInt8(remainder) + 48)))
        }

        if digits.isEmpty { return "0" }
        return (negative ? "-" : "") + String(digits.reversed())
    }
}

/// 自己实现的 binary plist 编解码。
///
/// 只处理二进制格式；XML plist 仍然交给 `PropertyListSerialization`（它对 XML 没问题，
/// 而且实测语料里没有 XML 归档）。
///
/// 解析结果用的是普通 Foundation 类型，UID 用 `ArchiveUID`：
/// `NSNull` / `NSNumber` / `Date` / `Data` / `String` / `[Any]` / `[AnyHashable: Any]`。
/// 这样上层的路径定位和写回逻辑不用为它单独开一套。
enum BinaryPlist {

    enum Failure: LocalizedError {
        case malformed
        case unsupported(String)

        var errorDescription: String? {
            switch self {
            case .malformed: return "binary plist 结构损坏"
            case .unsupported(let what): return "无法编码的类型：\(what)"
            }
        }
    }

    static let magic = Array("bplist00".utf8)

    // MARK: - 读

    static func parse(_ data: Data) -> Any? {
        let bytes = [UInt8](data)
        // 头 8 字节 + 尾 32 字节 trailer，再少就不可能是完整的
        guard bytes.count >= 40, bytes.starts(with: magic) else { return nil }

        let trailer = bytes.count - 32
        let offsetSize = Int(bytes[trailer + 6])
        let refSize = Int(bytes[trailer + 7])
        guard let rawCount = readBigEndian(bytes, at: trailer + 8, size: 8),
              let rawTop = readBigEndian(bytes, at: trailer + 16, size: 8),
              let rawTable = readBigEndian(bytes, at: trailer + 24, size: 8) else { return nil }

        let count = Int(clamping: rawCount)
        let top = Int(clamping: rawTop)
        let tableStart = Int(clamping: rawTable)

        guard (1...8).contains(offsetSize), (1...8).contains(refSize),
              count > 0, count <= 4_000_000, top < count,
              tableStart >= magic.count,
              // 偏移表必须整个落在 trailer 之前
              count <= (trailer - tableStart) / offsetSize else { return nil }

        var offsets = [Int]()
        offsets.reserveCapacity(count)
        for index in 0..<count {
            guard let value = readBigEndian(bytes, at: tableStart + index * offsetSize,
                                            size: offsetSize),
                  value < UInt64(trailer) else { return nil }
            offsets.append(Int(value))
        }

        let reader = Reader(bytes: bytes, offsets: offsets, refSize: refSize, limit: trailer)
        return reader.object(at: top, depth: 0)
    }

    private final class Reader {
        let bytes: [UInt8]
        let offsets: [Int]
        let refSize: Int
        let limit: Int
        /// 解析是把引用图展开成树，同一个对象被引用多次就会展开多份。
        /// 归档里的引用是 UID（叶子，不展开）所以没事，但坏掉或恶意构造的
        /// plist 可以靠层层共享撑爆内存，给个总量上限兜底。
        private var budget = 2_000_000

        init(bytes: [UInt8], offsets: [Int], refSize: Int, limit: Int) {
            self.bytes = bytes
            self.offsets = offsets
            self.refSize = refSize
            self.limit = limit
        }

        func object(at index: Int, depth: Int) -> Any? {
            guard depth < 64, index >= 0, index < offsets.count else { return nil }
            budget -= 1
            guard budget > 0 else { return nil }
            let start = offsets[index]
            guard start < limit else { return nil }

            let marker = bytes[start]
            let high = marker >> 4
            let low = Int(marker & 0x0F)

            switch marker {
            case 0x00, 0x0F: return NSNull()
            case 0x08: return NSNumber(value: false)
            case 0x09: return NSNumber(value: true)
            default: break
            }

            switch high {
            case 0x1:
                let size = 1 << low
                if size == 16 {
                    guard start + 17 <= limit else { return nil }
                    return WideInteger(bytes: Data(bytes[(start + 1)..<(start + 17)]))
                }
                guard size <= 8, let raw = readBigEndian(bytes, at: start + 1, size: size, limit: limit)
                else { return nil }
                // 8 字节整数是有符号的，其余按无符号读
                return size == 8 ? NSNumber(value: Int64(bitPattern: raw)) : NSNumber(value: raw)

            case 0x2:
                let size = 1 << low
                guard let raw = readBigEndian(bytes, at: start + 1, size: size, limit: limit)
                else { return nil }
                if size == 4 { return NSNumber(value: Float(bitPattern: UInt32(truncatingIfNeeded: raw))) }
                if size == 8 { return NSNumber(value: Double(bitPattern: raw)) }
                return nil

            case 0x3:
                guard marker == 0x33,
                      let raw = readBigEndian(bytes, at: start + 1, size: 8, limit: limit)
                else { return nil }
                return Date(timeIntervalSinceReferenceDate: Double(bitPattern: raw))

            case 0x8:
                let size = low + 1
                guard size <= 8, let raw = readBigEndian(bytes, at: start + 1, size: size, limit: limit)
                else { return nil }
                return ArchiveUID(value: raw)

            case 0x4, 0x5, 0x6, 0xA, 0xD:
                guard let (count, body) = count(after: start, low: low) else { return nil }
                return container(high: high, count: count, body: body, depth: depth)

            default:
                return nil
            }
        }

        /// 计数放在低 4 位；等于 0xF 时后面跟一个整数对象才是真正的长度
        private func count(after start: Int, low: Int) -> (Int, Int)? {
            guard low == 0x0F else { return (low, start + 1) }
            let next = start + 1
            guard next < limit, bytes[next] >> 4 == 0x1 else { return nil }
            let size = 1 << Int(bytes[next] & 0x0F)
            guard size <= 8, let raw = readBigEndian(bytes, at: next + 1, size: size, limit: limit),
                  raw <= UInt64(limit) else { return nil }
            return (Int(raw), next + 1 + size)
        }

        private func container(high: UInt8, count: Int, body: Int, depth: Int) -> Any? {
            switch high {
            case 0x4:
                guard body + count <= limit else { return nil }
                return Data(bytes[body..<(body + count)])

            case 0x5:
                guard body + count <= limit else { return nil }
                return String(bytes: bytes[body..<(body + count)], encoding: .ascii)

            case 0x6:
                guard body + count * 2 <= limit else { return nil }
                return String(bytes: bytes[body..<(body + count * 2)], encoding: .utf16BigEndian)

            // 集合（0xC）只当数组读的话，写回去就变成数组了 —— 那是静默改数据。
            // 这个标记只有 CFSet 会产生，NSKeyedArchiver 不会，实测语料里 0 次。
            // 与其留一条有损的写回路径，不如整份判失败：条目退回只显示十六进制，
            // 至少不会把集合悄悄写成数组。
            case 0xA:
                guard let refs = references(at: body, count: count) else { return nil }
                var result = [Any]()
                result.reserveCapacity(count)
                for ref in refs {
                    guard let child = object(at: ref, depth: depth + 1) else { return nil }
                    result.append(child)
                }
                return result

            case 0xD:
                guard let keyRefs = references(at: body, count: count),
                      let valueRefs = references(at: body + count * refSize, count: count)
                else { return nil }
                var result = [AnyHashable: Any]()
                for (keyRef, valueRef) in zip(keyRefs, valueRefs) {
                    // 归档里的键一律是字符串。不是的话宁可整份判失败，
                    // 也不要凑合成字符串——那样写回去就跟原文不是一回事了
                    guard let key = object(at: keyRef, depth: depth + 1) as? String,
                          let value = object(at: valueRef, depth: depth + 1) else { return nil }
                    result[key] = value
                }
                return result

            default:
                return nil
            }
        }

        private func references(at start: Int, count: Int) -> [Int]? {
            guard count >= 0, start >= 0, start + count * refSize <= limit else { return nil }
            var refs = [Int]()
            refs.reserveCapacity(count)
            for index in 0..<count {
                guard let raw = readBigEndian(bytes, at: start + index * refSize,
                                              size: refSize, limit: limit) else { return nil }
                refs.append(Int(clamping: raw))
            }
            return refs
        }
    }

    private static func readBigEndian(_ bytes: [UInt8], at offset: Int, size: Int,
                                      limit: Int? = nil) -> UInt64? {
        let end = limit ?? bytes.count
        guard size > 0, size <= 8, offset >= 0, offset + size <= end else { return nil }
        var value: UInt64 = 0
        for index in 0..<size {
            value = (value << 8) | UInt64(bytes[offset + index])
        }
        return value
    }

    // MARK: - 写

    /// 不做对象去重（Apple 的实现会把相同对象合并成一份）。那纯粹是存储优化，
    /// 数组顺序和引用值都不受影响，归档语义完全一致，代价是文件略大一点。
    static func serialize(_ root: Any) throws -> Data {
        var table = [Node?]()
        _ = try flatten(root, into: &table)
        let nodes = table.compactMap { $0 }
        guard nodes.count == table.count else { throw Failure.malformed }

        let refSize = byteWidth(for: UInt64(max(1, nodes.count - 1)))
        var body = Data(magic)
        var offsets = [Int]()
        offsets.reserveCapacity(nodes.count)

        for node in nodes {
            offsets.append(body.count)
            try encode(node, refSize: refSize, into: &body)
        }

        let tableStart = body.count
        let offsetSize = byteWidth(for: UInt64(max(1, tableStart)))
        for offset in offsets {
            append(UInt64(offset), width: offsetSize, to: &body)
        }

        body.append(contentsOf: [UInt8](repeating: 0, count: 6))   // 5 保留 + sortVersion
        body.append(UInt8(offsetSize))
        body.append(UInt8(refSize))
        append(UInt64(nodes.count), width: 8, to: &body)
        append(0, width: 8, to: &body)                             // 根对象固定是 0
        append(UInt64(tableStart), width: 8, to: &body)
        return body
    }

    private enum Node {
        case leaf(Any)
        case array([Int])
        case dictionary(keys: [Int], values: [Int])
    }

    /// 深度优先占位：先给当前节点占下标，子节点紧随其后，和解析时的顺序对应
    private static func flatten(_ value: Any, into table: inout [Node?]) throws -> Int {
        let index = table.count
        table.append(nil)

        if let array = value as? [Any] {
            var refs = [Int]()
            refs.reserveCapacity(array.count)
            for child in array {
                refs.append(try flatten(child, into: &table))
            }
            table[index] = .array(refs)
            return index
        }

        if let dictionary = value as? [AnyHashable: Any] {
            // 显式取 String 而不是 String(describing:)：后者对 AnyHashable 的行为
            // 依赖 description 的实现，写键名这种事不能靠它。取不出来就报错，
            // 总比把键写成别的东西、悄悄改掉归档内容强。
            let pairs = try dictionary
                .map { pair -> (String, Any) in
                    guard let key = pair.key as? String else {
                        throw Failure.unsupported("非字符串的字典键")
                    }
                    return (key, pair.value)
                }
                // 键顺序在 plist 里不影响语义，排一下让输出稳定可比
                .sorted { $0.0 < $1.0 }
            var keyRefs = [Int]()
            var valueRefs = [Int]()
            for pair in pairs {
                keyRefs.append(try flatten(pair.0, into: &table))
            }
            for pair in pairs {
                valueRefs.append(try flatten(pair.1, into: &table))
            }
            table[index] = .dictionary(keys: keyRefs, values: valueRefs)
            return index
        }

        table[index] = .leaf(value)
        return index
    }

    private static func encode(_ node: Node, refSize: Int, into body: inout Data) throws {
        switch node {
        case .array(let refs):
            appendCount(0xA, refs.count, to: &body)
            for ref in refs { append(UInt64(ref), width: refSize, to: &body) }

        case .dictionary(let keys, let values):
            appendCount(0xD, keys.count, to: &body)
            for ref in keys { append(UInt64(ref), width: refSize, to: &body) }
            for ref in values { append(UInt64(ref), width: refSize, to: &body) }

        case .leaf(let value):
            try encodeLeaf(value, into: &body)
        }
    }

    private static func encodeLeaf(_ value: Any, into body: inout Data) throws {
        if value is NSNull {
            body.append(0x00)
            return
        }

        if let wide = value as? WideInteger, wide.bytes.count == 16 {
            body.append(0x14)
            body.append(wide.bytes)
            return
        }

        if let uid = value as? ArchiveUID {
            let width = byteWidth(for: uid.value)
            body.append(0x80 | UInt8(width - 1))
            append(uid.value, width: width, to: &body)
            return
        }

        if let date = value as? Date {
            body.append(0x33)
            append(date.timeIntervalSinceReferenceDate.bitPattern, width: 8, to: &body)
            return
        }

        if let bytes = value as? Data {
            appendCount(0x4, bytes.count, to: &body)
            body.append(bytes)
            return
        }

        if let text = value as? String {
            if let ascii = text.data(using: .ascii) {
                appendCount(0x5, ascii.count, to: &body)
                body.append(ascii)
            } else {
                let utf16 = Array(text.utf16)
                appendCount(0x6, utf16.count, to: &body)
                for unit in utf16 { append(UInt64(unit), width: 2, to: &body) }
            }
            return
        }

        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                body.append(number.boolValue ? 0x09 : 0x08)
                return
            }
            if CFNumberIsFloatType(number as CFNumber) {
                body.append(0x23)
                append(number.doubleValue.bitPattern, width: 8, to: &body)
                return
            }
            let signed = number.int64Value
            if signed < 0 {
                // 负数只能用 8 字节有符号形式
                body.append(0x13)
                append(UInt64(bitPattern: signed), width: 8, to: &body)
            } else {
                let width = byteWidth(for: UInt64(signed))
                body.append(0x10 | UInt8(log2Width(width)))
                append(UInt64(signed), width: width, to: &body)
            }
            return
        }

        throw Failure.unsupported(String(describing: type(of: value)))
    }

    private static func appendCount(_ high: UInt8, _ count: Int, to body: inout Data) {
        if count < 0x0F {
            body.append(high << 4 | UInt8(count))
            return
        }
        body.append(high << 4 | 0x0F)
        let width = byteWidth(for: UInt64(count))
        body.append(0x10 | UInt8(log2Width(width)))
        append(UInt64(count), width: width, to: &body)
    }

    private static func append(_ value: UInt64, width: Int, to body: inout Data) {
        for index in stride(from: width - 1, through: 0, by: -1) {
            body.append(UInt8(truncatingIfNeeded: value >> (UInt64(index) * 8)))
        }
    }

    /// 整数编码只允许 1 / 2 / 4 / 8 字节
    private static func byteWidth(for value: UInt64) -> Int {
        if value <= 0xFF { return 1 }
        if value <= 0xFFFF { return 2 }
        if value <= 0xFFFF_FFFF { return 4 }
        return 8
    }

    private static func log2Width(_ width: Int) -> Int {
        switch width {
        case 1: return 0
        case 2: return 1
        case 4: return 2
        default: return 3
        }
    }
}
