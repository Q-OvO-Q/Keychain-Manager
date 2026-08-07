import Foundation
import Security

// MARK: - 模型

/// 解析出来的一个可编辑叶子
struct DecodedField: Identifiable {

    enum Kind {
        case string, integer, real, boolean, date, data, null

        var isEditable: Bool {
            switch self {
            case .string, .integer, .real, .boolean: return true
            case .date, .data, .null: return false
            }
        }

        var hint: String {
            switch self {
            case .string: return "文本"
            case .integer: return "整数"
            case .real: return "小数"
            case .boolean: return "开关"
            case .date: return "日期"
            case .data: return "二进制"
            case .null: return "空"
            }
        }
    }

    let id: String
    let label: String
    let kind: Kind
    let value: String
    fileprivate let location: FieldLocation
}

/// 叶子在整份 plist / JSON 里的存放位置。归档也用同一套：
/// 一个被引用的对象就在 `$objects[i]`，路径写成 `.key("$objects"), .index(i), …`。
///
/// 不能只记 `$objects` 下标 —— 归档里有大量值是**内联**存的而不是单独占一格：
/// `NSMutableString` 是 `{$class: UID, NS.string: "…"}`，自定义类的小整数也直接
/// 写在实例字典里（`{gracePeriod: 0, …}`）。只认下标会漏掉这些，实测 309 条归档
/// 里可编辑字段会从 2110 个掉到 1068 个，72 条整条都解不出可改的东西。
fileprivate typealias FieldLocation = [PathComponent]

fileprivate enum PathComponent {
    case key(String)
    case index(Int)

    var token: String {
        switch self {
        case .key(let name): return name
        case .index(let offset): return String(offset)
        }
    }
}

fileprivate enum EditPlan {
    /// 存的是**原始**解析结果，里面的 UID 仍是不透明对象，原样交回序列化器
    case propertyList(Any, PropertyListSerialization.PropertyListFormat)
    case json(Any)
    /// 字段表：每项是 ["n": 字段号, "w": 线型, "v": 值]
    case protobuf([Any])
}

struct DecodedPayload {
    let formatName: String
    let text: String
    let fields: [DecodedField]
    fileprivate let plan: EditPlan?

    var isEditable: Bool {
        plan != nil && fields.contains { $0.kind.isEditable }
    }
}

enum DecodeEditError: LocalizedError {
    case notEditable
    case noChanges
    case badNumber(label: String, expected: String)
    case pathBroken(label: String)
    case encodingFailed(String)
    case verificationFailed(String)

    var errorDescription: String? {
        switch self {
        case .notEditable:
            return "这段数据的格式不支持按字段保存。"
        case .noChanges:
            return "没有改动需要保存。"
        case .badNumber(let label, let expected):
            return "「\(label)」需要填\(expected)。"
        case .pathBroken(let label):
            return "「\(label)」在数据里的位置已失效，请重新打开该条目。"
        case .encodingFailed(let reason):
            return "重新编码失败：\(reason)"
        case .verificationFailed(let reason):
            return "重新编码后的数据没通过自检，已取消保存，原数据未改动。（\(reason)）"
        }
    }
}

// MARK: - 解析

/// 把条目数据里那些「看着是二进制、其实有结构」的内容解析成可读、可改的形式。
///
/// 对着一份 1447 条的完整导出统计过：binary plist 313 条（其中 309 条是归档、
/// 78 条含第三方类）、JSON 191 条、DER 53 条、protobuf 22 条、纯文本 576 条，
/// 其余是空值和无结构的密钥/哈希（40 条正好 32 字节，就是 AES 密钥本身）。
///
/// 归档必须**自己解 UID 引用图**，不能交给 `NSKeyedUnarchiver`：那 78 条里的
/// `FIRInstallationsStoredItem`、`OIDAuthState`、`EMMLoginInfo` 等类本 App 里
/// 根本不存在，`NSKeyedUnarchiver` 一律解不出来。自己解还有个附带好处 ——
/// 能记下每个叶子的存放路径，写回时只改那一处，引用图原封不动。
///
/// 不做的事：按 Windows-1252 之类的单字节编码硬解。这条查过实据，不是想当然：
/// 整份导出 83 万字节里 cp1252 未定义的只有 0.45%，随机字节的「解码成功率」97.9% ——
/// 什么都能解，就等于什么都没判。而且它解出来的不是信息：那 12 条「按 cp1252 看
/// 像文本」的条目实际是 protobuf，cp1252 只是把长度前缀 `f0`、`c3` 涂成了 `ð`、`Ã`。
/// 真正该做的是认出 protobuf，那 12 条里装的是 JWT 和 Tink 密钥集。
/// 另外也试过 UTF-16：整份导出 0 条命中。
enum DataDecoder {

    /// 只读全文的长度上限：详情页塞不下更多，还会拖慢滚动
    private static let renderLimit = 20_000
    private static let maxDepth = 24

    static func decode(_ data: Data) -> DecodedPayload? {
        guard !data.isEmpty else { return nil }
        let found = decodePropertyList(data)
            ?? decodeJSON(data)
            ?? decodeDER(data)
            ?? decodeProtobuf(data)
        guard let payload = found else { return nil }
        guard payload.text.count > renderLimit else { return payload }
        return DecodedPayload(formatName: payload.formatName,
                              text: payload.text.prefix(renderLimit) + "\n…（内容过长，已截断）",
                              fields: payload.fields,
                              plan: payload.plan)
    }

    // MARK: plist

    private static func decodePropertyList(_ data: Data) -> DecodedPayload? {
        // 必须先按魔数筛一遍。PropertyListSerialization 连 OpenStep 老格式也认，
        // 而在那套语法里一个裸词就是合法的字符串 plist——不筛的话，
        // 每条普通文本密码都会被「解析」成它自己，白白多出一段。
        guard let base = plistFormatName(data) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.binary
        guard let original = try? PropertyListSerialization.propertyList(from: data,
                                                                        options: [],
                                                                        format: &format) else {
            return nil
        }

        if let dictionary = original as? [AnyHashable: Any], dictionary["$archiver"] != nil {
            if let resolved = resolveArchive(dictionary) {
                return DecodedPayload(formatName: "\(base) · NSKeyedArchiver",
                                      text: resolved.text,
                                      fields: resolved.fields,
                                      plan: .propertyList(original, format))
            }
            // 解不开引用图时至少把原始结构摆出来，但不能让它可编辑：
            // 下标对不上，改了会写坏归档
            return DecodedPayload(formatName: "\(base) · NSKeyedArchiver（引用图未能还原）",
                                  text: renderPlain(original, indent: 0),
                                  fields: [],
                                  plan: nil)
        }

        var fields: [DecodedField] = []
        let text = collect(original, path: [], label: "", indent: 0, fields: &fields)
        return DecodedPayload(formatName: base,
                              text: text,
                              fields: fields,
                              plan: .propertyList(original, format))
    }

    private static func plistFormatName(_ data: Data) -> String? {
        if data.starts(with: Array("bplist".utf8)) { return "binary plist" }

        // XML plist 前面可能有空白
        let head = data.prefix(512).drop { $0 == 0x20 || $0 == 0x09 || $0 == 0x0a || $0 == 0x0d }
        if head.starts(with: Array("<?xml".utf8)) || head.starts(with: Array("<plist".utf8)) {
            return "XML plist"
        }
        return nil
    }

    // MARK: NSKeyedArchiver 引用图

    /// UID 在 Swift 里没有公开类型，取不到里面的整数。但把 plist 转成 XML 再读回来，
    /// UID 就会变成 `{"CF$UID": n}` 这样的普通字典 —— `plutil -convert xml1`
    /// 看到的就是这个。**只用于读**：写回时用的是原始那份，UID 仍是不透明对象，
    /// 原样交给序列化器，绝不能拿这份转换过的去写，否则 UID 会被当成真字典存进去。
    private static func exposingUIDs(_ object: Any) -> Any? {
        guard let xml = try? PropertyListSerialization.data(fromPropertyList: object,
                                                            format: .xml,
                                                            options: 0) else { return nil }
        return try? PropertyListSerialization.propertyList(from: xml, options: [], format: nil)
    }

    private static func uidValue(_ any: Any) -> Int? {
        guard let dictionary = any as? [AnyHashable: Any],
              dictionary.count == 1,
              let number = dictionary["CF$UID"] as? NSNumber else { return nil }
        return number.intValue
    }

    private static func resolveArchive(
        _ archive: [AnyHashable: Any]
    ) -> (text: String, fields: [DecodedField])? {
        guard let exposed = exposingUIDs(archive) as? [AnyHashable: Any],
              let objects = exposed["$objects"] as? [Any],
              let top = exposed["$top"] as? [AnyHashable: Any] else { return nil }

        // 路径是照着 exposed 记的、却要用到 original 上，两边的 $objects 必须一一对应
        guard (archive["$objects"] as? [Any])?.count == objects.count else { return nil }

        // `archivedData(withRootObject:)` 用的是 root，但手写归档可以是任意键，
        // 写死 root 会白白解不出来
        let rootRef = top
            .map { (String(describing: $0.key), $0.value) }
            .sorted { $0.0 < $1.0 }
            .first?.1
        guard let rootRef else { return nil }

        // $top 的值在真归档里一定是引用。取不出引用说明 XML 往返没按预期
        // 把 UID 摊成 CF$UID 字典 —— 那样记下来的路径全是错的，宁可退回只读。
        guard uidValue(rootRef) != nil else { return nil }

        var collected: [String: DecodedField] = [:]
        var order: [String] = []
        let text = resolve(rootRef, objects: objects, label: "", path: [], indent: 0,
                           visiting: [], fields: &collected, order: &order)

        return (text, order.compactMap { collected[$0] })
    }

    /// `path` 指向 `node` 这个值在整份 plist 里的存放位置，写回时照着它改。
    private static func resolve(_ node: Any,
                                objects: [Any],
                                label: String,
                                path: FieldLocation,
                                indent: Int,
                                visiting: Set<Int>,
                                fields: inout [String: DecodedField],
                                order: inout [String]) -> String {
        guard indent < maxDepth else { return "…" }

        if let index = uidValue(node) {
            guard index >= 0, index < objects.count else { return "<引用越界 \(index)>" }
            // 归档里出现环是合法的，不挡住就会无限递归
            guard !visiting.contains(index) else { return "<循环引用>" }
            // 被引用的对象就存在 $objects[index]，路径从这里重新起算
            return resolve(objects[index], objects: objects, label: label,
                           path: [.key("$objects"), .index(index)], indent: indent,
                           visiting: visiting.union([index]),
                           fields: &fields, order: &order)
        }

        // 叶子可能是单独占一格的，也可能内联在上层字典里，两种都要收
        if let kind = leafKind(of: node) {
            record(path: path, label: label, kind: kind, value: leafValue(node),
                   into: &fields, order: &order)
            return leafDisplay(node)
        }

        guard let dictionary = node as? [AnyHashable: Any] else {
            return leafDisplay(node)
        }

        let pad = String(repeating: "  ", count: indent)

        // NSDictionary / NSMutableDictionary：键和值分成两个平行数组
        if let keys = dictionary["NS.keys"] as? [Any],
           let values = dictionary["NS.objects"] as? [Any] {
            guard !keys.isEmpty else { return "{}" }
            let body = zip(keys, values).enumerated().map { offset, pair -> String in
                let name = keyName(pair.0, objects: objects)
                let child = resolve(pair.1, objects: objects, label: join(label, name),
                                    path: path + [.key("NS.objects"), .index(offset)],
                                    indent: indent + 1, visiting: visiting,
                                    fields: &fields, order: &order)
                return "\(pad)  \(name): \(child)"
            }.joined(separator: "\n")
            return "{\n\(body)\n\(pad)}"
        }

        // NSArray / NSSet
        if let values = dictionary["NS.objects"] as? [Any] {
            guard !values.isEmpty else { return "[]" }
            let body = values.enumerated().map { offset, value in
                let child = resolve(value, objects: objects, label: "\(label)[\(offset)]",
                                    path: path + [.key("NS.objects"), .index(offset)],
                                    indent: indent + 1, visiting: visiting,
                                    fields: &fields, order: &order)
                return "\(pad)  \(child)"
            }.joined(separator: "\n")
            return "[\n\(body)\n\(pad)]"
        }

        // NSString / NSMutableString：文本直接内联在这里，不单独占格
        if let string = dictionary["NS.string"] {
            return resolve(string, objects: objects, label: label,
                           path: path + [.key("NS.string")], indent: indent,
                           visiting: visiting, fields: &fields, order: &order)
        }
        if let bytes = dictionary["NS.data"] as? Data {
            return "<\(bytes.count) 字节二进制>"
        }
        if let time = dictionary["NS.time"] as? NSNumber {
            // NSDate 存的是相对 2001-01-01 的秒数
            return dateFormatter.string(from: Date(timeIntervalSinceReferenceDate: time.doubleValue))
        }

        // 自定义类的实例：键就是字段名。本 App 里没有这些类，
        // 但归档里带了 $classname，照样能展开成可读的东西
        let className = classNameOf(dictionary, objects: objects)
        let entries = dictionary
            .map { (String(describing: $0.key), $0.value) }
            .filter { $0.0 != "$class" }
            .sorted { $0.0 < $1.0 }
        guard !entries.isEmpty else { return className.map { "\($0) {}" } ?? "{}" }

        let body = entries.map { name, value -> String in
            let child = resolve(value, objects: objects, label: join(label, name),
                                path: path + [.key(name)], indent: indent + 1,
                                visiting: visiting, fields: &fields, order: &order)
            return "\(pad)  \(name): \(child)"
        }.joined(separator: "\n")
        let prefix = className.map { "\($0) " } ?? ""
        return "\(prefix){\n\(body)\n\(pad)}"
    }

    private static func classNameOf(_ dictionary: [AnyHashable: Any], objects: [Any]) -> String? {
        guard let reference = dictionary["$class"],
              let index = uidValue(reference),
              index >= 0, index < objects.count,
              let entry = objects[index] as? [AnyHashable: Any] else { return nil }
        return entry["$classname"] as? String
    }

    /// 字典的键本身也是引用，几乎总是字符串
    private static func keyName(_ reference: Any, objects: [Any]) -> String {
        if let index = uidValue(reference), index >= 0, index < objects.count {
            if let text = objects[index] as? String { return text }
            if let number = objects[index] as? NSNumber { return number.stringValue }
        }
        return String(describing: reference)
    }

    private static func join(_ path: String, _ name: String) -> String {
        path.isEmpty ? name : "\(path).\(name)"
    }

    /// 归档会把相同的字符串合并成同一格，所以一处存储可能对应多条引用路径。
    /// 合并标签而不是覆盖，用户才知道改这一格会同时影响哪几处。
    private static func record(path: FieldLocation,
                               label: String,
                               kind: DecodedField.Kind,
                               value: String,
                               into fields: inout [String: DecodedField],
                               order: inout [String]) {
        guard kind != .null else { return }

        let id = path.map(\.token).joined(separator: "/")
        let name = label.isEmpty ? "(根)" : label

        guard let existing = fields[id] else {
            fields[id] = DecodedField(id: id, label: name, kind: kind,
                                      value: value, location: path)
            order.append(id)
            return
        }

        let parts = existing.label.components(separatedBy: " / ")
        guard !parts.contains(name), parts.count < 6 else { return }
        fields[id] = DecodedField(id: id,
                                  label: existing.label + " / " + name,
                                  kind: existing.kind,
                                  value: existing.value,
                                  location: existing.location)
    }

    // MARK: 普通 plist / JSON：按路径定位

    private static func collect(_ value: Any,
                                path: [PathComponent],
                                label: String,
                                indent: Int,
                                fields: inout [DecodedField]) -> String {
        guard indent < maxDepth else { return "…" }
        let pad = String(repeating: "  ", count: indent)

        // 字典要排在数组前面判断：NSDictionary 桥接过来也能匹配序列
        if let dictionary = value as? [AnyHashable: Any] {
            guard !dictionary.isEmpty else { return "{}" }
            let body = dictionary
                .map { (String(describing: $0.key), $0.value) }
                .sorted { $0.0 < $1.0 }
                .map { name, child -> String in
                    let rendered = collect(child, path: path + [.key(name)],
                                           label: join(label, name),
                                           indent: indent + 1, fields: &fields)
                    return "\(pad)  \(name): \(rendered)"
                }
                .joined(separator: "\n")
            return "{\n\(body)\n\(pad)}"
        }

        if let array = value as? [Any] {
            guard !array.isEmpty else { return "[]" }
            let body = array.enumerated().map { offset, child in
                let rendered = collect(child, path: path + [.index(offset)],
                                       label: "\(label)[\(offset)]",
                                       indent: indent + 1, fields: &fields)
                return "\(pad)  \(rendered)"
            }.joined(separator: "\n")
            return "[\n\(body)\n\(pad)]"
        }

        if let kind = leafKind(of: value), kind != .null {
            fields.append(DecodedField(id: path.map(\.token).joined(separator: "/"),
                                       label: label.isEmpty ? "(根)" : label,
                                       kind: kind,
                                       value: leafValue(value),
                                       location: path))
        }
        return leafDisplay(value)
    }

    /// 引用图解不开时的兜底渲染，只读
    private static func renderPlain(_ value: Any, indent: Int) -> String {
        var ignored: [DecodedField] = []
        return collect(value, path: [], label: "", indent: indent, fields: &ignored)
    }

    // MARK: JSON

    private static func decodeJSON(_ data: Data) -> DecodedPayload? {
        guard let first = data.first,
              first == UInt8(ascii: "{") || first == UInt8(ascii: "[") else { return nil }
        guard let object = try? JSONSerialization.jsonObject(with: data) else { return nil }

        var fields: [DecodedField] = []
        let text = collect(object, path: [], label: "", indent: 0, fields: &fields)
        return DecodedPayload(formatName: "JSON", text: text, fields: fields, plan: .json(object))
    }

    // MARK: DER / ASN.1

    private static func decodeDER(_ data: Data) -> DecodedPayload? {
        guard isDER(data) else { return nil }

        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            var lines = ["X.509 证书，\(data.count) 字节"]
            if let summary = SecCertificateCopySubjectSummary(certificate) as String?, !summary.isEmpty {
                lines.append("主体：\(summary)")
            }
            return DecodedPayload(formatName: "DER 证书",
                                  text: lines.joined(separator: "\n"),
                                  fields: [], plan: nil)
        }

        return DecodedPayload(
            formatName: "DER / ASN.1",
            text: "以 SEQUENCE 开头的 ASN.1 结构，\(data.count) 字节。\n"
                + "常见于 RSA / EC 公钥。本工具只做识别，不展开完整 ASN.1。",
            fields: [], plan: nil
        )
    }

    /// 光看首字节是 0x30 不够 —— 那也是 ASCII 的 "0"。在实测的 1447 条里，
    /// 只判首字节会把 87 条算成 DER，而其中 34 条其实是以 "0" 开头的普通文本。
    /// 必须连长度字段一起校验，看它和数据实际长度对不对得上。
    private static func isDER(_ data: Data) -> Bool {
        let head = [UInt8](data.prefix(6))
        guard head.count >= 2, head[0] == 0x30 else { return false }

        let marker = head[1]
        if marker & 0x80 == 0 {
            return 2 + Int(marker) == data.count
        }

        let byteCount = Int(marker & 0x7F)
        guard byteCount >= 1, byteCount <= 4, head.count >= 2 + byteCount else { return false }
        var length = 0
        for offset in 0..<byteCount {
            length = (length << 8) | Int(head[2 + offset])
        }
        return 2 + byteCount + length == data.count
    }

    // MARK: protobuf

    /// 残余数据里唯一还能可靠识别的结构。判据是「严格全量解析」：必须正好吃完
    /// 所有字节、字段号合法、线型只认 0/1/2/5，少一个字节多一个字节都判否。
    ///
    /// 实测（1447 条导出 + 随机数据）：非 UTF-8 的 149 条残余里命中 22 条，
    /// 随机数据误报率随长度从 1% 降到 0.1%。作为对照，cp1252 的「解码成功率」
    /// 是 98% —— 差两个数量级，那个数字大到根本不能当判据用。
    ///
    /// 必须先排除合法 UTF-8 再试：621 条纯文本里有 8 条能被 protobuf 解析成功，
    /// 不挡住就会把好端端的文本显示成一堆字段号。
    ///
    /// `skippingTextGate` 只给保存后的自检用：那时格式已经确定就是 protobuf，
    /// 再走一遍「排除 UTF-8」的发现逻辑会把改完恰好变成合法 UTF-8 的内容判成非
    /// protobuf，于是自检失败、一次本来合法的保存被拦下来。
    fileprivate static func decodeProtobuf(_ data: Data,
                                           skippingTextGate: Bool = false) -> DecodedPayload? {
        guard data.count >= 2 else { return nil }
        guard skippingTextGate || String(data: data, encoding: .utf8) == nil else { return nil }

        let bytes = [UInt8](data)
        guard let fields = parseProtobuf(bytes, from: 0, to: bytes.count, depth: 0) else {
            return nil
        }

        var collected: [DecodedField] = []
        let text = collectProtobuf(fields, path: [], label: "", indent: 0, fields: &collected)
        return DecodedPayload(formatName: "Protocol Buffers",
                              text: text,
                              fields: collected,
                              plan: .protobuf(fields))
    }

    /// 显式标类型：字面量里混着 Int 和 NSNumber / Data，让编译器去推会推出别的东西
    private static func protoField(_ number: Int, _ wire: Int, _ value: Any) -> [String: Any] {
        ["n": number, "w": wire, "v": value]
    }

    private static func readVarint(_ bytes: [UInt8], _ index: inout Int, end: Int) -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while index < end {
            let byte = bytes[index]
            index += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
            if shift > 63 { return nil }
        }
        return nil
    }

    private static func parseProtobuf(_ bytes: [UInt8],
                                      from start: Int,
                                      to end: Int,
                                      depth: Int) -> [Any]? {
        guard depth < 8, end - start >= 2 else { return nil }

        var fields: [Any] = []
        var index = start
        while index < end {
            guard let key = readVarint(bytes, &index, end: end) else { return nil }
            let number = Int(key >> 3)
            let wire = Int(key & 7)
            // 线型 3/4 是早就废弃的 group，出现基本说明判错了
            guard number > 0, number <= 536_870_911 else { return nil }

            switch wire {
            case 0:
                guard let value = readVarint(bytes, &index, end: end) else { return nil }
                fields.append(protoField(number, wire, NSNumber(value: value)))

            case 2:
                guard let length = readVarint(bytes, &index, end: end),
                      length <= UInt64(end - index) else { return nil }
                let stop = index + Int(length)
                let payload = Array(bytes[index..<stop])
                let value: Any
                // 文本优先于嵌套：可读字符串本身就是答案，硬当消息解会解出乱字段
                if let string = String(bytes: payload, encoding: .utf8),
                   !string.isEmpty, isPrintable(string) {
                    value = string
                } else if let nested = parseProtobuf(bytes, from: index, to: stop, depth: depth + 1) {
                    value = nested
                } else {
                    value = Data(payload)
                }
                index = stop
                fields.append(protoField(number, wire, value))

            case 5:
                guard end - index >= 4 else { return nil }
                fields.append(protoField(number, wire, Data(bytes[index..<index + 4])))
                index += 4

            case 1:
                guard end - index >= 8 else { return nil }
                fields.append(protoField(number, wire, Data(bytes[index..<index + 8])))
                index += 8

            default:
                return nil
            }
        }
        return fields.isEmpty ? nil : fields
    }

    private static func collectProtobuf(_ fields: [Any],
                                        path: FieldLocation,
                                        label: String,
                                        indent: Int,
                                        fields collected: inout [DecodedField]) -> String {
        let pad = String(repeating: "  ", count: indent)
        let lines = fields.enumerated().compactMap { offset, entry -> String? in
            guard let field = entry as? [AnyHashable: Any],
                  let number = field["n"] as? Int else { return nil }

            let name = label.isEmpty ? "\(number)" : "\(label).\(number)"
            let valuePath = path + [.index(offset), .key("v")]
            guard let value = field["v"] else { return "\(pad)\(number): null" }

            if let nested = value as? [Any] {
                let body = collectProtobuf(nested, path: valuePath, label: name,
                                           indent: indent + 1, fields: &collected)
                return "\(pad)\(number) {\n\(body)\n\(pad)}"
            }

            if let kind = leafKind(of: value), kind != .null {
                collected.append(DecodedField(id: valuePath.map(\.token).joined(separator: "/"),
                                              label: name,
                                              kind: kind,
                                              value: leafValue(value),
                                              location: valuePath))
            }
            return "\(pad)\(number): \(leafDisplay(value))"
        }
        return lines.joined(separator: "\n")
    }

    // MARK: 叶子

    private static func leafKind(of value: Any) -> DecodedField.Kind? {
        if let text = value as? String {
            // 归档用 "$null" 这个字符串表示空引用，不是真的内容
            return text == "$null" ? .null : .string
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() { return .boolean }
            return CFNumberIsFloatType(number as CFNumber) ? .real : .integer
        }
        if value is Date { return .date }
        if value is Data { return .data }
        if value is NSNull { return .null }
        return nil
    }

    /// 用于编辑框的原值
    private static func leafValue(_ value: Any) -> String {
        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                return number.boolValue ? "true" : "false"
            }
            return number.stringValue
        }
        if let text = value as? String { return text }
        return leafDisplay(value)
    }

    /// 用于只读全文的显示值
    private static func leafDisplay(_ value: Any) -> String {
        if let text = value as? String {
            return text == "$null" ? "null" : "\"\(text)\""
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                return number.boolValue ? "true" : "false"
            }
            return number.stringValue
        }
        if let bytes = value as? Data {
            if let text = String(data: bytes, encoding: .utf8), isPrintable(text) {
                return "\"\(text)\"  (\(bytes.count) 字节)"
            }
            return "<\(bytes.count) 字节二进制>"
        }
        if let date = value as? Date { return dateFormatter.string(from: date) }
        if value is NSNull { return "null" }
        return String(describing: value)
    }

    /// 换行和制表符也算控制字符，但它们出现在文本里是正常的，不能据此判成二进制
    private static func isPrintable(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
                || $0 == "\n" || $0 == "\r" || $0 == "\t"
        }
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()
}

// MARK: - 写回

extension DecodedPayload {

    /// `edits` 是 field.id -> 新文本，只包含用户实际改过的字段
    func encoded(with edits: [String: String]) throws -> Data {
        guard let plan else { throw DecodeEditError.notEditable }

        let changed = fields.filter {
            guard let text = edits[$0.id] else { return false }
            return text != $0.value
        }
        guard !changed.isEmpty else { throw DecodeEditError.noChanges }

        let encoded: Data
        switch plan {
        case .propertyList(let root, let format):
            let updated = try apply(changed, edits: edits, to: root)
            do {
                encoded = try PropertyListSerialization.data(fromPropertyList: updated,
                                                             format: format,
                                                             options: 0)
            } catch {
                throw DecodeEditError.encodingFailed(error.localizedDescription)
            }

        case .json(let root):
            let updated = try apply(changed, edits: edits, to: root)
            do {
                encoded = try JSONSerialization.data(withJSONObject: updated,
                                                     options: [.sortedKeys])
            } catch {
                throw DecodeEditError.encodingFailed(error.localizedDescription)
            }

        case .protobuf(let root):
            guard let updated = try apply(changed, edits: edits, to: root) as? [Any] else {
                throw DecodeEditError.encodingFailed("字段表结构损坏")
            }
            encoded = try Self.encodeProtobuf(updated)
        }

        try verify(encoded, changed: changed)
        return encoded
    }

    /// 编完立刻再解一遍，结构对不上就报错而不是写进钥匙串。
    ///
    /// 主要是为了兜住归档那条路径上一个没法在开发机上验证的假设：UID 在 Swift 里
    /// 没有公开类型，写回时是把原始解析结果里的不透明 UID 对象原样交还给
    /// `PropertyListSerialization`，赌它序列化时仍当 UID 处理。这个自检把
    /// 「赌错了就默默写坏条目」变成「赌错了就明确报错、原数据不动」。
    private func verify(_ data: Data, changed: [DecodedField]) throws {
        guard let reparsed = reparse(data) else {
            throw DecodeEditError.verificationFailed("重新编码后的数据解析不回来")
        }
        guard reparsed.formatName == formatName else {
            throw DecodeEditError.verificationFailed(
                "格式从「\(formatName)」变成了「\(reparsed.formatName)」")
        }
        let survivors = Set(reparsed.fields.map(\.id))
        if let lost = changed.first(where: { !survivors.contains($0.id) }) {
            throw DecodeEditError.verificationFailed("字段「\(lost.label)」不见了")
        }
    }

    /// 自检要按原本的格式重解，而不是重走一遍发现流程
    private func reparse(_ data: Data) -> DecodedPayload? {
        if case .protobuf = plan {
            return DataDecoder.decodeProtobuf(data, skippingTextGate: true)
        }
        return DataDecoder.decode(data)
    }

    /// 原样重编码在实测的 22 条 protobuf 上字节完全一致，改字段后往返也全部通过，
    /// 所以这里可以放心写回。
    fileprivate static func encodeProtobuf(_ fields: [Any]) throws -> Data {
        var out = Data()
        for entry in fields {
            guard let field = entry as? [AnyHashable: Any],
                  let number = field["n"] as? Int,
                  let wire = field["w"] as? Int else {
                throw DecodeEditError.encodingFailed("字段表结构损坏")
            }
            appendVarint(UInt64(number) << 3 | UInt64(wire), to: &out)

            switch wire {
            case 0:
                guard let value = field["v"] as? NSNumber else {
                    throw DecodeEditError.encodingFailed("字段 \(number) 不是整数")
                }
                appendVarint(value.uint64Value, to: &out)

            case 2:
                let payload: Data
                if let text = field["v"] as? String {
                    payload = Data(text.utf8)
                } else if let nested = field["v"] as? [Any] {
                    payload = try encodeProtobuf(nested)
                } else if let raw = field["v"] as? Data {
                    payload = raw
                } else {
                    throw DecodeEditError.encodingFailed("字段 \(number) 内容无法编码")
                }
                appendVarint(UInt64(payload.count), to: &out)
                out.append(payload)

            case 1, 5:
                guard let raw = field["v"] as? Data, raw.count == (wire == 1 ? 8 : 4) else {
                    throw DecodeEditError.encodingFailed("字段 \(number) 定长内容损坏")
                }
                out.append(raw)

            default:
                throw DecodeEditError.encodingFailed("字段 \(number) 线型 \(wire) 不支持")
            }
        }
        return out
    }

    private static func appendVarint(_ value: UInt64, to data: inout Data) {
        var remaining = value
        repeat {
            var byte = UInt8(remaining & 0x7F)
            remaining >>= 7
            if remaining != 0 { byte |= 0x80 }
            data.append(byte)
        } while remaining != 0
    }

    private func apply(_ changed: [DecodedField],
                       edits: [String: String],
                       to root: Any) throws -> Any {
        var result = root
        for field in changed {
            guard let text = edits[field.id] else { continue }
            let value = try Self.converted(text, to: field.kind, label: field.label)
            result = try Self.setValue(value, at: field.location, in: result, label: field.label)
        }
        return result
    }

    fileprivate static func converted(_ text: String,
                                      to kind: DecodedField.Kind,
                                      label: String) throws -> Any {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .string:
            return text
        case .integer:
            guard let value = Int(trimmed) else {
                throw DecodeEditError.badNumber(label: label, expected: "整数")
            }
            return NSNumber(value: value)
        case .real:
            guard let value = Double(trimmed) else {
                throw DecodeEditError.badNumber(label: label, expected: "小数")
            }
            return NSNumber(value: value)
        case .boolean:
            switch trimmed.lowercased() {
            case "true", "1", "yes": return NSNumber(value: true)
            case "false", "0", "no": return NSNumber(value: false)
            default: throw DecodeEditError.badNumber(label: label, expected: "true 或 false")
            }
        case .date, .data, .null:
            throw DecodeEditError.notEditable
        }
    }

    fileprivate static func setValue(_ newValue: Any,
                                     at path: FieldLocation,
                                     in container: Any,
                                     label: String) throws -> Any {
        guard let head = path.first else { return newValue }
        let rest = Array(path.dropFirst())

        switch head {
        case .key(let name):
            guard var dictionary = container as? [AnyHashable: Any],
                  let child = dictionary[name] else {
                throw DecodeEditError.pathBroken(label: label)
            }
            dictionary[name] = try setValue(newValue, at: rest, in: child, label: label)
            return dictionary

        case .index(let offset):
            guard var array = container as? [Any], offset >= 0, offset < array.count else {
                throw DecodeEditError.pathBroken(label: label)
            }
            array[offset] = try setValue(newValue, at: rest, in: array[offset], label: label)
            return array
        }
    }
}
