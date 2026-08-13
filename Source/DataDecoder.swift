import Foundation
import Security

// MARK: - 模型

/// 解析出来的一个可编辑叶子
struct DecodedField: Identifiable {

    enum Kind {
        case string, integer, real, boolean
        /// 独立的日期对象
        case date
        /// 归档里的 NSDate：存的是相对 2001-01-01 的秒数
        case referenceDate
        /// 内容是可读 UTF-8 的字节串。归档里存 UUID、token、指纹很常用这种，
        /// 按文本编辑，写回时再转成字节
        case utf8Data
        /// 真二进制，按十六进制编辑
        case binaryData
        /// 太大，就地编辑没意义，只读
        case opaqueData
        /// 指向 `$null` 的空引用。填入内容会在 `$objects` 里新增一项，
        /// 再把这处引用指过去
        case nullReference

        var isEditable: Bool {
            switch self {
            case .opaqueData: return false
            default: return true
            }
        }

        /// 光看值看不出该按什么格式填的，给个提示
        var editingHint: String? {
            switch self {
            case .utf8Data: return "字节串（按文本填）"
            case .binaryData: return "字节串（按十六进制填）"
            case .date, .referenceDate: return "yyyy-MM-dd HH:mm:ss"
            case .nullReference: return "空引用，填入内容即可设值"
            default: return nil
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
/// 写在实例字典里（`{gracePeriod: 0, …}`）。只认下标会漏掉这些：同一份导出上实测，
/// 按路径能解出 2999 个可编辑字段，只认下标只剩 1374 个，还有 72 条归档一个都解不出。
fileprivate typealias FieldLocation = [PathComponent]

fileprivate enum PathComponent {
    case key(String)
    case index(Int)
    /// 这一处的字节串本身又是一份负载：解开它，路径的后半截作用在里面，写回时重新编码
    case into

    /// 字段 id 由路径拼成，是 ForEach 的身份标识，重了会让列表串行。
    /// 带上类型前缀，键名 "5" 和下标 5、键名 "→" 和 .into 就不会撞。
    var token: String {
        switch self {
        // 键名里可以有 "/"，而 id 是拿 "/" 把 token 拼起来的：
        // 键 "a/kb" 和路径 a→b 会拼出同一个 id，两个字段共用一份编辑值，
        // 改一处会同时写到另一处、覆盖掉不相干的内容。转义掉再拼。
        case .key(let name):
            return "k" + name
                .replacingOccurrences(of: "%", with: "%25")
                .replacingOccurrences(of: "/", with: "%2F")
        case .index(let offset): return "i\(offset)"
        case .into: return "→"
        }
    }
}

fileprivate enum EditPlan {
    /// 二进制 plist：读写都走自己实现的 `BinaryPlist`，UID 是 `ArchiveUID`
    case binaryPlist(Any)
    /// XML plist：交给 `PropertyListSerialization`
    case xmlPlist(Any)
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
/// 对着一份 1467 条的完整导出统计过：纯文本 627 条、binary plist 314 条（其中
/// 310 条是归档，78 条含本 App 里根本没有的第三方类）、JSON 191 条、DER 56 条、
/// protobuf 25 条、空值 120 条，剩下 134 条是没有结构的密钥和哈希本身。
///
/// 归档必须**自己解 UID 引用图**，不能交给 `NSKeyedUnarchiver`：那 78 条里的
/// `FIRInstallationsStoredItem`、`OIDAuthState`、`EMMLoginInfo` 等类本 App 里
/// 根本不存在，`NSKeyedUnarchiver` 一律解不出来。自己解还有个附带好处 ——
/// 能记下每个叶子的存放路径，写回时只改那一处，引用图原封不动。
///
/// 连 binary plist 本身的编解码也是自己实现的（见 [BinaryPlist]）：UID 在 Swift 里
/// 没有能读写的公开类型，绕不开。曾经试过「转 XML 再读回来把 UID 摊成 CF$UID 字典」，
/// 实机上整份归档全都解不开，已废弃。
///
/// 不做的事：按 Windows-1252 之类的单字节编码硬解。这条查过实据，不是想当然：
/// 整份导出 81 万字节里 cp1252 未定义的只有 0.47%，随机字节的「解码成功率」98.0% ——
/// 什么都能解，就等于什么都没判。而且它解出来的不是信息：那 12 条「按 cp1252 看
/// 像文本」的条目实际是 protobuf，cp1252 只是把长度前缀 `f0`、`c3` 涂成了 `ð`、`Ã`。
/// 真正该做的是认出 protobuf，那 12 条里装的是 JWT 和 Tink 密钥集。
/// 另外也试过 UTF-16：整份导出 0 条命中。
enum DataDecoder {

    /// 全文渲染的长度上限。全文已经挪到单独一页了，不再受表单行的限制，
    /// 所以放宽到实测最大那条归档（26 KB）展开后也不会被截断
    private static let renderLimit = 200_000
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
        // 必须先按魔数筛。二进制的交给自己的实现，XML 的才走 Foundation ——
        // 后者连 OpenStep 老格式也认，而在那套语法里一个裸词就是合法的字符串 plist，
        // 不筛的话每条普通文本密码都会被「解析」成它自己，白白多出一段。
        let parsed: Any
        let base: String
        let plan: (Any) -> EditPlan

        if data.starts(with: BinaryPlist.magic) {
            guard let root = BinaryPlist.parse(data) else { return nil }
            parsed = root
            base = "binary plist"
            plan = EditPlan.binaryPlist
        } else if isXMLPlist(data) {
            guard let root = try? PropertyListSerialization.propertyList(from: data,
                                                                        options: [],
                                                                        format: nil) else {
                return nil
            }
            parsed = root
            base = "XML plist"
            plan = EditPlan.xmlPlist
        } else {
            return nil
        }

        if let dictionary = parsed as? [AnyHashable: Any], dictionary["$archiver"] != nil {
            if let resolved = resolveArchive(dictionary) {
                return DecodedPayload(formatName: "\(base) · NSKeyedArchiver",
                                      text: resolved.text,
                                      fields: resolved.fields,
                                      plan: plan(parsed))
            }
            // 引用图解不开时至少把原始结构摆出来，但不能让它可编辑
            return DecodedPayload(formatName: "\(base) · NSKeyedArchiver（引用图未能还原）",
                                  text: renderPlain(parsed, indent: 0),
                                  fields: [],
                                  plan: nil)
        }

        var fields: [DecodedField] = []
        let text = collect(parsed, path: [], label: "", indent: 0, fields: &fields)
        return DecodedPayload(formatName: base, text: text, fields: fields, plan: plan(parsed))
    }

    private static func isXMLPlist(_ data: Data) -> Bool {
        // XML plist 前面可能有空白
        let head = data.prefix(512).drop { $0 == 0x20 || $0 == 0x09 || $0 == 0x0a || $0 == 0x0d }
        return head.starts(with: Array("<?xml".utf8)) || head.starts(with: Array("<plist".utf8))
    }

    // MARK: NSKeyedArchiver 引用图

    private static func uidValue(_ any: Any) -> Int? {
        guard let uid = any as? ArchiveUID else { return nil }
        return Int(clamping: uid.value)
    }

    private static func resolveArchive(
        _ archive: [AnyHashable: Any]
    ) -> (text: String, fields: [DecodedField])? {
        guard let objects = archive["$objects"] as? [Any],
              let top = archive["$top"] as? [AnyHashable: Any] else { return nil }

        // `archivedData(withRootObject:)` 用的是 root，但手写归档可以是任意键，
        // 写死 root 会白白解不出来
        let rootRef = top
            .map { (String(describing: $0.key), $0.value) }
            .sorted { $0.0 < $1.0 }
            .first?.1
        guard let rootRef, uidValue(rootRef) != nil else { return nil }

        var collected: [String: DecodedField] = [:]
        var order: [String] = []
        var text = resolve(rootRef, objects: objects, label: "", path: [], indent: 0,
                           visiting: [], fields: &collected, order: &order)

        // 整条归档的根就是 $null 的，实测有 6 条。光甩一个「null」出来
        // 谁也看不懂是解析失败还是内容本来就空
        if text == "null" && collected.isEmpty {
            text = "这条归档的内容是空的（根对象是 $null），不是解析失败。"
        }

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

            // 空引用：整份归档共用 $objects 里同一个 "$null"，改那一格会波及所有空值。
            // 所以记的是**引用本身**的位置，写回时新增一项再把这里指过去。
            if objects[index] as? String == "$null" {
                if !path.isEmpty {
                    record(path: path, label: label, kind: .nullReference, value: "",
                           into: &fields, order: &order)
                }
                return "null"
            }

            // 引用链本身也要封顶。这一跳不增加 indent（渲染缩进不该因为多绕一层引用而变），
            // 于是 maxDepth 管不到它 —— visiting 只挡环，挡不住 UID→UID→UID… 这种
            // 无环长链：手工构造一条 3000 跳的链就能在打开详情页时把主线程栈打爆。
            // visiting 恰好就是当前这条链上的祖先集合，拿它的大小当跳数用。
            guard visiting.count < 256 else { return "<引用链过深>" }

            // 被引用的对象就存在 $objects[index]，路径从这里重新起算
            return resolve(objects[index], objects: objects, label: label,
                           path: [.key("$objects"), .index(index)], indent: indent,
                           visiting: visiting.union([index]),
                           fields: &fields, order: &order)
        }

        // 字节串里还嵌着一份完整负载：展开它，并把内层字段的路径接到 .into 后面，
        // 这样内层也能改 —— 写回时先重编码内层，再重编码外层
        // 内层解出来没有可读字段的（例如 DER，只能识别不能展开）不走这条：
        // 那样这段字节既进不了字段列表也改不了，只剩全文里一行描述。
        // 落回下面的叶子处理，仍然可编辑，显示上照样带出内层是什么。
        if let bytes = node as? Data, let inner = nestedPayload(in: bytes),
           !inner.fields.isEmpty {
            for field in inner.fields {
                record(path: path + [.into] + field.location,
                       label: join(label, field.label), kind: field.kind,
                       value: field.value, into: &fields, order: &order)
            }
            let indented = inner.text
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map { String(repeating: "  ", count: indent + 1) + $0 }
                .joined(separator: "\n")
            return "\(bytes.count) 字节 · \(inner.formatName)\n\(indented)"
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
                // 键名本身也是内容，也该能改。走一遍 resolve 就会被记成字段
                _ = resolve(pair.0, objects: objects, label: "\(join(label, name)) (键名)",
                            path: path + [.key("NS.keys"), .index(offset)],
                            indent: indent + 1, visiting: visiting,
                            fields: &fields, order: &order)
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
        // NSData 包装。以前这里直接返回字节数就完事，可实测 36 个二进制叶子里
        // 有 15 个其实是纯可读文本（UUID、token、指纹），还有 2 个里面嵌着
        // 完整的归档 / protobuf —— 一律显示成「N 字节二进制」等于把内容藏了
        if let bytes = dictionary["NS.data"] as? Data {
            return resolve(bytes, objects: objects, label: label,
                           path: path + [.key("NS.data")], indent: indent,
                           visiting: visiting, fields: &fields, order: &order)
        }
        if let time = dictionary["NS.time"] as? NSNumber {
            // NSDate 存的是相对 2001-01-01 的秒数
            let text = dateFormatter.string(from: Date(timeIntervalSinceReferenceDate: time.doubleValue))
            record(path: path + [.key("NS.time")], label: label, kind: .referenceDate,
                   value: text, into: &fields, order: &order)
            return text
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

        // 和 resolve 一样：字节串里嵌着完整负载的，展开成内层字段而不是当成叶子
        if let bytes = value as? Data, let inner = nestedPayload(in: bytes),
           !inner.fields.isEmpty {
            for field in inner.fields {
                fields.append(DecodedField(id: (path + [.into] + field.location)
                                              .map(\.token).joined(separator: "/"),
                                           label: join(label, field.label),
                                           kind: field.kind,
                                           value: field.value,
                                           location: path + [.into] + field.location))
            }
            return "\(bytes.count) 字节 · \(inner.formatName)\n\(inner.text)"
        }

        if let kind = leafKind(of: value) {
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

    /// 光看首字节是 0x30 不够 —— 那也是 ASCII 的 "0"。在实测的 1467 条里，
    /// 只判首字节会把 91 条算成 DER，而其中 35 条其实是以 "0" 开头的普通文本。
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
    /// 实测（1467 条导出 + 随机数据）：非 UTF-8 的 159 条残余里命中 25 条，
    /// 随机数据误报率 0.05%–0.17%。作为对照，cp1252 的「解码成功率」是 98% ——
    /// 差三个数量级，那个数字大到根本不能当判据用。
    ///
    /// 合法 UTF-8 一律先排除。这条现在是双保险：判据收紧之前，818 条能读成文本的
    /// 条目里有 8 条会被 protobuf 解析成功，收紧之后是 0 条。但文本就该按文本显示，
    /// 不该摆成一堆字段号，所以闸留着。
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

        // 至少得有一个长度分隔字段（字符串 / 字节串 / 嵌套消息）。真实消息几乎总有，
        // 而随机字节恰好凑出来的基本是纯 varint。这一条把 20 字节随机数据的误报率
        // 把随机短数据的误报率压到约十分之一（16 字节 1.12% -> 0.10%）；实测导出里
        // 1520 条 SHA-1 哈希属性的误报从 10 条降到 0 条，818 条文本条目的误报从 8 条降到 0 条。
        // 代价是漏掉 1 条 8 字节、字段号 4329229 的「消息」—— 那个本来也是误报。
        guard fields.contains(where: { ($0 as? [AnyHashable: Any])?["w"] as? Int == 2 }) else {
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

            // 和 resolve / collect 保持一致：字节字段里嵌着完整负载的，
            // 展开成内层字段而不是只显示一句「N 字节二进制」
            if let bytes = value as? Data, let inner = nestedPayload(in: bytes),
               !inner.fields.isEmpty {
                for field in inner.fields {
                    collected.append(DecodedField(id: (valuePath + [.into] + field.location)
                                                     .map(\.token).joined(separator: "/"),
                                                  label: join(name, field.label),
                                                  kind: field.kind,
                                                  value: field.value,
                                                  location: valuePath + [.into] + field.location))
                }
                return "\(pad)\(number): \(bytes.count) 字节 · \(inner.formatName)\n\(inner.text)"
            }

            if let kind = leafKind(of: value) {
                // fixed32 / fixed64 的字节数是固定的。leafKind 只看内容，碰上恰好
                // 可打印的 4 / 8 字节会判成文本，于是放出一个能随便改长度的输入框，
                // 而编码时长度对不上只能报错。定长字段一律按十六进制编辑 ——
                // 注意值也要一并换成十六进制，否则框里显示的是文本、解析却按十六进制。
                let fixedWidth = (field["w"] as? Int).map { $0 == 1 || $0 == 5 } ?? false
                let raw = value as? Data
                let resolved: (DecodedField.Kind, String) = (fixedWidth && raw != nil)
                    ? (.binaryData, raw!.hexString)
                    : (kind, leafValue(value))

                collected.append(DecodedField(id: valuePath.map(\.token).joined(separator: "/"),
                                              label: name,
                                              kind: resolved.0,
                                              value: resolved.1,
                                              location: valuePath))
            }
            return "\(pad)\(number): \(leafDisplay(value))"
        }
        return lines.joined(separator: "\n")
    }

    // MARK: 叶子

    /// 十六进制编辑框的上限。再大就不是人能手改的了，也会把 Form 撑爆
    private static let hexEditLimit = 512

    private static func leafKind(of value: Any) -> DecodedField.Kind? {
        if value is String { return .string }
        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() { return .boolean }
            return CFNumberIsFloatType(number as CFNumber) ? .real : .integer
        }
        if value is Date { return .date }
        // 128 位整数：Swift 侧没有能装下的数值类型，编辑框转不回去，所以只读
        if value is WideInteger { return .opaqueData }
        if let bytes = value as? Data {
            // 顺序要和 leafDisplay 一致：能当文本读就按文本，读不成再按十六进制。
            // 嵌套结构在 resolve / collect 里已经先一步展开成内层字段了，走不到这
            if let text = String(data: bytes, encoding: .utf8), !text.isEmpty, isPrintable(text) {
                return .utf8Data
            }
            return bytes.count <= hexEditLimit ? .binaryData : .opaqueData
        }
        if value is NSNull { return .nullReference }
        return nil
    }

    /// 字节串里是不是还套着一层能解的东西。归档里套归档、套 protobuf 都实际见过。
    fileprivate static func nestedPayload(in bytes: Data) -> DecodedPayload? {
        // 只认有明确魔数 / 强判据的，别把普通字节猜成结构
        guard bytes.count >= 4 else { return nil }
        if bytes.starts(with: BinaryPlist.magic) || isXMLPlist(bytes) {
            return decodePropertyList(bytes)
        }
        if bytes.first == UInt8(ascii: "{") || bytes.first == UInt8(ascii: "[") {
            return decodeJSON(bytes)
        }
        if isDER(bytes) { return decodeDER(bytes) }
        return decodeProtobuf(bytes)
    }

    /// 用于编辑框的原值
    private static func leafValue(_ value: Any) -> String {
        if let wide = value as? WideInteger { return wide.decimalDescription }
        if let number = value as? NSNumber {
            if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() {
                return number.boolValue ? "true" : "false"
            }
            return number.stringValue
        }
        if let text = value as? String { return text }
        if let bytes = value as? Data {
            switch leafKind(of: bytes) {
            case .utf8Data: return String(data: bytes, encoding: .utf8) ?? ""
            case .binaryData: return bytes.hexString
            default: break
            }
        }
        return leafDisplay(value)
    }

    /// 用于只读全文的显示值
    private static func leafDisplay(_ value: Any) -> String {
        if let wide = value as? WideInteger { return wide.decimalDescription }
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
            if let text = String(data: bytes, encoding: .utf8), !text.isEmpty, isPrintable(text) {
                return "\"\(text)\"  (\(bytes.count) 字节)"
            }
            // 这里是纯显示，不要求内层有可读字段：认出是 DER 也比甩一串十六进制强
            if let inner = nestedPayload(in: bytes) {
                return "\(bytes.count) 字节 · \(inner.formatName)\n\(inner.text)"
            }
            // 短的直接把十六进制摆出来，别让人还得回原始数据区自己数
            if bytes.count <= 64 { return "\(bytes.hexString)  (\(bytes.count) 字节)" }
            return "\(bytes.prefix(32).hexString)…  (\(bytes.count) 字节)"
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

    fileprivate static func parseDate(_ text: String) -> Date? {
        dateFormatter.date(from: text)
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        // 固定格式必须配 POSIX 区域，否则在非公历区域下格式化和解析会对不上
        formatter.locale = Locale(identifier: "en_US_POSIX")
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

        guard let root = planRoot else { throw DecodeEditError.notEditable }
        let updated = try apply(changed, edits: edits, to: root)

        let encoded: Data
        do {
            encoded = try encodeRoot(updated)
        } catch let error as DecodeEditError {
            throw error
        } catch {
            throw DecodeEditError.encodingFailed(error.localizedDescription)
        }

        try verify(encoded, changed: changed)
        return encoded
    }

    /// 编完立刻再解一遍，结构对不上就报错而不是写进钥匙串。
    ///
    /// binary plist 的编码是本项目自己实现的，没法在开发机上跑真机验证，
    /// 这一步就是它的安全网：把「编错了默默写坏条目」变成「编错了明确报错、原数据不动」。
    private func verify(_ data: Data, changed: [DecodedField]) throws {
        guard let reparsed = reparse(data) else {
            throw DecodeEditError.verificationFailed("重新编码后的数据解析不回来")
        }
        guard reparsed.formatName == formatName else {
            throw DecodeEditError.verificationFailed(
                "格式从「\(formatName)」变成了「\(reparsed.formatName)」")
        }
        let survivors = Set(reparsed.fields.map(\.id))
        // 空引用被填上之后，那处就不再是空引用了，它的 id 本来就会变，不能当成丢失
        if let lost = changed.first(where: {
            $0.kind != .nullReference && !survivors.contains($0.id)
        }) {
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

    /// 原样重编码在实测的 25 条 protobuf 上字节完全一致，改字段后往返也全部通过，
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
                let expected = wire == 1 ? 8 : 4
                guard let raw = field["v"] as? Data else {
                    throw DecodeEditError.encodingFailed("字段 \(number) 内容无法编码")
                }
                guard raw.count == expected else {
                    throw DecodeEditError.encodingFailed(
                        "字段 \(number) 是定长 \(expected) 字节，填了 \(raw.count) 字节")
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

            if field.kind == .nullReference {
                result = try Self.fillNull(text, at: field.location, in: result, label: field.label)
                continue
            }

            var wideUnsigned = false
            if case .protobuf = plan { wideUnsigned = true }
            let value = try Self.converted(text, to: field.kind, label: field.label,
                                           allowsWideUnsigned: wideUnsigned)
            result = try Self.setValue(value, at: field.location, in: result, label: field.label)
        }
        return result
    }

    /// 填上一个空引用。
    ///
    /// 归档里所有空值共用 `$objects` 里同一个 `"$null"`，改那一格会把整份归档的空值
    /// 一起改掉，所以只能新增一项再把这处引用指过去 —— 这要在**引用所在的那一层归档**上做。
    /// 路径可能穿过嵌套负载，那就先解到最内层再动手，否则会把字符串直接写进内层归档的
    /// 引用位上，把内层写坏。
    fileprivate static func fillNull(_ text: String,
                                     at path: FieldLocation,
                                     in container: Any,
                                     label: String) throws -> Any {
        let boundary = path.lastIndex {
            if case .into = $0 { return true }
            return false
        }

        if let boundary {
            // 先走到（含）那个 .into，拿到解开后的内层根，再在内层递归处理
            return try mutate(at: Array(path[...boundary]), in: container, label: label) { inner in
                try fillNull(text, at: Array(path[(boundary + 1)...]), in: inner, label: label)
            }
        }

        guard var archive = container as? [AnyHashable: Any],
              var objects = archive["$objects"] as? [Any],
              archive["$archiver"] != nil else {
            // JSON / 普通 plist 没有这层间接，直接把值写进去就行
            return try setValue(text, at: path, in: container, label: label)
        }

        objects.append(text)
        archive["$objects"] = objects
        return try setValue(ArchiveUID(value: UInt64(objects.count - 1)),
                            at: path, in: archive, label: label)
    }

    /// `allowsWideUnsigned` 只有 protobuf 该给 true：它的 varint 是 64 位无符号。
    /// binary plist 的整数编码是有符号的，把超过 Int64.max 的值塞进去会以补码存成负数。
    fileprivate static func converted(_ text: String,
                                      to kind: DecodedField.Kind,
                                      label: String,
                                      allowsWideUnsigned: Bool = false) throws -> Any {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .string:
            return text
        case .integer:
            if let value = Int(trimmed) { return NSNumber(value: value) }
            // 超过 Int64.max 的无符号值只有 protobuf 的 varint 装得下。
            // binary plist 的整数编码是有符号的，塞进去会以补码变成负数存下来，
            // 而自检只比对字段 id、发现不了值被改写，所以这里直接拒绝。
            if allowsWideUnsigned, let value = UInt64(trimmed) {
                return NSNumber(value: value)
            }
            throw DecodeEditError.badNumber(label: label, expected: "整数")
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
        case .utf8Data:
            return Data(text.utf8)
        case .binaryData:
            guard let bytes = trimmed.hexData else {
                throw DecodeEditError.badNumber(label: label,
                                                expected: "十六进制（长度为偶数，只含 0-9 / a-f）")
            }
            return bytes
        case .date:
            guard let date = DataDecoder.parseDate(trimmed) else {
                throw DecodeEditError.badNumber(label: label, expected: "yyyy-MM-dd HH:mm:ss 格式的时间")
            }
            return date
        case .referenceDate:
            guard let date = DataDecoder.parseDate(trimmed) else {
                throw DecodeEditError.badNumber(label: label, expected: "yyyy-MM-dd HH:mm:ss 格式的时间")
            }
            return NSNumber(value: date.timeIntervalSinceReferenceDate)
        case .nullReference:
            // 归档要新增 $objects 项，在 apply 里另行处理；其余格式直接放字符串
            return text
        case .opaqueData:
            throw DecodeEditError.notEditable
        }
    }

    fileprivate static func setValue(_ newValue: Any,
                                     at path: FieldLocation,
                                     in container: Any,
                                     label: String) throws -> Any {
        try mutate(at: path, in: container, label: label) { _ in newValue }
    }

    /// 沿路径走到底，把末端的值交给 `transform` 换成新的。
    /// 单独抽出来是因为「填空引用」要拿到的不是叶子而是那一层的归档根。
    fileprivate static func mutate(at path: FieldLocation,
                                   in container: Any,
                                   label: String,
                                   using transform: (Any) throws -> Any) throws -> Any {
        guard let head = path.first else { return try transform(container) }
        let rest = Array(path.dropFirst())

        switch head {
        case .key(let name):
            guard var dictionary = container as? [AnyHashable: Any],
                  let child = dictionary[name] else {
                throw DecodeEditError.pathBroken(label: label)
            }
            dictionary[name] = try mutate(at: rest, in: child, label: label, using: transform)
            return dictionary

        case .index(let offset):
            guard var array = container as? [Any], offset >= 0, offset < array.count else {
                throw DecodeEditError.pathBroken(label: label)
            }
            array[offset] = try mutate(at: rest, in: array[offset], label: label, using: transform)
            return array

        case .into:
            // 这一处的字节串本身是一份负载：解开、在里面改、再原样编码回去。
            //
            // 走不通时再按 protobuf 试一次：nestedPayload 里那道「先排除合法 UTF-8」
            // 是给**发现**用的，而这里格式早就定了。改完的内层字节一旦恰好成了合法
            // UTF-8，发现流程就不再认它是 protobuf，于是一次本来合法的保存永远失败。
            guard let bytes = container as? Data else {
                throw DecodeEditError.pathBroken(label: label)
            }
            guard let inner = DataDecoder.nestedPayload(in: bytes)
                    ?? DataDecoder.decodeProtobuf(bytes, skippingTextGate: true),
                  let innerRoot = inner.planRoot else {
                throw DecodeEditError.pathBroken(label: label)
            }
            let updated = try mutate(at: rest, in: innerRoot, label: label, using: transform)
            return try inner.encodeRoot(updated)
        }
    }

    /// 内层负载的解析树和它的编码方式
    fileprivate var planRoot: Any? {
        switch plan {
        case .binaryPlist(let root), .xmlPlist(let root), .json(let root): return root
        case .protobuf(let root): return root
        case nil: return nil
        }
    }

    fileprivate func encodeRoot(_ updated: Any) throws -> Data {
        switch plan {
        case .binaryPlist:
            return try BinaryPlist.serialize(updated)
        case .xmlPlist:
            return try PropertyListSerialization.data(fromPropertyList: updated,
                                                      format: .xml, options: 0)
        case .json:
            return try JSONSerialization.data(withJSONObject: updated, options: [.sortedKeys])
        case .protobuf:
            guard let fields = updated as? [Any] else {
                throw DecodeEditError.encodingFailed("字段表结构损坏")
            }
            return try Self.encodeProtobuf(fields)
        case nil:
            throw DecodeEditError.notEditable
        }
    }
}
