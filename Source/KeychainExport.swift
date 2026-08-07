import Foundation
import Security

/// JSON 导入 / 导出的编解码。
///
/// 格式（与外部导出工具一致）：
/// ```json
/// {
///   "access_group": "TEAMID.com.example",
///   "genp": [ { "acct": "...", "v_Data": { "type": "text", ... } } ],
///   "inet": [], "keys": [], "cert": []
/// }
/// ```
///
/// 属性值有三种写法，区别是有含义的：
/// - 普通字符串 / 数字 → 原值就是 `String` / `NSNumber`
/// - `{"type":"text","value":…}` → 原值是 **Data**，且能解成 UTF-8
/// - `{"type":"data","base64":…}` → 原值是 Data，解不成 UTF-8
///
/// 靠这条规则往返才不会失真：把 Data 型的 `acct` 导出成普通字符串，
/// 再导入回去就变成了 String，主键随之改变。
enum KeychainExport {

    // MARK: - 类别与 JSON 键的对应

    static func jsonKey(for itemClass: KeychainItemClass) -> String {
        switch itemClass {
        case .genericPassword:  return "genp"
        case .internetPassword: return "inet"
        case .key:              return "keys"
        case .certificate:      return "cert"
        }
    }

    static func itemClass(forJSONKey key: String) -> KeychainItemClass? {
        KeychainItemClass.allCases.first { jsonKey(for: $0) == key }
    }

    // MARK: - 导入时忽略的键

    /// 这些一律不写回钥匙串：
    /// - `sha1` / `tomb` / `musr`：系统内部维护
    /// - `cdat` / `mdat`：创建与修改时间由系统给
    /// - `sdat` / `edat`：密钥有效期，iOS 无公开常量，写了也无从校验
    /// - `accc`：导出的是 `<SecAccessControlRef: dku>` 这种调试字符串，
    ///   还原不成对象；保护级别由 `pdmn` 单独承载，不会丢
    /// - `class` / `v_PersistentRef`：查询结构本身，不是属性
    static let ignoredOnImport: Set<String> = [
        "sha1", "tomb", "musr", "cdat", "mdat", "sdat", "edat",
        "accc", "class", "v_PersistentRef", "UUID", "persistref"
    ]

    // MARK: - 编码

    static func makeJSON(items: [KeychainItem], accessGroup: String) throws -> Data {
        var buckets: [String: [[String: Any]]] = [:]
        for itemClass in KeychainItemClass.allCases {
            buckets[jsonKey(for: itemClass)] = []
        }

        for item in items {
            var encoded: [String: Any] = [:]
            // 持久引用只在本机本次进程有意义，带出去纯属噪音，示例格式里也没有
            for (key, value) in item.rawAttributes
            where key != "class" && key != (kSecValuePersistentRef as String) {
                encoded[key] = encode(value)
            }
            // 数据不在枚举结果里，单独补上；读不出来的就不写这一项
            if item.isDataReadable, let data = item.data {
                encoded[kSecValueData as String] = encode(data)
            }
            buckets[jsonKey(for: item.itemClass), default: []].append(encoded)
        }

        var root: [String: Any] = ["access_group": accessGroup]
        for (key, value) in buckets { root[key] = value }

        return try JSONSerialization.data(withJSONObject: root,
                                          options: [.prettyPrinted, .sortedKeys])
    }

    private static func encode(_ value: Any) -> Any {
        if let data = value as? Data {
            if let text = String(data: data, encoding: .utf8) {
                return ["type": "text", "value": text, "length": data.count]
            }
            return ["type": "data", "base64": data.base64EncodedString(), "length": data.count]
        }
        if let date = value as? Date {
            return isoFormatter.string(from: date)
        }
        if let number = value as? NSNumber { return number }
        if let string = value as? String { return string }
        // SecAccessControl 之类无法序列化的对象，退回它的调试描述（与导出工具一致）
        return "\(value)"
    }

    // MARK: - 解码

    struct ParsedItem {
        let itemClass: KeychainItemClass
        /// 已按上面的规则还原成 String / NSNumber / Data
        let attributes: [String: Any]
        /// 有属性解不出来时记下原因。整条跳过并如实报告，
        /// 而不是拿个空值顶上去 —— 那会在钥匙串里造出一条内容为空、
        /// 看上去却导入成功的条目
        var decodeFailure: String?
    }

    struct ParsedFile {
        let accessGroup: String
        let items: [ParsedItem]

        func count(of itemClass: KeychainItemClass) -> Int {
            items.filter { $0.itemClass == itemClass }.count
        }
    }

    enum ParseError: LocalizedError {
        case notAnObject
        case noItems

        var errorDescription: String? {
            switch self {
            case .notAnObject: return "文件顶层不是 JSON 对象"
            case .noItems:     return "文件里没有 genp / inet / keys / cert 任何一类条目"
            }
        }
    }

    static func parse(_ data: Data) throws -> ParsedFile {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let root = object as? [String: Any] else { throw ParseError.notAnObject }

        let accessGroup = root["access_group"] as? String ?? ""
        var items: [ParsedItem] = []

        for itemClass in KeychainItemClass.allCases {
            guard let bucket = root[jsonKey(for: itemClass)] as? [[String: Any]] else { continue }
            for entry in bucket {
                var attributes: [String: Any] = [:]
                var failure: String?
                for (key, value) in entry {
                    guard !ignoredOnImport.contains(key) else { continue }
                    switch decode(value) {
                    case .success(let decoded):
                        attributes[key] = decoded
                    case .skip:
                        continue
                    case .broken(let reason):
                        failure = failure ?? "「\(key)」\(reason)"
                    }
                }
                guard !attributes.isEmpty else { continue }
                items.append(ParsedItem(itemClass: itemClass,
                                        attributes: attributes,
                                        decodeFailure: failure))
            }
        }

        guard !items.isEmpty else { throw ParseError.noItems }
        return ParsedFile(accessGroup: accessGroup, items: items)
    }

    fileprivate enum Decoded {
        case success(Any)
        /// 这一项没法用，但不足以判整条不可导入（例如无法识别的包装类型）
        case skip
        /// 值明显坏了。整条条目要跳过并报告，不能拿空值顶替
        case broken(String)
    }

    private static func decode(_ value: Any) -> Decoded {
        guard let wrapper = value as? [String: Any], let type = wrapper["type"] as? String else {
            // 普通字符串 / 数字：原样保留类型
            return .success(value)
        }

        switch type {
        case "text":
            // 带类型标记说明原值是 Data，不能还原成 String
            guard let text = wrapper["value"] as? String else {
                return .broken("标为 text 却没有 value 字段")
            }
            return .success(Data(text.utf8))
        case "data":
            guard let base64 = wrapper["base64"] as? String else {
                return .broken("标为 data 却没有 base64 字段")
            }
            guard let bytes = Data(base64Encoded: base64) else {
                return .broken("base64 解不开")
            }
            return .success(bytes)
        default:
            return .skip
        }
    }

    // MARK: - 建议文件名

    static func suggestedFileName(accessGroup: String) -> String {
        let group = accessGroup.isEmpty ? "keychain" : accessGroup
        let safe = group.replacingOccurrences(of: "/", with: "_")
                        .replacingOccurrences(of: ":", with: "_")
        return "keychain_export_\(safe).json"
    }

    private static let isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
