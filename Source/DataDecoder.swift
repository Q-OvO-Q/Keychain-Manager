import Foundation
import Security

struct DecodedPayload {
    let formatName: String
    let text: String
}

/// 把条目数据里那些「看着是二进制、其实有结构」的内容解析成可读文本。
///
/// 实测样本里，`type: data` 的条目绝大多数是 **binary plist**，而且几乎都是
/// `NSKeyedArchiver` 归档 —— 后者只解成 plist 仍然不可读，因为内容是
/// `$objects` 数组加一堆 `CF$UID` 引用，必须把对象图还原回来才有意义。
///
/// 不做的事：按 Windows-1252 之类的单字节编码硬解。那不是「解析」——
/// 256 个字节里只有 5 个未定义，随机数据也有 ~98% 能「解码成功」，
/// 因此它既不能用来判断格式，解出来的也是乱码而不是信息。
enum DataDecoder {

    /// 超过这个长度的渲染结果会被截断：详情页是只读预览，
    /// 塞进 Form 的一整屏文本再长也没人看，还会拖慢滚动
    private static let renderLimit = 20_000

    static func decode(_ data: Data) -> DecodedPayload? {
        guard !data.isEmpty else { return nil }
        guard let payload = decodePropertyList(data) ?? decodeJSON(data) ?? decodeDER(data) else {
            return nil
        }
        guard payload.text.count > renderLimit else { return payload }
        let truncated = payload.text.prefix(renderLimit)
        return DecodedPayload(formatName: payload.formatName,
                              text: truncated + "\n…（内容过长，已截断）")
    }

    // MARK: - plist / NSKeyedArchiver

    private static func decodePropertyList(_ data: Data) -> DecodedPayload? {
        // 必须先按魔数筛一遍。PropertyListSerialization 连 OpenStep 老格式也认，
        // 而在那套语法里一个裸词就是合法的字符串 plist——不筛的话，
        // 每条普通文本密码都会被「解析」成它自己，白白多出一段。
        guard let base = plistFormatName(data) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.binary
        guard let object = try? PropertyListSerialization.propertyList(from: data,
                                                                      options: [],
                                                                      format: &format) else {
            return nil
        }

        // 归档的 plist 直接渲染出来是 $objects + CF$UID 的引用汤，
        // 交给 NSKeyedUnarchiver 还原成真正的对象图
        if let dictionary = object as? [AnyHashable: Any], dictionary["$archiver"] != nil {
            if let root = unarchive(data, topKey: topKey(in: dictionary)) {
                return DecodedPayload(formatName: "\(base) · NSKeyedArchiver",
                                      text: render(root))
            }
            // 含无法实例化的自定义类时还原会失败，退回原始结构总比什么都不给强
            return DecodedPayload(formatName: "\(base) · NSKeyedArchiver（对象图未能还原）",
                                  text: render(object))
        }

        return DecodedPayload(formatName: base, text: render(object))
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

    /// `archivedData(withRootObject:)` 存的键是 `root`，但用 `encode(_:forKey:)`
    /// 手写的归档可以是任意键，写死 `root` 会白白解不出来。`$top` 里就有真正的键名。
    private static func topKey(in archive: [AnyHashable: Any]) -> String {
        guard let top = archive["$top"] as? [AnyHashable: Any],
              let key = top.keys.map({ String(describing: $0) }).sorted().first else {
            return NSKeyedArchiveRootObjectKey
        }
        return key
    }

    private static func unarchive(_ data: Data, topKey: String) -> Any? {
        guard let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data) else { return nil }
        // 归档里多是 NSDictionary / NSString / NSNumber，但也可能有自定义类；
        // 关掉安全编码要求才能尽量还原，失败时下面会退回原始结构
        unarchiver.requiresSecureCoding = false
        defer { unarchiver.finishDecoding() }
        return try? unarchiver.decodeTopLevelObject(forKey: topKey)
    }

    // MARK: - JSON

    private static func decodeJSON(_ data: Data) -> DecodedPayload? {
        guard let first = data.first,
              first == UInt8(ascii: "{") || first == UInt8(ascii: "[") else { return nil }
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: object,
                                                       options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: pretty, encoding: .utf8) else {
            return nil
        }
        return DecodedPayload(formatName: "JSON", text: text)
    }

    // MARK: - DER / ASN.1

    private static func decodeDER(_ data: Data) -> DecodedPayload? {
        // ASN.1 SEQUENCE + 长格式长度，是证书和 RSA/EC 公钥的开头
        guard data.count > 2, data[data.startIndex] == 0x30 else { return nil }

        if let certificate = SecCertificateCreateWithData(nil, data as CFData) {
            var lines = ["X.509 证书，\(data.count) 字节"]
            if let summary = SecCertificateCopySubjectSummary(certificate) as String?, !summary.isEmpty {
                lines.append("主体：\(summary)")
            }
            return DecodedPayload(formatName: "DER 证书", text: lines.joined(separator: "\n"))
        }

        return DecodedPayload(
            formatName: "DER / ASN.1",
            text: "以 SEQUENCE 开头的 ASN.1 结构，\(data.count) 字节。\n"
                + "常见于 RSA / EC 公钥。本工具只做识别，不展开完整 ASN.1。"
        )
    }

    // MARK: - 渲染

    private static func render(_ value: Any, indent: Int = 0) -> String {
        // 归档还原出来的对象图可能有环（自定义类互相引用），必须封顶
        guard indent < 32 else { return "…" }

        let pad = String(repeating: "  ", count: indent)

        // 字典要排在数组前面判断：NSDictionary 桥接过来也能匹配序列
        if let dictionary = value as? [AnyHashable: Any] {
            guard !dictionary.isEmpty else { return "{}" }
            let body = dictionary
                .map { (String(describing: $0.key), $0.value) }
                .sorted { $0.0 < $1.0 }
                .map { "\(pad)  \($0.0): \(render($0.1, indent: indent + 1))" }
                .joined(separator: "\n")
            return "{\n\(body)\n\(pad)}"
        }

        if let array = value as? [Any] {
            guard !array.isEmpty else { return "[]" }
            let body = array
                .map { "\(pad)  \(render($0, indent: indent + 1))" }
                .joined(separator: "\n")
            return "[\n\(body)\n\(pad)]"
        }

        if let data = value as? Data {
            // 嵌套的 Data 常常又是一层归档，能读成文本就直接显示
            if let text = String(data: data, encoding: .utf8), isPrintable(text) {
                return "\"\(text)\"  (\(data.count) 字节)"
            }
            return "<\(data.count) 字节二进制>"
        }

        if let date = value as? Date {
            return dateFormatter.string(from: date)
        }

        if let string = value as? String {
            return "\"\(string)\""
        }

        return "\(value)"
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
