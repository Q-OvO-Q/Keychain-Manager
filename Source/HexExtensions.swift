import Foundation

extension Data {
    /// 小写十六进制字符串。用查表拼接，避免为每个字节走一次 String(format:)
    var hexString: String {
        let digits = Array("0123456789abcdef".utf8)
        var output = [UInt8]()
        output.reserveCapacity(count * 2)
        for byte in self {
            output.append(digits[Int(byte >> 4)])
            output.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// 内容是否为合法 UTF-8 文本
    var utf8Text: String? {
        String(data: self, encoding: .utf8)
    }
}

extension String {
    /// 解析十六进制字符串。
    ///
    /// 会忽略空白、`0x` 前缀与常见分隔符；长度为奇数或含非法字符时返回 nil。
    /// 旧实现遇到奇数长度会静默丢掉最后半个字节，遇到换行则整体返回 nil 且调用方未作提示。
    var hexData: Data? {
        let ignored: Set<Character> = [" ", "\t", "\r", "\n", ":", "-", "_", ",", "<", ">"]
        let filtered: String = filter { !ignored.contains($0) }
        let stripped = filtered
            .replacingOccurrences(of: "0x", with: "")
            .replacingOccurrences(of: "0X", with: "")

        guard !stripped.isEmpty else { return Data() }
        guard stripped.count % 2 == 0 else { return nil }

        var data = Data(capacity: stripped.count / 2)
        var index = stripped.startIndex
        while index < stripped.endIndex {
            let next = stripped.index(index, offsetBy: 2)
            guard let byte = UInt8(stripped[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}
