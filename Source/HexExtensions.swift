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
    /// 会忽略空白与常见分隔符，并剥掉每个片段**开头**的 `0x` / `0X` 前缀；
    /// 长度为奇数或含非法字符时返回 nil。
    /// 旧实现遇到奇数长度会静默丢掉最后半个字节，遇到换行则整体返回 nil 且调用方未作提示。
    ///
    /// 前缀只认片段开头，不能在整串里盲目删除 "0x"：那会把前一个字节的 0 一起吃掉
    /// （"a0xb" 变成 "ab"，写入的字节完全不对），两次顺序替换还能互相制造新的匹配
    /// （"00xX" 删成空串）。逐字符校验而不是用 `UInt8(_:radix:)`：
    /// 后者接受前导 "+"，会把 "+a" 静默解析成 0x0A 而不是报非法。
    var hexData: Data? {
        let separators: Set<Character> = [" ", "\t", "\r", "\n", ":", "-", "_", ",", "<", ">"]

        var nibbles: [UInt8] = []
        nibbles.reserveCapacity(count)
        for token in split(whereSeparator: { separators.contains($0) }) {
            var body = token
            if body.hasPrefix("0x") || body.hasPrefix("0X") {
                body = body.dropFirst(2)
            }
            for character in body {
                guard let value = character.hexDigitValue, character.isASCII else { return nil }
                nibbles.append(UInt8(value))
            }
        }

        guard nibbles.count % 2 == 0 else { return nil }

        var data = Data(capacity: nibbles.count / 2)
        var index = 0
        while index < nibbles.count {
            data.append(nibbles[index] << 4 | nibbles[index + 1])
            index += 2
        }
        return data
    }
}
