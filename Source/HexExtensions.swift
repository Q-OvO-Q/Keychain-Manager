import Foundation

extension Data {
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension String {
    var hexData: Data? {
        var data = Data()
        var temp = ""
        for char in self {
            temp.append(char)
            if temp.count == 2 {
                guard let byte = UInt8(temp, radix: 16) else { return nil }
                data.append(byte)
                temp = ""
            }
        }
        return data
    }
}
