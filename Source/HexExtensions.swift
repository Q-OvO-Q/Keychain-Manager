import Foundation

extension Data {
    var hexString: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension String {
    var hexData: Data? {
        // Remove whitespace and validate characters
        let hexString = self.filter { !$0.isWhitespace }
        
        // Check if string has odd length
        guard hexString.count % 2 == 0 else {
            return nil
        }
        
        var data = Data()
        var temp = ""
        for char in hexString {
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
