import Foundation

// MARK: - 描述文件数据模型
struct ProvisioningProfile {
    let keychainAccessGroups: [String]
    let applicationIdentifier: String
    let teamIdentifier: String
    let appIdentifierPrefix: [String]
    
    /// 通过 TeamID 前缀生成通配符 Group (例如 "TEAMID.*")
    var wildcardGroup: String? {
        // 查找第一个非空前缀
        let prefix = appIdentifierPrefix.first(where: { !$0.isEmpty }) ?? teamIdentifier
        guard !prefix.isEmpty else { return nil }
        return "\(prefix).*"
    }
}

// MARK: - 描述文件解析器
enum ProvisioningProfileParser {
    
    /// 解析应用内嵌的 embedded.mobileprovision 文件
    /// 提取 keychain-access-groups 等关键信息
    static func parse() -> ProvisioningProfile? {
        guard let profilePath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let profileData = try? Data(contentsOf: URL(fileURLWithPath: profilePath)) else {
            return nil
        }
        
        guard let plistDict = extractPlist(from: profileData) else {
            return nil
        }
        
        let entitlements = plistDict["Entitlements"] as? [String: Any] ?? [:]
        let keychainGroups = entitlements["keychain-access-groups"] as? [String] ?? []
        let appId = entitlements["application-identifier"] as? String ?? ""
        let teamId = (plistDict["TeamIdentifier"] as? [String])?.first ?? ""
        let appIdPrefix = plistDict["ApplicationIdentifierPrefix"] as? [String] ?? []
        
        return ProvisioningProfile(
            keychainAccessGroups: keychainGroups,
            applicationIdentifier: appId,
            teamIdentifier: teamId,
            appIdentifierPrefix: appIdPrefix
        )
    }
    
    /// 从 CMS/PKCS#7 签名数据中提取 XML plist
    private static func extractPlist(from data: Data) -> [String: Any]? {
        // mobileprovision 文件是 CMS SignedData 结构
        // 其中包含一段 XML plist，通过标记定位并提取
        guard let startMarker = "<?xml".data(using: .utf8),
              let endMarker = "</plist>".data(using: .utf8),
              let startRange = data.range(of: startMarker) else {
            return nil
        }
        
        // 仅在 XML 起始标记之后搜索结束标记，避免生成无效范围
        guard let endRange = data.range(of: endMarker,
                                        options: [],
                                        in: startRange.lowerBound..<data.endIndex) else {
            return nil
        }
        
        let plistData = data[startRange.lowerBound..<endRange.upperBound]
        
        return try? PropertyListSerialization.propertyList(
            from: Data(plistData),
            format: nil
        ) as? [String: Any]
    }
}
