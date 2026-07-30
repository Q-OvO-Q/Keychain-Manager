import Foundation

// MARK: - 描述文件数据模型

struct ProvisioningProfile {
    let name: String
    let keychainAccessGroups: [String]
    let applicationIdentifier: String
    let teamIdentifier: String
    let appIdentifierPrefix: [String]
    let applicationGroups: [String]
    let expirationDate: Date?

    /// 用于替换 entitlements 里的 `$(AppIdentifierPrefix)` 占位符
    var identifierPrefix: String {
        appIdentifierPrefix.first(where: { !$0.isEmpty }) ?? teamIdentifier
    }

    /// 通配符 Group（TEAMID.*）。只有描述文件本身授予了通配符权限时查询才会成功
    var wildcardGroup: String? {
        let prefix = identifierPrefix
        guard !prefix.isEmpty else { return nil }
        return "\(prefix).*"
    }

    /// 汇总所有可用作 kSecAttrAccessGroup 的取值。
    ///
    /// 包含通配符、显式声明的 keychain-access-groups、application-identifier
    /// （它本身就是应用的默认 keychain 组），以及 App Group —— 在 iOS 上
    /// App Group 标识符同样可以当作 keychain access group 使用。
    var allAccessGroups: [String] {
        var groups: [String] = []

        func append(_ group: String) {
            let resolved = resolvePlaceholders(in: group)
            guard !resolved.isEmpty, !groups.contains(resolved) else { return }
            groups.append(resolved)
        }

        if let wildcard = wildcardGroup { append(wildcard) }
        keychainAccessGroups.forEach(append)
        append(applicationIdentifier)
        applicationGroups.forEach(append)

        return groups
    }

    var summary: String {
        var parts: [String] = []
        if !name.isEmpty { parts.append(name) }
        if !identifierPrefix.isEmpty { parts.append("Team \(identifierPrefix)") }
        if let expirationDate {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd"
            let expired = expirationDate < Date() ? "已过期 " : "有效至 "
            parts.append(expired + formatter.string(from: expirationDate))
        }
        return parts.joined(separator: " · ")
    }

    /// entitlements 中可能残留 `$(AppIdentifierPrefix)` 之类的占位符
    private func resolvePlaceholders(in group: String) -> String {
        let prefix = identifierPrefix
        guard !prefix.isEmpty else { return group }
        return group
            .replacingOccurrences(of: "$(AppIdentifierPrefix)", with: prefix + ".")
            .replacingOccurrences(of: "$(TeamIdentifierPrefix)", with: prefix + ".")
            // 占位符本身通常已带尾点，替换后可能出现连续两个点
            .replacingOccurrences(of: "..", with: ".")
    }
}

// MARK: - 描述文件解析器

enum ProvisioningProfileParser {

    /// 解析应用内嵌的 embedded.mobileprovision
    static func parse() -> ProvisioningProfile? {
        guard let data = loadProfileData(), let plist = extractPlist(from: data) else {
            return nil
        }

        let entitlements = plist["Entitlements"] as? [String: Any] ?? [:]

        return ProvisioningProfile(
            name: plist["Name"] as? String ?? "",
            keychainAccessGroups: entitlements["keychain-access-groups"] as? [String] ?? [],
            applicationIdentifier: entitlements["application-identifier"] as? String ?? "",
            teamIdentifier: (plist["TeamIdentifier"] as? [String])?.first ?? "",
            appIdentifierPrefix: plist["ApplicationIdentifierPrefix"] as? [String] ?? [],
            applicationGroups: entitlements["com.apple.security.application-groups"] as? [String] ?? [],
            expirationDate: plist["ExpirationDate"] as? Date
        )
    }

    /// 描述文件通常在 .app 根目录，越狱/重签环境下也可能落在其它位置
    private static func loadProfileData() -> Data? {
        if let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
           let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
            return data
        }

        let fallback = Bundle.main.bundleURL.appendingPathComponent("embedded.mobileprovision")
        return try? Data(contentsOf: fallback)
    }

    /// 从 CMS/PKCS#7 签名容器里截出内嵌的 XML plist
    private static func extractPlist(from data: Data) -> [String: Any]? {
        guard let startMarker = "<?xml".data(using: .utf8),
              let endMarker = "</plist>".data(using: .utf8),
              let startRange = data.range(of: startMarker) else {
            return nil
        }

        // 只在起始标记之后搜索结束标记，避免构造出无效区间
        guard let endRange = data.range(of: endMarker,
                                       options: [],
                                       in: startRange.lowerBound..<data.endIndex) else {
            return nil
        }

        let plistData = Data(data[startRange.lowerBound..<endRange.upperBound])

        return try? PropertyListSerialization.propertyList(
            from: plistData,
            format: nil
        ) as? [String: Any]
    }
}
