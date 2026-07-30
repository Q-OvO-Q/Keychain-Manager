import Foundation
import Security

// MARK: - 条目类别

enum KeychainItemClass: String, CaseIterable, Identifiable {
    case genericPassword
    case internetPassword
    case key
    case certificate

    var id: String { rawValue }

    /// 对应的 kSecClass 取值
    var secClass: String {
        switch self {
        case .genericPassword:  return kSecClassGenericPassword as String
        case .internetPassword: return kSecClassInternetPassword as String
        case .key:              return kSecClassKey as String
        case .certificate:      return kSecClassCertificate as String
        }
    }

    var displayName: String {
        switch self {
        case .genericPassword:  return "通用"
        case .internetPassword: return "网络"
        case .key:              return "密钥"
        case .certificate:      return "证书"
        }
    }

    /// 只有密码类条目支持修改 kSecValueData
    var supportsDataEditing: Bool {
        self == .genericPassword || self == .internetPassword
    }

    /// 该类别在 keychain 中的完整主键属性。
    ///
    /// 删除与更新都必须按完整主键定位：属性给少了会匹配到同组的兄弟条目（误删），
    /// 给错了则一条也匹配不上（表现为「删除成功但刷新后又出现」）。
    var primaryKeyAttributes: [String] {
        switch self {
        case .genericPassword:
            return [kSecAttrAccount, kSecAttrService, kSecAttrGeneric,
                    kSecAttrAccessGroup, kSecAttrSynchronizable].map { $0 as String }
        case .internetPassword:
            return [kSecAttrAccount, kSecAttrSecurityDomain, kSecAttrServer,
                    kSecAttrProtocol, kSecAttrAuthenticationType, kSecAttrPort, kSecAttrPath,
                    kSecAttrAccessGroup, kSecAttrSynchronizable].map { $0 as String }
        case .key:
            return [kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrKeyClass,
                    kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrEffectiveKeySize,
                    kSecAttrAccessGroup, kSecAttrSynchronizable].map { $0 as String }
        case .certificate:
            return [kSecAttrCertificateType, kSecAttrIssuer, kSecAttrSerialNumber,
                    kSecAttrAccessGroup, kSecAttrSynchronizable].map { $0 as String }
        }
    }

    /// 足以把单条记录从同组其它条目里区分出来的属性。
    /// 一条都拿不到时禁止按属性删除 —— 那样的查询会命中整个 Access Group。
    var identityAttributes: [String] {
        switch self {
        case .genericPassword:
            return [kSecAttrAccount, kSecAttrService].map { $0 as String }
        case .internetPassword:
            return [kSecAttrAccount, kSecAttrServer].map { $0 as String }
        case .key:
            return [kSecAttrApplicationLabel, kSecAttrApplicationTag].map { $0 as String }
        case .certificate:
            return [kSecAttrIssuer, kSecAttrSerialNumber, kSecAttrLabel].map { $0 as String }
        }
    }
}

// MARK: - 条目模型

struct KeychainItem: Identifiable {
    /// SwiftUI 身份标识。优先取自持久引用，因此跨刷新保持稳定（选中状态、导航不会错乱）
    let id: String

    let itemClass: KeychainItemClass

    /// SecItemCopyMatching 回传的原始属性，仅用于详情展示
    let rawAttributes: [String: Any]

    /// 精确指向该条目的持久引用（编码了 class + rowid，跨进程稳定）
    let persistentRef: Data?

    /// 按完整主键构造的查询，用于 SecItemDelete / SecItemUpdate
    let primaryKeyQuery: [String: Any]

    /// 退化查询：仅在系统回传的属性类型异常、完整主键查询被拒时使用
    let minimalPrimaryKeyQuery: [String: Any]?

    /// 展示用标题（可能是占位文案，**绝不可**放进查询）
    let displayTitle: String

    let account: String
    let accessGroup: String
    let isSynchronizable: Bool

    /// 标签存储键。沿用历史格式以免升级后丢失用户已打的标签
    let tagKey: String

    /// nil 表示尚未读取；非 nil 时 dataStatus 为 errSecSuccess 才代表内容有效
    var data: Data?
    var dataStatus: OSStatus?

    var appTag: String { TagManager.shared.tag(for: tagKey) }

    /// 无持久引用、也没有任何区分性属性时，任何删除查询都会波及同组其它条目
    var canBeTargeted: Bool {
        if persistentRef != nil { return true }
        return itemClass.identityAttributes.contains { primaryKeyQuery[$0] != nil }
    }

    var isDataReadable: Bool {
        guard let status = dataStatus else { return false }
        return status == errSecSuccess
    }

    // MARK: 初始化

    init(itemClass: KeychainItemClass, attributes: [String: Any], fallbackIndex: Int) {
        self.itemClass = itemClass
        self.rawAttributes = attributes

        let persistentRef = attributes[kSecValuePersistentRef as String] as? Data
        self.persistentRef = persistentRef

        let account = KeychainItem.stringValue(attributes[kSecAttrAccount as String]) ?? ""
        let group = KeychainItem.stringValue(attributes[kSecAttrAccessGroup as String]) ?? ""
        self.account = account
        self.accessGroup = group

        let syncNumber = attributes[kSecAttrSynchronizable as String] as? NSNumber
        let synchronizable = syncNumber?.boolValue ?? false
        self.isSynchronizable = synchronizable

        // 标题分两份：keyPart 是真实属性值（可为空串），display 才允许出现占位文案。
        // 旧版本把「未知 Service」当成真实 service 塞进删除查询，导致条目永远删不掉。
        let (display, keyPart) = KeychainItem.makeTitle(itemClass: itemClass, attributes: attributes)
        self.displayTitle = display

        let tagKey = KeychainItem.makeTagKey(classDisplay: itemClass.displayName,
                                             title: keyPart,
                                             account: account,
                                             accessGroup: group)
        self.tagKey = tagKey

        // 完整主键查询：直接回传系统给出的属性值，避免任何自制的类型转换
        var query: [String: Any] = [kSecClass as String: itemClass.secClass]
        for attribute in itemClass.primaryKeyAttributes {
            if let value = attributes[attribute] {
                query[attribute] = value
            }
        }
        // 同步属性必须显式给出：查询缺省按 false 处理，会漏掉 iCloud 同步条目
        query[kSecAttrSynchronizable as String] = synchronizable
        self.primaryKeyQuery = query

        // 退化查询同样只回传系统给出的原始值：account 可能是 Data 而非 String，
        // 用转换后的字符串反而匹配不上
        var minimal: [String: Any] = [
            kSecClass as String: itemClass.secClass,
            kSecAttrSynchronizable as String: synchronizable
        ]
        if let rawGroup = attributes[kSecAttrAccessGroup as String] {
            minimal[kSecAttrAccessGroup as String] = rawGroup
        }
        var minimalHasIdentity = false
        for attribute in itemClass.identityAttributes {
            if let value = attributes[attribute] {
                minimal[attribute] = value
                minimalHasIdentity = true
            }
        }
        self.minimalPrimaryKeyQuery = minimalHasIdentity ? minimal : nil

        if let ref = persistentRef {
            self.id = "ref:" + ref.base64EncodedString()
        } else {
            self.id = "key:\(tagKey)#\(fallbackIndex)"
        }
    }

    /// 与历史版本一致的标签键格式，升级后已有标签继续生效
    static func makeTagKey(classDisplay: String, title: String, account: String, accessGroup: String) -> String {
        let separator = "|||"
        return "\(classDisplay)\(separator)\(title)\(separator)\(account)\(separator)\(accessGroup)"
    }

    // MARK: 辅助

    /// keychain 属性可能以 String / Data / NSNumber 任一形式回传
    static func stringValue(_ value: Any?) -> String? {
        guard let value else { return nil }
        if let string = value as? String { return string }
        if let data = value as? Data { return String(data: data, encoding: .utf8) }
        if let number = value as? NSNumber { return number.stringValue }
        return nil
    }

    /// 返回 (展示标题, 用于标签键的真实属性值)
    private static func makeTitle(itemClass: KeychainItemClass,
                                 attributes: [String: Any]) -> (String, String) {
        let label = stringValue(attributes[kSecAttrLabel as String]) ?? ""

        switch itemClass {
        case .genericPassword:
            let service = stringValue(attributes[kSecAttrService as String]) ?? ""
            if !service.isEmpty { return (service, service) }
            if !label.isEmpty { return (label, service) }
            return ("(无 Service)", service)

        case .internetPassword:
            let server = stringValue(attributes[kSecAttrServer as String]) ?? ""
            if !server.isEmpty { return (server, server) }
            if !label.isEmpty { return (label, server) }
            return ("(无 Server)", server)

        case .key:
            if !label.isEmpty { return (label, label) }
            if let tag = stringValue(attributes[kSecAttrApplicationTag as String]), !tag.isEmpty {
                return (tag, tag)
            }
            if let appLabel = attributes[kSecAttrApplicationLabel as String] as? Data {
                let hex = appLabel.hexString
                return ("Key " + String(hex.prefix(16)), hex)
            }
            return ("(未命名密钥)", "")

        case .certificate:
            if !label.isEmpty { return (label, label) }
            if let serial = attributes[kSecAttrSerialNumber as String] as? Data {
                let hex = serial.hexString
                return ("Cert " + String(hex.prefix(16)), hex)
            }
            return ("(未命名证书)", "")
        }
    }
}

// MARK: - Identifiable / Hashable

extension KeychainItem: Hashable {
    static func == (lhs: KeychainItem, rhs: KeychainItem) -> Bool {
        lhs.id == rhs.id && lhs.data == rhs.data && lhs.dataStatus == rhs.dataStatus
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

// MARK: - 属性展示格式化

enum KeychainAttributeFormatter {

    /// keychain 属性名是四字符短码（acct / svce / agrp …），这里翻译成可读名称
    static func label(for key: String) -> String {
        if let known = names[key] { return "\(known)  (\(key))" }
        return key
    }

    static func value(_ value: Any) -> String {
        if let string = value as? String { return string.isEmpty ? "(空字符串)" : string }
        if let date = value as? Date { return dateFormatter.string(from: date) }
        if let data = value as? Data {
            if let text = String(data: data, encoding: .utf8),
               !text.isEmpty,
               text.rangeOfCharacter(from: .controlCharacters) == nil {
                return "\(text)  ·  \(data.count) 字节"
            }
            return "HEX \(data.hexString)  ·  \(data.count) 字节"
        }
        if let number = value as? NSNumber { return number.stringValue }
        return "\(value)"
    }

    /// kSecAttrAccessible 的短码含义，是判断条目为何读不出来的关键线索
    static func accessibilityDescription(_ raw: String) -> String {
        accessibilityNames[raw] ?? raw
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    private static let accessibilityNames: [String: String] = dictionary(from: [
        (kSecAttrAccessibleWhenUnlocked as String, "解锁后可访问"),
        (kSecAttrAccessibleAfterFirstUnlock as String, "首次解锁后可访问"),
        (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String, "解锁后可访问 · 仅本机"),
        (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String, "首次解锁后可访问 · 仅本机"),
        (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String, "需设置密码 · 仅本机"),
        // 已废弃的常量不再引用，直接用其短码
        ("dk", "始终可访问（已废弃）"),
        ("dku", "始终可访问 · 仅本机（已废弃）")
    ])

    /// 多个 kSecAttr 常量会共用同一个短码（例如 kSecAttrType 与 kSecAttrKeyType 都是 "type"），
    /// 因此不能直接写字典字面量 —— 重复键会在运行时直接 trap。
    private static let names: [String: String] = dictionary(from: [
        (kSecClass as String, "类别"),
        (kSecAttrAccount as String, "账号"),
        (kSecAttrService as String, "服务"),
        (kSecAttrServer as String, "服务器"),
        (kSecAttrAccessGroup as String, "访问组"),
        (kSecAttrAccessible as String, "可访问性"),
        (kSecAttrSynchronizable as String, "iCloud 同步"),
        (kSecAttrCreationDate as String, "创建时间"),
        (kSecAttrModificationDate as String, "修改时间"),
        (kSecAttrLabel as String, "标签"),
        (kSecAttrDescription as String, "描述"),
        (kSecAttrComment as String, "备注"),
        (kSecAttrCreator as String, "创建者"),
        (kSecAttrType as String, "类型码 / 密钥算法"),
        (kSecAttrKeyType as String, "类型码 / 密钥算法"),
        (kSecAttrGeneric as String, "通用字段"),
        (kSecAttrIsInvisible as String, "隐藏"),
        (kSecAttrIsNegative as String, "占位条目"),
        (kSecAttrSecurityDomain as String, "安全域"),
        (kSecAttrProtocol as String, "协议"),
        (kSecAttrAuthenticationType as String, "认证类型"),
        (kSecAttrPort as String, "端口"),
        (kSecAttrPath as String, "路径"),
        (kSecAttrApplicationLabel as String, "应用标签"),
        (kSecAttrApplicationTag as String, "应用 Tag"),
        (kSecAttrKeyClass as String, "密钥类别"),
        (kSecAttrKeySizeInBits as String, "密钥位数"),
        (kSecAttrEffectiveKeySize as String, "有效位数"),
        (kSecAttrCertificateType as String, "证书类型"),
        (kSecAttrCertificateEncoding as String, "证书编码"),
        (kSecAttrSubject as String, "主体"),
        (kSecAttrIssuer as String, "签发者"),
        (kSecAttrSerialNumber as String, "序列号"),
        (kSecAttrSubjectKeyID as String, "主体密钥 ID"),
        (kSecAttrPublicKeyHash as String, "公钥哈希"),
        (kSecValueData as String, "数据"),
        (kSecValuePersistentRef as String, "持久引用")
    ])

    /// 保留首次出现的映射，重复键直接忽略
    private static func dictionary(from pairs: [(String, String)]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in pairs where result[key] == nil {
            result[key] = value
        }
        return result
    }
}
