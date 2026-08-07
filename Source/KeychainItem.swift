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

    /// 该类别在 keychain 表里已知的列。
    ///
    /// `SecItemCopyMatching` **只回传有值的键**，没设过的属性直接不出现在结果里。
    /// 详情页靠这份清单把「未设置」的属性也列出来，否则看起来就像这些属性不存在，
    /// 也会和「可修改的元数据」那一节对不上（那节是固定列出的）。
    var knownAttributes: [String] {
        // alis 实测出现在 1385/1467 条上（每个 App 容器一个 UUID）。
        // 它没有公开常量，但确实是这张表里的一列，缺了它没设过的条目就看不出「本可以有」
        let shared = [kSecAttrLabel, kSecAttrCreationDate, kSecAttrModificationDate,
                      kSecAttrAccessGroup, kSecAttrAccessible, kSecAttrSynchronizable]
            .map { $0 as String } + ["accc", "alis"]

        switch self {
        case .genericPassword:
            return [kSecAttrAccount, kSecAttrService, kSecAttrGeneric,
                    kSecAttrDescription, kSecAttrComment, kSecAttrCreator,
                    kSecAttrType, kSecAttrIsInvisible, kSecAttrIsNegative]
                .map { $0 as String } + shared

        case .internetPassword:
            return [kSecAttrAccount, kSecAttrSecurityDomain, kSecAttrServer,
                    kSecAttrProtocol, kSecAttrAuthenticationType, kSecAttrPort, kSecAttrPath,
                    kSecAttrDescription, kSecAttrComment, kSecAttrCreator,
                    kSecAttrType, kSecAttrIsInvisible, kSecAttrIsNegative]
                .map { $0 as String } + shared

        case .key:
            return [kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrKeyClass,
                    kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrEffectiveKeySize,
                    kSecAttrCreator,
                    kSecAttrIsPermanent, kSecAttrCanEncrypt, kSecAttrCanDecrypt,
                    kSecAttrCanDerive, kSecAttrCanSign, kSecAttrCanVerify,
                    kSecAttrCanWrap, kSecAttrCanUnwrap]
                .map { $0 as String }
                // 密钥这一类系统还会回传一批没有公开常量的列，实测 99 条密钥里
                // 29～53 条带着它们。不列出来，没设过的那些看起来就像这些属性不存在
                + ["sens", "asen", "extr", "next", "priv", "modi",
                   "snrc", "vyrc", "sdat", "edat", "tkid"]
                + shared

        case .certificate:
            return [kSecAttrCertificateType, kSecAttrCertificateEncoding,
                    kSecAttrSubject, kSecAttrIssuer, kSecAttrSerialNumber,
                    kSecAttrSubjectKeyID, kSecAttrPublicKeyHash]
                .map { $0 as String } + shared
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
            // kcls 必须带上：klbl 是公钥的 SHA-1，**一对密钥的公私钥共用同一个值**，
            // 加上 atag 也一样。只按 klbl+atag 删会把另一半一起删掉 ——
            // 实测导出里就有这样一对，除 kcls 和用途标志外完全相同。
            return [kSecAttrApplicationLabel, kSecAttrApplicationTag, kSecAttrKeyClass]
                .map { $0 as String }
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

    /// 预先拼好的小写检索串，查询结束时填充一次。
    /// 上千条目时若每次按键都实时拼字符串并把 Data 转成 String，输入会明显卡顿。
    /// 标签不在其中 —— 它随时可改，检索时单独查（字典查找，很便宜）。
    var searchIndex: String = ""

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

        // 密钥 / 证书的标签键刻意**不用 labl**：它是可编辑的，
        // 拿它当键的话，用户改一次标签就会让已打的 App 标签失联。
        // 改用主键里的稳定标识（klbl / atag、slnr），显示仍优先用 labl。
        case .key:
            let stable = (attributes[kSecAttrApplicationLabel as String] as? Data)?.hexString
                ?? stringValue(attributes[kSecAttrApplicationTag as String])
                ?? ""
            if !label.isEmpty { return (label, stable) }
            if let tag = stringValue(attributes[kSecAttrApplicationTag as String]), !tag.isEmpty {
                return (tag, stable)
            }
            if !stable.isEmpty { return ("Key " + String(stable.prefix(16)), stable) }
            return ("(未命名密钥)", "")

        case .certificate:
            let stable = (attributes[kSecAttrSerialNumber as String] as? Data)?.hexString ?? ""
            if !label.isEmpty { return (label, stable) }
            if !stable.isEmpty { return ("Cert " + String(stable.prefix(16)), stable) }
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

    /// crtr / type 存的是 32 位整数，但惯例按四个 ASCII 字符看，
    /// 直接显示数字（如 1634758764）没人认得出来
    static func value(_ value: Any, forKey key: String,
                      itemClass: KeychainItemClass? = nil) -> String {
        // 保护级别是「这条为什么读不出来」的关键线索，却一直只显示 ak / ck / dku
        // 这样的短码。accessibilityDescription 早就知道它们的含义，只是没接上来。
        if key == kSecAttrAccessible as String, let raw = KeychainItem.stringValue(value) {
            let name = accessibilityDescription(raw)
            return name == raw ? raw : "\(name)  ·  \(raw)"
        }

        // 密钥类别只显示 0 / 1，看不出是公钥还是私钥 —— 而删除定位正是靠它区分密钥对
        if key == kSecAttrKeyClass as String, let raw = KeychainItem.stringValue(value) {
            if let name = keyClassNames[raw] { return "\(name)  ·  \(raw)" }
        }

        // type 这一列在密码类里是四字符码，在密钥里却是算法编号（RSA=42、EC=73）
        if key == kSecAttrKeyType as String, itemClass == .key,
           let raw = KeychainItem.stringValue(value) {
            if let name = keyTypeNames[raw] { return "\(name)  ·  \(raw)" }
            return raw
        }

        let fourCharCodeKeys = [kSecAttrCreator as String, kSecAttrType as String]
        if fourCharCodeKeys.contains(key), let number = value as? NSNumber {
            let code = KeychainStore.FourCharCode.text(from: number)
            return code == number.stringValue ? code : "\(code)  ·  \(number.stringValue)"
        }
        return self.value(value)
    }

    /// 取值是 Security 框架的常量，但系统按数字回传
    private static let keyClassNames: [String: String] = [
        "0": "公钥", "1": "私钥", "2": "对称密钥"
    ]

    private static let keyTypeNames: [String: String] = [
        "42": "RSA", "73": "椭圆曲线 EC", "0": "未指定"
    ]

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
        // 固定格式串配 POSIX 区域：设备用非公历日历时，年份会按那套纪年输出
        formatter.locale = Locale(identifier: "en_US_POSIX")
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
        (kSecValuePersistentRef as String, "持久引用"),

        // 以下短码没有对应的公开常量，但系统确实会回传，只能按 securityd 的
        // 表结构直接写字面量。缺了它们详情页就会出现一串看不懂的四字母。
        ("accc", "访问控制 SecAccessControl"),
        ("tomb", "墓碑标记（已删除待同步）"),
        ("musr", "多用户 / Persona 标识"),
        ("sha1", "证书 SHA-1 指纹"),
        ("vwht", "同步视图提示 View Hint"),
        ("tkid", "令牌 ID"),
        ("sysb", "系统绑定"),
        ("UUID", "条目 UUID"),
        ("persistref", "持久引用"),
        ("alis", "别名 Alias"),
        ("scrp", "脚本码"),
        ("cusi", "自定义图标"),
        ("prot", "保护数据"),
        ("pcss", "受保护类密钥"),
        ("pcsk", "受保护类公钥"),
        ("pcsi", "受保护类标识"),
        ("sdat", "生效时间"),
        ("edat", "失效时间"),
        // 密钥用途位
        ("sens", "敏感 Sensitive"),
        ("asen", "总是敏感"),
        ("extr", "可导出"),
        ("next", "永不可导出"),
        ("encr", "可用于加密"),
        ("decr", "可用于解密"),
        ("drve", "可用于派生"),
        ("sign", "可用于签名"),
        ("vrfy", "可用于验签"),
        ("snrc", "可用于恢复签名"),
        ("vyrc", "可用于恢复验签"),
        ("wrap", "可用于包装密钥"),
        ("unwp", "可用于解包密钥"),
        ("priv", "私钥"),
        ("modi", "可修改"),
        ("perm", "永久存储")
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
