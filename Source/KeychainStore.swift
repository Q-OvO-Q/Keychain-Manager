import Foundation
import Security
import LocalAuthentication

// MARK: - 查询范围

enum KeychainScope: Equatable, Hashable {
    /// 不限定 Access Group：返回本应用有权访问的全部条目，也不受通配符 Group 权限限制
    case allAccessible
    case group(String)

    var displayName: String {
        switch self {
        case .allAccessible:      return "全部可访问"
        case .group(let group):   return group
        }
    }
}

// MARK: - 查询结果

struct KeychainClassError {
    let itemClass: KeychainItemClass
    /// nil 表示这次是不限定 Access Group 的查询
    let accessGroup: String?
    let status: OSStatus

    var description: String {
        let scope = accessGroup.map { "「\($0)」" } ?? ""
        return "\(itemClass.displayName)\(scope)：\(KeychainStore.message(for: status))"
    }
}

struct KeychainFetchResult {
    var items: [KeychainItem] = []
    /// 逐个类别 / Access Group 记录失败原因；
    /// 只要有失败就不能把「查到 0 条」当成「确实没有」
    var classErrors: [KeychainClassError] = []
}

// MARK: - 保护级别选项

struct AccessibleOption: Identifiable {
    let title: String
    let value: String
    var id: String { value }

    static let all: [AccessibleOption] = [
        AccessibleOption(title: "解锁后可访问",
                         value: kSecAttrAccessibleWhenUnlocked as String),
        AccessibleOption(title: "首次解锁后可访问",
                         value: kSecAttrAccessibleAfterFirstUnlock as String),
        AccessibleOption(title: "解锁后 · 仅本机",
                         value: kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String),
        AccessibleOption(title: "首次解锁后 · 仅本机",
                         value: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String),
        AccessibleOption(title: "需设置密码 · 仅本机",
                         value: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
    ]

    /// 条目当前值可能是已废弃的取值（dk / dku），不在标准列表里。
    /// 那样 Picker 会选不中任何一项而显示空白，所以按需补进去。
    static func options(including current: String) -> [AccessibleOption] {
        guard !current.isEmpty, !all.contains(where: { $0.value == current }) else { return all }
        let label = KeychainAttributeFormatter.accessibilityDescription(current)
        return all + [AccessibleOption(title: label, value: current)]
    }
}

// MARK: - 操作结果

struct KeychainOperationFailure {
    let item: KeychainItem
    let status: OSStatus
}

// MARK: - Keychain 访问层

/// 所有 Security 框架调用集中在此。方法均为同步阻塞，调用方负责放到后台队列。
enum KeychainStore {

    /// errSecMissingEntitlement。部分 SDK 对该常量有平台可用性标注，直接用数值更稳妥
    private static let missingEntitlement: OSStatus = -34018

    // MARK: - 查询

    /// 两段式读取：
    /// 1. 先只取属性和持久引用（`kSecReturnData` 与 `kSecMatchLimitAll` 同时使用时，
    ///    只要结果集中有一条数据解不开，整批查询就会失败或被静默丢弃）；
    /// 2. 再逐条按持久引用取数据，单条失败不影响其它条目照常显示和删除。
    static func fetchItems(scope: KeychainScope,
                          classes: [KeychainItemClass],
                          knownGroups: [String] = [],
                          includeProtected: Bool = false,
                          loadData: Bool = true,
                          progress: ((String) -> Void)? = nil) -> KeychainFetchResult {
        var result = KeychainFetchResult()
        var rows: [(KeychainItemClass, [String: Any])] = []

        /// 跑一趟枚举并把结果收进 rows；失败时按 (类别, 组) 记录。
        ///
        /// 允许验证却失败（用户取消、整批认证失败等）时退回跳过验证再查一次，
        /// 至少把不需要验证的条目拿到手。
        func collect(itemClass: KeychainItemClass, group: String?, skipAuthenticationUI: Bool) {
            let outcome = enumerate(itemClass: itemClass,
                                   accessGroup: group,
                                   skipAuthenticationUI: skipAuthenticationUI)

            switch outcome.status {
            case errSecSuccess, errSecItemNotFound:
                rows.append(contentsOf: outcome.rows.map { (itemClass, $0) })

            default:
                if !skipAuthenticationUI {
                    let retry = enumerate(itemClass: itemClass,
                                         accessGroup: group,
                                         skipAuthenticationUI: true)
                    if retry.status == errSecSuccess || retry.status == errSecItemNotFound {
                        rows.append(contentsOf: retry.rows.map { (itemClass, $0) })
                    }
                }
                result.classErrors.append(KeychainClassError(itemClass: itemClass,
                                                             accessGroup: group,
                                                             status: outcome.status))
            }
        }

        switch scope {
        case .group(let group):
            for itemClass in classes {
                progress?("正在枚举\(itemClass.displayName)条目…")
                collect(itemClass: itemClass, group: group, skipAuthenticationUI: !includeProtected)
            }

        case .allAccessible:
            // 第一趟：不限组的兜底扫描。
            //
            // 通配符 entitlement（TEAMID.*）授予的是「该前缀下所有组」的访问权，
            // 这些组名不出现在 entitlements 里，逐组枚举永远猜不到它们；
            // 不限组查询不依赖组名，正好补上这个缺口。
            //
            // 它始终跳过验证：职责只是覆盖「名字未知的组」，而不限组查询横跨全部组，
            // 正是最初把整个通用类打掉的那条查询 —— 放开验证只会白弹一次框，
            // 然后照样整批 errSecAuthFailed，一条也换不回来。
            //
            // 由此留下一个补不上的缺口：某个未知组内条目全部受保护时，skip 会把它们
            // 全部略过，组名无从暴露，逐组也就永远猜不到这个名字。
            // 试过一个办法并已实机否掉：只请求 kSecReturnPersistentRef、不请求属性，
            // 指望「不解密元数据就不必验证」——实际照样弹验证，白费一次。
            // iOS 没有枚举 access group 的公开 API，暂时只能靠手动输入组名绕过。
            for itemClass in classes {
                progress?("正在扫描\(itemClass.displayName)条目…")
                collect(itemClass: itemClass, group: nil, skipAuthenticationUI: true)
            }

            // 把扫描结果里出现的组名并入待查列表。
            // 放在逐组之前是有意的：这样兜底新发现的组本次就能被逐组覆盖到
            // （包括其中的受保护条目），不必等下一次刷新。
            var groups = knownGroups
            var seen = Set(groups)
            for row in rows {
                guard let group = row.1[kSecAttrAccessGroup as String] as? String,
                      !group.isEmpty, seen.insert(group).inserted else { continue }
                groups.append(group)
            }

            // 第二趟：逐组枚举。单个组失败只影响它自己，
            // 不会像不限组查询那样把整个类别一起带走。
            let total = classes.count * groups.count
            var completed = 0
            for itemClass in classes {
                for group in groups {
                    completed += 1
                    if completed % 10 == 0 || completed == total {
                        progress?("正在枚举\(itemClass.displayName)条目 \(completed)/\(total)…")
                    }
                    collect(itemClass: itemClass, group: group, skipAuthenticationUI: !includeProtected)
                }
            }
        }

        // 兜底扫描和逐组枚举必然大量重叠（同一条目两趟都会命中），按持久引用去重
        rows = deduplicate(rows)

        var items: [KeychainItem] = []
        items.reserveCapacity(rows.count)

        for (index, row) in rows.enumerated() {
            var item = KeychainItem(itemClass: row.0, attributes: row.1, fallbackIndex: index)
            if loadData {
                if index % 25 == 0 {
                    progress?("正在读取数据 \(index)/\(rows.count)…")
                }
                let outcome = copyData(for: item)
                item.data = outcome.data

                // `kSecUseAuthenticationUISkip` 对需要验证的条目是**静默跳过**，
                // 取数据因此返回 errSecItemNotFound（找不到）而不是 errSecInteractionNotAllowed。
                // 但条目刚刚才枚举出来，不可能不存在 —— 照原样上报会让界面显示
                // 「读取失败 / 未找到匹配条目」，而且「解锁读取」按钮的出现条件是
                // errSecInteractionNotAllowed，于是这些条目彻底没法解锁。
                // 这里翻译成语义正确的状态。
                if outcome.status == errSecItemNotFound {
                    item.dataStatus = errSecInteractionNotAllowed
                } else {
                    item.dataStatus = outcome.status
                }
            }

            item.searchIndex = makeSearchIndex(for: item)
            items.append(item)
        }

        // 固定排序：让列表稳定，同时保证无持久引用时的回退 id 也稳定
        items.sort { lhs, rhs in
            if lhs.itemClass != rhs.itemClass {
                return classOrder(lhs.itemClass) < classOrder(rhs.itemClass)
            }
            let titleComparison = lhs.displayTitle.localizedCaseInsensitiveCompare(rhs.displayTitle)
            if titleComparison != .orderedSame {
                return titleComparison == .orderedAscending
            }
            return lhs.account.localizedCaseInsensitiveCompare(rhs.account) == .orderedAscending
        }

        result.items = items
        return result
    }

    private static func classOrder(_ itemClass: KeychainItemClass) -> Int {
        KeychainItemClass.allCases.firstIndex(of: itemClass) ?? 0
    }

    /// 把可检索字段拼成一个小写串，只在查询结束时算一次
    private static func makeSearchIndex(for item: KeychainItem) -> String {
        var parts = [item.displayTitle, item.account, item.accessGroup]
        if item.isDataReadable, let text = item.data?.utf8Text {
            parts.append(text)
        }
        return parts.joined(separator: "\n").lowercased()
    }

    /// 枚举单个类别。`accessGroup` 为 nil 表示不限定组。
    ///
    /// `skipAuthenticationUI` 决定受 `SecAccessControl` 保护的条目如何处理：
    /// 跳过则它们不会出现在结果里，不跳过则系统可能弹出验证。
    ///
    /// 注意：不能假设「取属性不需要解密所以枚举不会弹验证」。iOS 13 起 keychain 的
    /// 元数据本身也是加密的，返回属性同样要解密，受保护条目在枚举阶段就会要求验证 ——
    /// 实机上正是枚举阶段弹的验证框。
    private static func enumerate(itemClass: KeychainItemClass,
                                 accessGroup: String?,
                                 skipAuthenticationUI: Bool) -> (rows: [[String: Any]], status: OSStatus) {
        var query: [String: Any] = [
            kSecClass as String: itemClass.secClass,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnPersistentRef as String: true,
            // 缺省只返回非同步条目，iCloud 同步的条目会整批隐身
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        applyAuthenticationPolicy(to: &query, allowUI: !skipAuthenticationUI)

        var output: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &output)
        guard status == errSecSuccess else { return ([], status) }

        if let array = output as? [[String: Any]] { return (array, status) }
        if let single = output as? [String: Any] { return ([single], status) }
        return ([], status)
    }

    /// 按持久引用去重；拿不到持久引用的条目一律保留，宁可重复也不丢
    private static func deduplicate(
        _ rows: [(KeychainItemClass, [String: Any])]
    ) -> [(KeychainItemClass, [String: Any])] {
        var seen = Set<Data>()
        var unique: [(KeychainItemClass, [String: Any])] = []
        unique.reserveCapacity(rows.count)

        for row in rows {
            guard let reference = row.1[kSecValuePersistentRef as String] as? Data else {
                unique.append(row)
                continue
            }
            if seen.insert(reference).inserted {
                unique.append(row)
            }
        }
        return unique
    }

    /// 单条读取数据；返回的 status 用于向用户解释「为什么这条读不出来」。
    ///
    /// `allowAuthenticationUI` 只能由用户主动触发的操作打开，枚举列表时必须保持关闭，
    /// 原因见 `applyAuthenticationPolicy`。
    static func copyData(for item: KeychainItem,
                        allowAuthenticationUI: Bool = false) -> (data: Data?, status: OSStatus) {
        // 主动解锁时给一个显式的 LAContext：可以自定义验证提示文案，
        // 也让下面两次尝试共用同一次验证结果，不会连弹两个框
        var context: LAContext?
        if allowAuthenticationUI {
            let created = LAContext()
            created.localizedReason = "读取受保护的 Keychain 条目内容"
            context = created
        }

        var referenceStatus = errSecItemNotFound

        if let ref = item.persistentRef {
            var query: [String: Any] = [
                kSecValuePersistentRef as String: ref,
                kSecReturnData as String: true
            ]
            applyAuthenticationPolicy(to: &query, allowUI: allowAuthenticationUI, context: context)

            var output: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &output)
            if status == errSecSuccess {
                return (output as? Data ?? Data(), errSecSuccess)
            }
            referenceStatus = status

            // 枚举阶段维持原行为：只有引用失效才退回主键查询。
            // 主动解锁时两条路都试 —— 持久引用被拒不代表主键查询也会被拒。
            if !allowAuthenticationUI && status != errSecItemNotFound {
                return (nil, status)
            }
        }

        var query = item.primaryKeyQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        applyAuthenticationPolicy(to: &query, allowUI: allowAuthenticationUI, context: context)

        var output: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &output)
        if status == errSecSuccess {
            return (output as? Data ?? Data(), errSecSuccess)
        }

        // 两条路都失败时，报信息量更大的那个（「找不到」通常是最没用的那个）
        if status == errSecItemNotFound && referenceStatus != errSecItemNotFound {
            return (nil, referenceStatus)
        }
        return (nil, status)
    }

    /// 单条 `kSecMatchLimitOne` + `kSecReturnData` 查询碰上受 `SecAccessControl` 保护的条目时，
    /// 系统会弹出 Face ID / Touch ID 验证。这在枚举场景下有两个后果：
    /// 刷新一次列表就要连续验证 N 次；且 Info.plist 缺少 `NSFaceIDUsageDescription` 时，
    /// 系统会直接终止进程（启动即闪退）。
    /// 因此枚举一律 Skip —— 受保护条目如实报 errSecInteractionNotAllowed，列表标注「受保护」，
    /// 由用户在详情页主动解锁。
    private static func applyAuthenticationPolicy(to query: inout [String: Any],
                                                 allowUI: Bool,
                                                 context: LAContext? = nil) {
        guard allowUI else {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
            return
        }
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
    }

    // MARK: - 删除

    /// 按可靠性递进尝试删除，最后再确认条目是否真的消失了。
    ///
    /// 旧实现丢弃了 `SecItemDelete` 的返回值并直接把行从列表里抹掉，
    /// 于是任何失败都表现为「删掉了，刷新后又回来」。这里只在确认删除成功时才返回 success。
    @discardableResult
    static func delete(_ item: KeychainItem) -> OSStatus {
        guard item.canBeTargeted else {
            // 没有持久引用也没有区分性属性：任何查询都会命中整组条目，宁可失败也不误删
            return errSecParam
        }

        var lastStatus = errSecItemNotFound

        // 1. 持久引用：精确命中单条，不受属性类型转换影响
        if let ref = item.persistentRef {
            let query: [String: Any] = [kSecValuePersistentRef as String: ref]
            lastStatus = SecItemDelete(query as CFDictionary)
            if lastStatus == errSecSuccess { return errSecSuccess }
        }

        // 2. 完整主键
        let byPrimaryKey = SecItemDelete(item.primaryKeyQuery as CFDictionary)
        if byPrimaryKey == errSecSuccess { return errSecSuccess }
        if byPrimaryKey != errSecItemNotFound { lastStatus = byPrimaryKey }

        // 3. 退化主键，应对系统回传属性类型异常导致 errSecParam 的情况
        if let minimal = item.minimalPrimaryKeyQuery {
            let byMinimal = SecItemDelete(minimal as CFDictionary)
            if byMinimal == errSecSuccess { return errSecSuccess }
            if byMinimal != errSecItemNotFound { lastStatus = byMinimal }
        }

        // 4. 前面全都 errSecItemNotFound，可能是被更宽的查询连带删掉了 —— 确认一下
        if !exists(item) { return errSecSuccess }

        return lastStatus
    }

    /// 条目是否仍然存在。无法判定时一律按「还在」处理，绝不谎报删除成功。
    static func exists(_ item: KeychainItem) -> Bool {
        if let ref = item.persistentRef {
            let query: [String: Any] = [
                kSecValuePersistentRef as String: ref,
                kSecReturnAttributes as String: true
            ]
            var output: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &output)
            if status == errSecSuccess { return true }
        }

        var query = item.primaryKeyQuery
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var output: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &output)
        return status != errSecItemNotFound
    }

    // MARK: - 修改

    /// 可以改的元数据。
    ///
    /// 主键属性不在此列：改它们等于把条目挪到另一个主键上，会和已存在的条目
    /// 撞车返回 errSecDuplicateItem，风险远大于收益。
    ///
    /// 网络密码看起来元数据更多（srvr / ptcl / atyp / port / path / sdmn），
    /// 但那几项**全都是它的主键**，所以两类密码可改的其实是同一批非主键字段。
    enum EditableAttribute: String, CaseIterable, Identifiable {
        case label
        case comment
        case description
        case creator
        case type
        case accessible
        case invisible
        case negative

        var id: String { rawValue }

        var key: String {
            switch self {
            case .label:       return kSecAttrLabel as String
            case .comment:     return kSecAttrComment as String
            case .description: return kSecAttrDescription as String
            case .creator:     return kSecAttrCreator as String
            case .type:        return kSecAttrType as String
            case .accessible:  return kSecAttrAccessible as String
            case .invisible:   return kSecAttrIsInvisible as String
            case .negative:    return kSecAttrIsNegative as String
            }
        }

        var displayName: String {
            switch self {
            case .label:       return "标签 (labl)"
            case .comment:     return "备注 (icmt)"
            case .description: return "描述 (desc)"
            case .creator:     return "创建者 (crtr)"
            case .type:        return "类型码 (type)"
            case .accessible:  return "可访问性 (pdmn)"
            case .invisible:   return "隐藏 (invi)"
            case .negative:    return "占位条目 (nega)"
            }
        }

        enum Kind {
            case text
            case boolean
            case accessibility
            /// 四字符码：系统按 32 位整数存储，写成 'aapl' 这样四个字符更好认
            case fourCharCode
        }

        var kind: Kind {
            switch self {
            case .invisible, .negative:  return .boolean
            case .accessible:            return .accessibility
            case .creator, .type:        return .fourCharCode
            default:                     return .text
            }
        }

        static func available(for itemClass: KeychainItemClass) -> [EditableAttribute] {
            switch itemClass {
            case .genericPassword, .internetPassword:
                return allCases
            case .key, .certificate:
                // 这两类的其余字段要么是主键，要么由系统从密钥 / 证书本身派生
                // （subj / issr / slnr / skid / pkhh），改了只会和实际内容对不上。
                // 但 labl 和 pdmn 是普通属性，没有理由锁死。
                return [.label, .accessible]
            }
        }
    }

    /// 取值来自 Security 框架常量的属性，用选择器而不是自由输入
    struct AttributeOption: Identifiable {
        let title: String
        let value: String
        var id: String { value.isEmpty ? "__unset__" : value }

        static let unset = AttributeOption(title: "不设置", value: "")

        static let protocols: [AttributeOption] = [unset] + [
            ("HTTP", kSecAttrProtocolHTTP), ("HTTPS", kSecAttrProtocolHTTPS),
            ("FTP", kSecAttrProtocolFTP), ("FTPS", kSecAttrProtocolFTPS),
            ("SSH", kSecAttrProtocolSSH), ("SMTP", kSecAttrProtocolSMTP),
            ("IMAP", kSecAttrProtocolIMAP), ("IMAPS", kSecAttrProtocolIMAPS),
            ("POP3", kSecAttrProtocolPOP3), ("POP3S", kSecAttrProtocolPOP3S),
            ("LDAP", kSecAttrProtocolLDAP), ("LDAPS", kSecAttrProtocolLDAPS),
            ("SMB", kSecAttrProtocolSMB), ("IRC", kSecAttrProtocolIRC),
            ("Telnet", kSecAttrProtocolTelnet), ("SOCKS", kSecAttrProtocolSOCKS)
        ].map { AttributeOption(title: $0.0, value: $0.1 as String) }

        static let authenticationTypes: [AttributeOption] = [unset] + [
            ("HTTP Basic", kSecAttrAuthenticationTypeHTTPBasic),
            ("HTTP Digest", kSecAttrAuthenticationTypeHTTPDigest),
            ("HTML 表单", kSecAttrAuthenticationTypeHTMLForm),
            ("NTLM", kSecAttrAuthenticationTypeNTLM),
            ("MSN", kSecAttrAuthenticationTypeMSN),
            ("DPA", kSecAttrAuthenticationTypeDPA),
            ("RPA", kSecAttrAuthenticationTypeRPA),
            ("默认", kSecAttrAuthenticationTypeDefault)
        ].map { AttributeOption(title: $0.0, value: $0.1 as String) }

        static let keyClasses: [AttributeOption] = [unset] + [
            ("公钥", kSecAttrKeyClassPublic),
            ("私钥", kSecAttrKeyClassPrivate),
            ("对称密钥", kSecAttrKeyClassSymmetric)
        ].map { AttributeOption(title: $0.0, value: $0.1 as String) }

        static let keyTypes: [AttributeOption] = [unset] + [
            ("RSA", kSecAttrKeyTypeRSA),
            ("EC (SEC Prime Random)", kSecAttrKeyTypeECSECPrimeRandom)
        ].map { AttributeOption(title: $0.0, value: $0.1 as String) }
    }

    /// `kSecAttrCreator` / `kSecAttrType` 存的是 32 位整数，
    /// 但惯例是当成四个 ASCII 字符看（例如 'aapl'）。两种写法都接受。
    enum FourCharCode {
        static func text(from value: Any?) -> String {
            guard let number = value as? NSNumber else { return "" }
            let raw = number.uint32Value
            let bytes = [UInt8(truncatingIfNeeded: raw >> 24),
                         UInt8(truncatingIfNeeded: raw >> 16),
                         UInt8(truncatingIfNeeded: raw >> 8),
                         UInt8(truncatingIfNeeded: raw)]
            // 四个字节都可打印才按字符显示，否则退回十进制
            if bytes.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }) {
                return String(decoding: bytes, as: UTF8.self)
            }
            return String(raw)
        }

        static func number(from text: String) -> NSNumber? {
            let trimmed = text.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }

            if let decimal = UInt32(trimmed) { return NSNumber(value: decimal) }

            let bytes = Array(trimmed.utf8)
            guard bytes.count == 4 else { return nil }
            let raw = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            return NSNumber(value: raw)
        }
    }

    /// 重新读取单条条目的属性。
    ///
    /// 改完元数据后用它就地刷新，不必为一次改动重跑整轮逐组查询。
    /// 保留原有的数据与读取状态 —— 这次改的是属性，数据没动。
    static func reload(_ item: KeychainItem) -> KeychainItem? {
        guard let ref = item.persistentRef else { return nil }

        let query: [String: Any] = [
            kSecValuePersistentRef as String: ref,
            kSecReturnAttributes as String: true
        ]

        var output: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &output) == errSecSuccess,
              var attributes = output as? [String: Any] else {
            return nil
        }

        // 按引用查询不一定回传 v_PersistentRef，补回去，id 才能保持不变
        attributes[kSecValuePersistentRef as String] = ref

        var reloaded = KeychainItem(itemClass: item.itemClass,
                                    attributes: attributes,
                                    fallbackIndex: 0)
        reloaded.data = item.data
        reloaded.dataStatus = item.dataStatus
        reloaded.searchIndex = makeSearchIndex(for: reloaded)
        return reloaded
    }

    /// 批量修改元数据。传入空字符串会把该属性置空。
    static func updateAttributes(_ item: KeychainItem, changes: [String: Any]) -> OSStatus {
        guard !changes.isEmpty else { return errSecSuccess }
        guard item.canBeTargeted else { return errSecParam }

        if let ref = item.persistentRef {
            let query: [String: Any] = [kSecValuePersistentRef as String: ref]
            let status = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
            if status == errSecSuccess { return errSecSuccess }
        }

        return SecItemUpdate(item.primaryKeyQuery as CFDictionary, changes as CFDictionary)
    }

    static func updateData(_ item: KeychainItem, to data: Data) -> OSStatus {
        guard item.itemClass.supportsDataEditing else { return errSecUnimplemented }
        guard item.canBeTargeted else { return errSecParam }

        let attributes: [String: Any] = [kSecValueData as String: data]

        if let ref = item.persistentRef {
            let query: [String: Any] = [kSecValuePersistentRef as String: ref]
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if status == errSecSuccess { return errSecSuccess }
        }

        return SecItemUpdate(item.primaryKeyQuery as CFDictionary, attributes as CFDictionary)
    }

    // MARK: - 新增

    struct NewItem {
        var itemClass: KeychainItemClass = .genericPassword
        /// genp 写入 kSecAttrService，inet 写入 kSecAttrServer；密钥 / 证书不用
        var title: String = ""
        var account: String = ""
        var data: Data = Data()
        var accessGroup: String = ""
        var accessible: String = kSecAttrAccessibleWhenUnlocked as String
        var synchronizable = false

        // 描述性字段
        var label: String = ""
        var itemDescription: String = ""
        var comment: String = ""
        /// 四字符码文本，留空表示不设置
        var creator: String = ""
        var typeCode: String = ""
        var isInvisible = false
        var isNegative = false

        // 通用密码
        var generic: String = ""

        // 网络密码（这几项都是它主键的一部分，只能在新增时定）
        var securityDomain: String = ""
        var networkProtocol: String = ""
        var authenticationType: String = ""
        var port: String = ""
        var path: String = ""

        // 密钥
        var keyClass: String = ""
        var keyType: String = ""
        var applicationTag: String = ""
    }

    static func add(_ newItem: NewItem) -> OSStatus {
        var attributes: [String: Any] = [
            kSecClass as String: newItem.itemClass.secClass,
            kSecAttrAccessible as String: newItem.accessible
        ]
        if newItem.synchronizable {
            attributes[kSecAttrSynchronizable as String] = true
        }

        switch newItem.itemClass {
        case .genericPassword:
            attributes[kSecAttrService as String] = newItem.title
            attributes[kSecAttrAccount as String] = newItem.account
            attributes[kSecValueData as String] = newItem.data
            if let generic = newItem.generic.data(using: .utf8), !generic.isEmpty {
                attributes[kSecAttrGeneric as String] = generic
            }

        case .internetPassword:
            attributes[kSecAttrServer as String] = newItem.title
            attributes[kSecAttrAccount as String] = newItem.account
            attributes[kSecValueData as String] = newItem.data
            if !newItem.securityDomain.isEmpty {
                attributes[kSecAttrSecurityDomain as String] = newItem.securityDomain
            }
            if !newItem.networkProtocol.isEmpty {
                attributes[kSecAttrProtocol as String] = newItem.networkProtocol
            }
            if !newItem.authenticationType.isEmpty {
                attributes[kSecAttrAuthenticationType as String] = newItem.authenticationType
            }
            if let port = Int(newItem.port.trimmingCharacters(in: .whitespaces)), port > 0 {
                attributes[kSecAttrPort as String] = port
            }
            if !newItem.path.isEmpty {
                attributes[kSecAttrPath as String] = newItem.path
            }

        case .certificate:
            // 证书不是「一堆属性」，而是一份 DER 数据：subj / issr / slnr 都由系统
            // 从证书本身解析，手填没有意义也不被接受。所以先构造 SecCertificate，
            // 传 kSecValueRef 而不是 kSecValueData。
            guard let certificate = SecCertificateCreateWithData(nil, newItem.data as CFData) else {
                return errSecDecode
            }
            attributes[kSecValueRef as String] = certificate

        case .key:
            attributes[kSecValueData as String] = newItem.data
            if !newItem.keyClass.isEmpty {
                attributes[kSecAttrKeyClass as String] = newItem.keyClass
            }
            if !newItem.keyType.isEmpty {
                attributes[kSecAttrKeyType as String] = newItem.keyType
            }
            if let tag = newItem.applicationTag.data(using: .utf8), !tag.isEmpty {
                attributes[kSecAttrApplicationTag as String] = tag
            }
        }

        if !newItem.label.isEmpty {
            attributes[kSecAttrLabel as String] = newItem.label
        }

        // 其余描述性字段只有密码类有对应的列
        if newItem.itemClass.supportsDataEditing {
            if !newItem.itemDescription.isEmpty {
                attributes[kSecAttrDescription as String] = newItem.itemDescription
            }
            if !newItem.comment.isEmpty {
                attributes[kSecAttrComment as String] = newItem.comment
            }
            if let creator = FourCharCode.number(from: newItem.creator) {
                attributes[kSecAttrCreator as String] = creator
            }
            if let typeCode = FourCharCode.number(from: newItem.typeCode) {
                attributes[kSecAttrType as String] = typeCode
            }
            if newItem.isInvisible {
                attributes[kSecAttrIsInvisible as String] = true
            }
            if newItem.isNegative {
                attributes[kSecAttrIsNegative as String] = true
            }
        }

        // 通配符 Group 只是权限声明，不是可写入的实际 Group
        let group = newItem.accessGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        if !group.isEmpty && !isWildcardGroup(group) {
            attributes[kSecAttrAccessGroup as String] = group
        }

        return SecItemAdd(attributes as CFDictionary, nil)
    }

    /// 通配符 Group（TEAMID.*）无法作为写入目标
    static func isWildcardGroup(_ group: String) -> Bool {
        group.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("*")
    }

    // MARK: - 错误描述

    /// SecCopyErrorMessageString 仅 macOS 可用，这里自行维护 iOS 上常见错误的中文说明
    static func message(for status: OSStatus) -> String {
        switch status {
        case errSecSuccess:
            return "成功"
        case errSecItemNotFound:
            return "未找到匹配条目 (-25300)"
        case errSecDuplicateItem:
            return "条目已存在 (-25299)"
        case errSecInteractionNotAllowed:
            return "条目受保护或设备已锁定，当前不可访问 (-25308)"
        case errSecAuthFailed:
            return "认证失败 (-25293)"
        case errSecNotAvailable:
            return "Keychain 服务不可用 (-25291)"
        case errSecDecode:
            return "数据解码失败 (-26275)"
        case errSecParam:
            return "查询参数无效，无法唯一定位该条目 (-50)"
        case errSecAllocate:
            return "内存分配失败 (-108)"
        case errSecUnimplemented:
            return "该类别不支持此操作 (-4)"
        case errSecIO:
            return "I/O 错误 (-36)"
        case errSecUserCanceled:
            return "用户取消 (-128)"
        case KeychainStore.missingEntitlement:
            return "缺少 keychain-access-groups 权限，无法访问该 Access Group (-34018)"
        default:
            return "错误码 \(status)"
        }
    }
}
