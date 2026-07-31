import Foundation
import Security

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

        // 逐组枚举而不是一次不限组的广查询。
        //
        // 不限组查询会横跨全部 entitlement 组，只要其中一个组出问题
        // （实机上是 com.apple.token 触发验证），整个类别一起返回 errSecAuthFailed，
        // 该类别的条目就全部看不到了。逐组之后单个组失败只影响它自己。
        //
        // 前提是拿得到完整的组列表 —— 通配符组在查询里是**字面匹配**，
        // 用 `TEAMID.*` 查只会返回 agrp 恰好等于该字符串的条目，
        // 不会展开命中 `TEAMID.foo.bar`，所以必须逐个真实组名去查。
        let targets: [String?]
        switch scope {
        case .group(let group):
            targets = [group]
        case .allAccessible:
            // 末尾追加一次不限组扫描（nil）。
            //
            // 通配符 entitlement（TEAMID.*）授予的是「该前缀下所有组」的访问权，
            // 这些组名不出现在 entitlements 里，逐组枚举永远猜不到它们。
            // 不限组查询不依赖组名，正好补上这个缺口；重复条目由持久引用去重消化。
            targets = knownGroups.isEmpty ? [nil] : knownGroups.map { Optional($0) } + [nil]
        }

        let total = classes.count * targets.count
        var completed = 0

        for itemClass in classes {
            for target in targets {
                completed += 1
                if total <= 1 || completed % 10 == 0 || completed == total {
                    progress?("正在枚举\(itemClass.displayName)条目 \(completed)/\(total)…")
                }

                let outcome = enumerate(itemClass: itemClass,
                                       accessGroup: target,
                                       skipAuthenticationUI: !includeProtected)

                switch outcome.status {
                case errSecSuccess, errSecItemNotFound:
                    rows.append(contentsOf: outcome.rows.map { (itemClass, $0) })

                default:
                    // 允许验证时失败（用户取消、验证不通过、整批认证失败等）：
                    // 退回跳过验证再查一次，至少把不需要验证的条目拿到手，
                    // 同时如实记录失败，好定位是哪个组里藏着受保护条目。
                    if includeProtected {
                        let retry = enumerate(itemClass: itemClass,
                                             accessGroup: target,
                                             skipAuthenticationUI: true)
                        if retry.status == errSecSuccess || retry.status == errSecItemNotFound {
                            rows.append(contentsOf: retry.rows.map { (itemClass, $0) })
                        }
                    }
                    result.classErrors.append(KeychainClassError(itemClass: itemClass,
                                                                 accessGroup: target,
                                                                 status: outcome.status))
                }
            }
        }

        // 同一条目可能被多个组名命中（例如字面存在的通配符组），按持久引用去重
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
        if let ref = item.persistentRef {
            var query: [String: Any] = [
                kSecValuePersistentRef as String: ref,
                kSecReturnData as String: true
            ]
            applyAuthenticationPolicy(to: &query, allowUI: allowAuthenticationUI)

            var output: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &output)
            if status == errSecSuccess {
                return (output as? Data ?? Data(), errSecSuccess)
            }
            // 引用失效才退回主键查询，其它错误（如条目受保护）直接如实上报
            if status != errSecItemNotFound {
                return (nil, status)
            }
        }

        var query = item.primaryKeyQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        applyAuthenticationPolicy(to: &query, allowUI: allowAuthenticationUI)

        var output: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &output)
        if status == errSecSuccess {
            return (output as? Data ?? Data(), errSecSuccess)
        }
        return (nil, status)
    }

    /// 单条 `kSecMatchLimitOne` + `kSecReturnData` 查询碰上受 `SecAccessControl` 保护的条目时，
    /// 系统会弹出 Face ID / Touch ID 验证。这在枚举场景下有两个后果：
    /// 刷新一次列表就要连续验证 N 次；且 Info.plist 缺少 `NSFaceIDUsageDescription` 时，
    /// 系统会直接终止进程（启动即闪退）。
    /// 因此枚举一律 Skip —— 受保护条目如实报 errSecInteractionNotAllowed，列表标注「受保护」，
    /// 由用户在详情页主动解锁。
    private static func applyAuthenticationPolicy(to query: inout [String: Any], allowUI: Bool) {
        guard !allowUI else { return }
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
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
        /// genp 写入 kSecAttrService，inet 写入 kSecAttrServer
        var title: String = ""
        var account: String = ""
        var data: Data = Data()
        var accessGroup: String = ""
        var accessible: String = kSecAttrAccessibleWhenUnlocked as String
        var label: String = ""
    }

    static func add(_ newItem: NewItem) -> OSStatus {
        guard newItem.itemClass.supportsDataEditing else { return errSecUnimplemented }

        var attributes: [String: Any] = [
            kSecClass as String: newItem.itemClass.secClass,
            kSecAttrAccount as String: newItem.account,
            kSecValueData as String: newItem.data,
            kSecAttrAccessible as String: newItem.accessible
        ]

        if newItem.itemClass == .internetPassword {
            attributes[kSecAttrServer as String] = newItem.title
        } else {
            attributes[kSecAttrService as String] = newItem.title
        }

        if !newItem.label.isEmpty {
            attributes[kSecAttrLabel as String] = newItem.label
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
