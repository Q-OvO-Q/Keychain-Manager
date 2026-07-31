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
    let status: OSStatus
}

struct KeychainFetchResult {
    var items: [KeychainItem] = []
    /// 按类别记录查询失败原因；只要有失败就不能把「查到 0 条」当成「确实没有」
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
                          fallbackGroups: [String] = [],
                          loadData: Bool = true,
                          progress: ((String) -> Void)? = nil) -> KeychainFetchResult {
        var result = KeychainFetchResult()
        var rows: [(KeychainItemClass, [String: Any])] = []

        let group: String?
        if case .group(let target) = scope { group = target } else { group = nil }

        for itemClass in classes {
            progress?("正在枚举\(itemClass.displayName)条目…")

            let outcome = enumerate(itemClass: itemClass, accessGroup: group)

            switch outcome.status {
            case errSecSuccess, errSecItemNotFound:
                rows.append(contentsOf: outcome.rows.map { (itemClass, $0) })

            default:
                // 不限定 Access Group 的广查询会横跨全部 entitlement 组，
                // 只要其中有一条需要用户验证，整个类别就会一起失败（实机上表现为通用类 -25293）。
                // 此时逐个已知 Group 重试，至少把能读到的部分捞回来。
                var recovered: [[String: Any]] = []
                var anyGroupSucceeded = false

                if group == nil && !fallbackGroups.isEmpty {
                    for (index, candidate) in fallbackGroups.enumerated() {
                        progress?("\(itemClass.displayName)：逐组重试 \(index + 1)/\(fallbackGroups.count)…")
                        let perGroup = enumerate(itemClass: itemClass, accessGroup: candidate)
                        if perGroup.status == errSecSuccess || perGroup.status == errSecItemNotFound {
                            anyGroupSucceeded = true
                            recovered.append(contentsOf: perGroup.rows)
                        }
                    }
                }

                if anyGroupSucceeded {
                    rows.append(contentsOf: recovered.map { (itemClass, $0) })
                } else {
                    result.classErrors.append(KeychainClassError(itemClass: itemClass, status: outcome.status))
                }
            }
        }

        // 逐组重试时通配符组与具体组会重复命中同一条目，按持久引用去重
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
                item.dataStatus = outcome.status
            }
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

    /// 枚举单个类别。`accessGroup` 为 nil 表示不限定组。
    private static func enumerate(itemClass: KeychainItemClass,
                                 accessGroup: String?) -> (rows: [[String: Any]], status: OSStatus) {
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
        // 枚举阶段同样必须跳过验证：结果集里只要有一条需要用户验证，
        // 系统就会先弹 Face ID，验证结果又不适用于整批，最终整个类别返回 errSecAuthFailed。
        applyAuthenticationPolicy(to: &query, allowUI: false)

        var output: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &output)

        guard status == errSecSuccess else { return ([], status) }

        if let array = output as? [[String: Any]] {
            return (array, status)
        }
        if let single = output as? [String: Any] {
            return ([single], status)
        }
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
            guard let ref = row.1[kSecValuePersistentRef as String] as? Data else {
                unique.append(row)
                continue
            }
            if seen.insert(ref).inserted {
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
