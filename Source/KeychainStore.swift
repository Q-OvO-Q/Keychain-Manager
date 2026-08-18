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
    static func makeSearchIndex(for item: KeychainItem) -> String {
        var parts = [item.displayTitle, item.account, item.accessGroup]

        // 把所有能读成文本的属性都纳入：标签、描述、备注、路径、端口……
        // 只索引标题 / 账号 / 组 / 内容的话，按这些字段是搜不到的。
        // stringValue 对解不成 UTF-8 的二进制属性返回 nil，正好把它们排除在外。
        for (key, value) in item.rawAttributes where key != (kSecValuePersistentRef as String) {
            if let text = KeychainItem.stringValue(value), !text.isEmpty {
                parts.append(text)
            }
            // 详情页把 pdmn / kcls / type 显示成「首次解锁后可访问」「私钥」「RSA」，
            // 索引里却只有 ak / 1 / 42 —— 看得到又搜不到。把翻译后的写法也收进来
            let formatted = KeychainAttributeFormatter.value(value, forKey: key,
                                                             itemClass: item.itemClass)
            if !formatted.isEmpty { parts.append(formatted) }
        }

        if item.isDataReadable, let data = item.data {
            if let text = data.utf8Text {
                parts.append(text)
            } else if let decoded = DataDecoder.decode(data) {
                // bplist、protobuf 这些解不成 UTF-8 的，详情页里内容看得清清楚楚，
                // 不一起索引就成了「看得到却搜不到」。实测有 395 条属于这种。
                // 枚举本来就在后台线程上跑，多这点解析开销无所谓。
                parts.append(decoded.text)
            }
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

    /// 去重：有持久引用的按引用，没有的按主键
    private static func deduplicate(
        _ rows: [(KeychainItemClass, [String: Any])]
    ) -> [(KeychainItemClass, [String: Any])] {
        var seen = Set<Data>()
        var unique: [(KeychainItemClass, [String: Any])] = []
        unique.reserveCapacity(rows.count)

        // 没有持久引用的行按主键去重。「全部可访问」下同一条会被不限组扫描和
        // 逐组枚举各返回一次，一律保留就会在列表里出现两份。
        // 按主键去重是安全的：实测 1467 条导出里四个类别的主键组合都完全唯一
        //（1347/1347、21/21、99/99），不存在两条不同条目共用一个主键。
        var seenKeys = Set<String>()

        for row in rows {
            guard let reference = row.1[kSecValuePersistentRef as String] as? Data else {
                let fingerprint = primaryKeyFingerprint(itemClass: row.0, attributes: row.1)
                if seenKeys.insert(fingerprint).inserted {
                    unique.append(row)
                }
                continue
            }
            if seen.insert(reference).inserted {
                unique.append(row)
            }
        }
        return unique
    }

    /// 主键各字段拼成的指纹，仅用于给缺少持久引用的行去重
    private static func primaryKeyFingerprint(itemClass: KeychainItemClass,
                                              attributes: [String: Any]) -> String {
        var parts = [itemClass.secClass as String]
        for key in itemClass.primaryKeyAttributes.sorted() {
            switch attributes[key] {
            case let text as String:     parts.append("\(key)=s:\(text)")
            case let data as Data:       parts.append("\(key)=d:\(data.base64EncodedString())")
            case let number as NSNumber: parts.append("\(key)=n:\(number)")
            case .none:                  parts.append("\(key)=nil")
            case .some(let other):       parts.append("\(key)=?:\(other)")
            }
        }
        return parts.joined(separator: "|")
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

        // 主键缺项时这条查询会匹配上兄弟条目，而 kSecMatchLimitOne 会随便挑一条回来 ——
        // 那就是把**别人的密码**当成这条的内容显示、索引、导出。宁可报读不出来。
        guard isSafeToMutate(item) else { return (nil, referenceStatus) }

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

        // 2. 完整主键 —— 但「完整」是有条件的：系统只回传有值的键，缺一项这条查询
        //    就少一个约束，而 SecItemDelete 删的是全部命中项。实测 1068 条通用密码
        //    没有 gena，它们的查询也会匹配上有 gena 的兄弟条目。齐全才直接删。
        if isSafeToMutate(item) {
            let byPrimaryKey = SecItemDelete(item.primaryKeyQuery as CFDictionary)
            if byPrimaryKey == errSecSuccess { return errSecSuccess }
            if byPrimaryKey != errSecItemNotFound { lastStatus = byPrimaryKey }
        } else {
            lastStatus = errSecParam
        }

        // 3. 退化主键，应对系统回传属性类型异常导致 errSecParam 的情况。
        //
        //    但 SecItemDelete 会删掉**所有**命中项，而退化查询按定义比主键更宽，
        //    所以动手前先数一遍：只要可能命中不止一条就不删，宁可报失败。
        //    这不是假想 —— 一对密钥的公私钥共用同一个 klbl（公钥的 SHA-1）和 atag，
        //    只差 kcls，实测导出里就有这么一对。
        //
        //    受保护条目数不出来（跳过验证后返回 errSecInteractionNotAllowed），
        //    于是这一步对它们一律不执行。这是有意的，别改回去：数不出来就等于
        //    无法确认「只命中一条」，而删除不可逆。真要删这类条目，走前两步 ——
        //    持久引用和完整主键都不需要解密，正常情况下第 1 步就成了。
        if let minimal = item.minimalPrimaryKeyQuery, matchCount(for: minimal) <= 1 {
            let byMinimal = SecItemDelete(minimal as CFDictionary)
            if byMinimal == errSecSuccess { return errSecSuccess }
            if byMinimal != errSecItemNotFound { lastStatus = byMinimal }
        }

        // 4. 前面全都 errSecItemNotFound，可能是被更宽的查询连带删掉了 —— 确认一下
        if !exists(item) { return errSecSuccess }

        return lastStatus
    }

    /// 该查询会命中多少条。数不清时返回 `Int.max`，让调用方按「可能很多」处理。
    ///
    /// 用 `Fail` 而不是 `Skip`：`Skip` 会把需要验证的条目**静默剔除**，数出来的是
    /// 「我这次能看见几条」，而不是「SecItemDelete / SecItemUpdate 实际会改到几条」——
    /// 那样护栏会放行一个其实命中多条的查询，正好把它要防的事放过去。
    /// `Fail` 只要有任一命中项需要验证就整体报错，恰好等于「数不清」。两者都不会弹框。
    private static func matchCount(for query: [String: Any]) -> Int {
        var counting = query
        counting[kSecMatchLimit as String] = kSecMatchLimitAll
        counting[kSecReturnPersistentRef as String] = true
        counting[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail

        var output: AnyObject?
        let status = SecItemCopyMatching(counting as CFDictionary, &output)
        if status == errSecItemNotFound { return 0 }
        guard status == errSecSuccess else { return .max }
        if let rows = output as? [Any] { return rows.count }
        return output == nil ? 0 : 1
    }

    /// 这条查询动手前需不需要先数一遍。
    ///
    /// 主键齐全时它是精确的（实测四个类别的主键组合都唯一），直接动手；
    /// 缺了任何一项就少一个约束，必须确认只命中一条 —— 数不清也算不通过。
    private static func isSafeToMutate(_ item: KeychainItem) -> Bool {
        item.hasCompletePrimaryKey || matchCount(for: item.primaryKeyQuery) <= 1
    }

    /// 条目是否仍然存在。无法判定时一律按「还在」处理，绝不谎报删除成功。
    static func exists(_ item: KeychainItem) -> Bool {
        // 用 Fail 而不是 Skip，理由与 matchCount 相同：Skip 会把需要验证的条目
        // **静默剔除**，返回 errSecItemNotFound（见 fetchItems 里的实测注释）——
        // 一条删除失败的受保护条目会被误判成「已删除」，delete() 随之谎报成功，
        // 界面把行抹掉、标签也一并清除，条目却还在钥匙串里。
        // Fail 让受保护条目如实报 errSecInteractionNotAllowed，
        // 正好落进「判不出就算还在」那一档。两者都不会弹验证框。
        if let ref = item.persistentRef {
            let query: [String: Any] = [
                kSecValuePersistentRef as String: ref,
                kSecReturnAttributes as String: true,
                kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
            ]
            var output: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &output)
            if status != errSecItemNotFound { return true }
        }

        var query = item.primaryKeyQuery
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail

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
        case description
        case comment
        case creator
        case type
        case accessible
        case invisible
        case negative
        // 密钥专有：这些都是普通列，不构成主键，SecItemUpdate 接受
        case isPermanent
        case canEncrypt
        case canDecrypt
        case canDerive
        case canSign
        case canVerify
        case canWrap
        case canUnwrap

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
            case .isPermanent: return kSecAttrIsPermanent as String
            case .canEncrypt:  return kSecAttrCanEncrypt as String
            case .canDecrypt:  return kSecAttrCanDecrypt as String
            case .canDerive:   return kSecAttrCanDerive as String
            case .canSign:     return kSecAttrCanSign as String
            case .canVerify:   return kSecAttrCanVerify as String
            case .canWrap:     return kSecAttrCanWrap as String
            case .canUnwrap:   return kSecAttrCanUnwrap as String
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
            case .isPermanent: return "永久存储 (perm)"
            case .canEncrypt:  return "可加密 (encr)"
            case .canDecrypt:  return "可解密 (decr)"
            case .canDerive:   return "可派生 (drve)"
            case .canSign:     return "可签名 (sign)"
            case .canVerify:   return "可验签 (vrfy)"
            case .canWrap:     return "可包装密钥 (wrap)"
            case .canUnwrap:   return "可解包密钥 (unwp)"
            }
        }

        enum Kind: Int, Comparable {
            // rawValue 就是界面上的排列次序：同类控件聚在一起，不互相穿插
            case text = 0
            case fourCharCode = 1
            case accessibility = 2
            case boolean = 3

            static func < (lhs: Kind, rhs: Kind) -> Bool { lhs.rawValue < rhs.rawValue }
        }

        var kind: Kind {
            switch self {
            case .invisible, .negative, .isPermanent,
                 .canEncrypt, .canDecrypt, .canDerive,
                 .canSign, .canVerify, .canWrap, .canUnwrap:
                return .boolean
            case .accessible:
                return .accessibility
            case .creator, .type:
                return .fourCharCode
            case .label, .comment, .description:
                return .text
            }
        }

        /// 按控件类型排好序的可编辑属性，界面直接照这个顺序渲染。
        /// 排序集中在这里，各页面就不必各自维护一份顺序 —— 之前新增页排了、
        /// 详情页没排，同一批字段在两个界面上的次序就不一样了。
        static func ordered(for itemClass: KeychainItemClass) -> [EditableAttribute] {
            let declarationOrder = Dictionary(uniqueKeysWithValues:
                allCases.enumerated().map { ($1, $0) })
            return available(for: itemClass).sorted { lhs, rhs in
                lhs.kind != rhs.kind
                    ? lhs.kind < rhs.kind
                    : (declarationOrder[lhs] ?? 0) < (declarationOrder[rhs] ?? 0)
            }
        }

        /// 每个类别里**所有**非主键、非派生的属性。
        ///
        /// 排除的只有两类：构成主键的（改了等于挪走条目），
        /// 以及系统从密钥 / 证书数据算出来的（subj / issr / slnr / skid / pkhh /
        /// ctyp / cenc），手改只会和实际内容对不上。
        static func available(for itemClass: KeychainItemClass) -> [EditableAttribute] {
            switch itemClass {
            case .genericPassword, .internetPassword:
                return [.label, .description, .comment, .creator, .type,
                        .accessible, .invisible, .negative]
            case .key:
                // crtr 在文档里只列在密码类下，但密钥表确实有这一列（导出文件里带着它），
                // 且带 crtr 的密钥本来就能被 SecItemAdd 接受 —— 有实证就放开
                return [.label, .accessible, .creator, .isPermanent,
                        .canEncrypt, .canDecrypt, .canDerive,
                        .canSign, .canVerify, .canWrap, .canUnwrap]
            case .certificate:
                // 证书除了 labl 和 pdmn，其余列全部由证书本身决定
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
            // 四个字节都可打印才按字符显示，否则退回十进制。
            //
            // 全是数字的除外（例如 "1234"）：那样显示出来和十进制写法长得一模一样，
            // 而 number(from:) 会优先按十进制解析 —— 于是「看一眼再保存」就把
            // 825373492 悄悄变成了 1234。这类退回十进制，显示与解析才对得上。
            let text = String(decoding: bytes, as: UTF8.self)
            if bytes.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }),
               !text.allSatisfy({ $0.isNumber }) {
                return text
            }
            return String(raw)
        }

        static func number(from text: String) -> NSNumber? {
            let trimmed = text.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }

            // 十进制只认「整串就是数字」的输入。带空白垫充的（如 " 123"）不算：
            // 那可能是 text(from:) 显示出来的空格垫充四字符码，按十进制解析会把
            // 0x20313233 变成 123，往返就失真了。
            if text == trimmed, let decimal = UInt32(trimmed) {
                return NSNumber(value: decimal)
            }

            // 原文恰好 4 字节时按原文收，空格也是合法的四字符码字节 ——
            // text(from:) 会把 'sit '（0x73697420）显示成 "sit "，
            // 先 trim 再解析的话，这个显示出来的值自己就再也填不回去了。
            let raw = Array(text.utf8)
            if raw.count == 4 {
                return NSNumber(value: raw.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
            }

            if let decimal = UInt32(trimmed) { return NSNumber(value: decimal) }

            let bytes = Array(trimmed.utf8)
            guard bytes.count == 4 else { return nil }
            let raw32 = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            return NSNumber(value: raw32)
        }
    }

    /// 重新读取单条条目的属性。
    ///
    /// 改完元数据后用它就地刷新，不必为一次改动重跑整轮逐组查询。
    /// 保留原有的数据与读取状态 —— 这次改的是属性，数据没动。
    static func reload(_ item: KeychainItem) -> KeychainItem? {
        // 一律跳过验证：这里只是回读属性，不该为此弹验证框
        func fetch(_ base: [String: Any]) -> [String: Any]? {
            var query = base
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip

            var output: AnyObject?
            guard SecItemCopyMatching(query as CFDictionary, &output) == errSecSuccess else {
                return nil
            }
            return output as? [String: Any]
        }

        // 没有持久引用（或引用已失效）时退回主键查询：写入本身是靠
        // updateByPrimaryKey 成功的，回读却只认引用的话，界面会把刚保存的值弹回旧值
        var attributes: [String: Any]?
        if let ref = item.persistentRef {
            attributes = fetch([kSecValuePersistentRef as String: ref])
        }
        if attributes == nil, isSafeToMutate(item) {
            attributes = fetch(item.primaryKeyQuery)
        }
        guard var attributes else { return nil }

        // 按引用查询不一定回传 v_PersistentRef，补回去，id 才能保持不变
        if let ref = item.persistentRef {
            attributes[kSecValuePersistentRef as String] = ref
        }

        // 沿用原条目的回退序号：没有持久引用的条目 id 是「key:标签键#序号」，
        // 这里写死 0 的话，一次成功的保存就会把 id 换掉 ——
        // 详情页按旧 id 找不到条目，页面立刻变成「条目已不存在」
        var reloaded = KeychainItem(itemClass: item.itemClass,
                                    attributes: attributes,
                                    fallbackIndex: item.fallbackIndex)
        reloaded.data = item.data
        reloaded.dataStatus = item.dataStatus
        reloaded.searchIndex = makeSearchIndex(for: reloaded)
        return reloaded
    }

    /// 持久引用那条路是否值得换主键再试。
    ///
    /// 只有「引用本身失效 / 不被接受」才换：改受保护条目会触发系统验证，
    /// 用户取消（errSecUserCanceled）、设备锁定（errSecInteractionNotAllowed）、
    /// 认证失败（errSecAuthFailed）时换条路结局完全一样 ——
    /// 只会立刻再弹一次验证框，把一次「取消」变成连续两问。
    private static func shouldFallBackToPrimaryKey(after status: OSStatus) -> Bool {
        status == errSecItemNotFound || status == errSecParam
    }

    /// 批量修改元数据。传入空字符串会把该属性置空。
    static func updateAttributes(_ item: KeychainItem, changes: [String: Any]) -> OSStatus {
        guard !changes.isEmpty else { return errSecSuccess }
        guard item.canBeTargeted else { return errSecParam }

        if let ref = item.persistentRef {
            let query: [String: Any] = [kSecValuePersistentRef as String: ref]
            let status = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
            if status == errSecSuccess { return errSecSuccess }
            if !shouldFallBackToPrimaryKey(after: status) { return status }
        }

        return updateByPrimaryKey(item, changes)
    }

    static func updateData(_ item: KeychainItem, to data: Data) -> OSStatus {
        guard item.itemClass.supportsDataEditing else { return errSecUnimplemented }
        guard item.canBeTargeted else { return errSecParam }

        let attributes: [String: Any] = [kSecValueData as String: data]

        if let ref = item.persistentRef {
            let query: [String: Any] = [kSecValuePersistentRef as String: ref]
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if status == errSecSuccess { return errSecSuccess }
            if !shouldFallBackToPrimaryKey(after: status) { return status }
        }

        return updateByPrimaryKey(item, attributes)
    }

    /// 持久引用那条路走不通时的回退。
    ///
    /// `primaryKeyQuery` 是拿「系统回传了哪些主键属性」拼的，缺一项查询就少一个约束 ——
    /// 实测 1068 条通用密码没有 gena，它们的查询里就没有这条约束，因而也会匹配上
    /// **有** gena 的兄弟条目。而 `SecItemUpdate` 改的是全部命中项。
    ///
    /// 那 1068 条目前一条都不会命中多条，所以这是潜伏问题；但和导入覆盖那处是同一个
    /// 形状，后果是悄悄改掉别人的密码，所以照同一套办法先数再改。
    private static func updateByPrimaryKey(_ item: KeychainItem,
                                           _ changes: [String: Any]) -> OSStatus {
        guard isSafeToMutate(item) else { return errSecParam }
        return SecItemUpdate(item.primaryKeyQuery as CFDictionary, changes as CFDictionary)
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
        /// klbl：非对称密钥通常由系统按公钥哈希填，导入原始密钥时可自定
        var applicationLabel: String = ""
        var keySizeInBits: String = ""
        var effectiveKeySize: String = ""
        var isPermanent = false
        var canEncrypt = false
        var canDecrypt = false
        var canDerive = false
        var canSign = false
        var canVerify = false
        var canWrap = false
        var canUnwrap = false
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
            // bsiz 属于密钥主键。导入原始密钥时系统一般无从自行推断，
            // 缺了它 SecItemAdd 往往直接 errSecParam。
            if let bits = Int(newItem.keySizeInBits.trimmingCharacters(in: .whitespaces)), bits > 0 {
                attributes[kSecAttrKeySizeInBits as String] = bits
            }
            if let bits = Int(newItem.effectiveKeySize.trimmingCharacters(in: .whitespaces)), bits > 0 {
                attributes[kSecAttrEffectiveKeySize as String] = bits
            }
            if let tag = newItem.applicationTag.data(using: .utf8), !tag.isEmpty {
                attributes[kSecAttrApplicationTag as String] = tag
            }
            if let appLabel = newItem.applicationLabel.data(using: .utf8), !appLabel.isEmpty {
                attributes[kSecAttrApplicationLabel as String] = appLabel
            }
            // 显式写 true / false，不能「只在 true 时写」：这些标志省略时系统会
            // 按密钥类型自行推断，而不是当成 false —— 那样界面上关掉的开关根本不起作用。
            // 详情页一直是这么写的（SecItemUpdate 带显式 false），所以这条路是通的。
            attributes[kSecAttrIsPermanent as String] = newItem.isPermanent
            attributes[kSecAttrCanEncrypt as String] = newItem.canEncrypt
            attributes[kSecAttrCanDecrypt as String] = newItem.canDecrypt
            attributes[kSecAttrCanDerive as String] = newItem.canDerive
            attributes[kSecAttrCanSign as String] = newItem.canSign
            attributes[kSecAttrCanVerify as String] = newItem.canVerify
            attributes[kSecAttrCanWrap as String] = newItem.canWrap
            attributes[kSecAttrCanUnwrap as String] = newItem.canUnwrap
        }

        if !newItem.label.isEmpty {
            attributes[kSecAttrLabel as String] = newItem.label
        }

        // 描述性字段按该类别**实际可编辑**的集合来判断，而不是按「是不是密码类」
        // 一刀切 —— crtr 对密钥也是可设的，一刀切会让界面填了却发不出去。
        let editable = Set(EditableAttribute.available(for: newItem.itemClass).map(\.key))

        if editable.contains(kSecAttrDescription as String), !newItem.itemDescription.isEmpty {
            attributes[kSecAttrDescription as String] = newItem.itemDescription
        }
        if editable.contains(kSecAttrComment as String), !newItem.comment.isEmpty {
            attributes[kSecAttrComment as String] = newItem.comment
        }
        if editable.contains(kSecAttrCreator as String),
           let creator = FourCharCode.number(from: newItem.creator) {
            attributes[kSecAttrCreator as String] = creator
        }
        if editable.contains(kSecAttrType as String),
           let typeCode = FourCharCode.number(from: newItem.typeCode) {
            attributes[kSecAttrType as String] = typeCode
        }
        if editable.contains(kSecAttrIsInvisible as String) {
            attributes[kSecAttrIsInvisible as String] = newItem.isInvisible
        }
        if editable.contains(kSecAttrIsNegative as String) {
            attributes[kSecAttrIsNegative as String] = newItem.isNegative
        }

        // 通配符组同样可以写入：钥匙串把它当成普通组名存下来，
        // 查询时也只按字面匹配。之前按「它只是权限声明」把它剥掉是错的。
        let group = newItem.accessGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        if !group.isEmpty {
            attributes[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecParam else { return status }

        // 万一某个类别不接受显式 false，退回「只写 true」再试一次：
        // 开关失效总比整条建不出来强，而且失败会明确报给用户。
        //
        // 只摘已知的布尔开关，不能按「值等于 false」判：NSNumber(0) 也能
        // `as? Bool` 成功（Foundation 对 0/1 的桥接），按值判会把用户显式
        // 填的 crtr/type = 0 一起悄悄摘掉。
        let booleanKeys = Set([kSecAttrIsInvisible, kSecAttrIsNegative,
                               kSecAttrIsPermanent, kSecAttrCanEncrypt,
                               kSecAttrCanDecrypt, kSecAttrCanDerive,
                               kSecAttrCanSign, kSecAttrCanVerify,
                               kSecAttrCanWrap, kSecAttrCanUnwrap].map { $0 as String })
        var relaxed = attributes
        for (key, value) in attributes
        where booleanKeys.contains(key) && (value as? Bool) == false {
            relaxed.removeValue(forKey: key)
        }
        guard relaxed.count != attributes.count else { return status }
        return SecItemAdd(relaxed as CFDictionary, nil)
    }

    // MARK: - 导入

    struct ImportFailure {
        let title: String
        /// 直接给原因，而不是甩一个错误码 —— 有些失败（安全隔区密钥）
        /// 是原理上不可能成功的，光看 -50 会以为是程序出错
        let reason: String
    }

    struct ImportOutcome {
        var added = 0
        var replaced = 0
        /// 系统拒收「尽量保真」的属性、摘掉后才写进去的条数。
        /// 不算失败，但要让用户知道这些条目不是原样还原的
        var degraded = 0
        var failures: [ImportFailure] = []

        var attempted: Int { added + replaced + failures.count }
    }

    /// `SecItemAdd` 能接受的属性。
    ///
    /// **不能照搬「securityd 回传什么就送回什么」** —— 那条规则对查询成立，对添加不成立：
    /// 添加时会校验属性集合，碰到 `tkid` / `priv` / `modi` / `next` / `extr`
    /// 这类只读属性会整条返回 errSecParam，一个属性就废掉一整条。
    ///
    /// 白名单由已有定义推导（主键属性 + 可编辑属性 + 数据），不另立一套，
    /// 以后增删类别或调整主键定义时会自动跟上。
    private static func settableAttributes(for itemClass: KeychainItemClass) -> Set<String> {
        // 证书的身份全部来自 DER，除标签和保护级别外一概不能手给。
        // 但 v_Data 必须留着：下面的导入逻辑要拿这份 DER 重建 SecCertificate，
        // 白名单把它滤掉的话，每一张证书都会以「不是合法的 DER 证书」失败 ——
        // 而那行代码就写在过滤的下一行。
        if itemClass == .certificate {
            return [kSecAttrLabel, kSecAttrAccessible,
                    kSecAttrAccessGroup, kSecAttrSynchronizable, kSecValueData]
                .map { $0 as String }
                .reduce(into: Set<String>()) { $0.insert($1) }
        }

        var keys = Set(itemClass.primaryKeyAttributes)
        for attribute in EditableAttribute.available(for: itemClass) {
            keys.insert(attribute.key)
        }
        keys.insert(kSecValueData as String)
        keys.formUnion(bestEffortAttributes)
        return keys
    }

    /// 尽量保真、但不确定系统一定接受的属性。
    ///
    /// `alis` 出现在实测导出的 1385/1467 条上，值是每个 App 容器一个的 UUID
    /// （同一个 app 的多条共用同一个值）。丢掉它，导入回去的条目未必还能被原来的
    /// app 认领。但它是不是 `SecItemAdd` 允许手给的属性，只有真机说了算 ——
    /// 之前密钥的 `priv`/`modi`/`extr` 就是写了直接 -50。
    ///
    /// 苹果没把它开放给 SecItem。两边证据一致：iOS SDK 里没有 `kSecAttrAlias`
    /// 这个常量（编译报 cannot find in scope），而 Security 源码
    /// `libsecurity_keychain/lib/SecItem.cpp` 的属性映射表里那一行是注释掉的：
    /// `//  { kSecKeyAlias, /* not yet exposed by SecItem */, ... }`。
    ///
    /// 但 SecItem 的字典就是字符串键，`"alis"` 仍然送得进去，收不收只有真机知道。
    /// 所以先带上写，被拒（errSecParam）就摘掉重试 —— 能保真就保真，
    /// 不能也只是退回原来的行为，不会因此整批失败。
    private static let bestEffortAttributes: Set<String> = ["alis"]

    /// 按导入文件里的属性直接写入。
    ///
    /// 与 `add(_:)` 分开是有意的：那个方法接收界面上手填的字段，
    /// 这里拿到的是从钥匙串导出来的原始属性，要尽量原样写回去。
    ///
    /// `overrideGroup` 非空时覆盖每条自带的 `agrp` —— 导出文件里的组在本机
    /// 未必存在，此时必须能改投到一个有权限的组，否则整份文件都写不进去。
    static func importItems(_ items: [KeychainExport.ParsedItem],
                           overrideGroup: String?,
                           replaceExisting: Bool,
                           progress: ((Int, Int) -> Void)? = nil) -> ImportOutcome {
        var outcome = ImportOutcome()
        var bestEffortRejected = false

        for (index, item) in items.enumerated() {
            progress?(index, items.count)

            if let reason = unimportableReason(item) {
                outcome.failures.append(ImportFailure(title: describe(item), reason: reason))
                continue
            }

            let settable = settableAttributes(for: item.itemClass)
            var attributes = item.attributes.filter { settable.contains($0.key) }
            attributes[kSecClass as String] = item.itemClass.secClass

            let group = overrideGroup?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !group.isEmpty {
                attributes[kSecAttrAccessGroup as String] = group
            }

            // 证书由 DER 决定身份，必须还原成 SecCertificate 再交给 kSecValueRef
            if item.itemClass == .certificate {
                guard let der = attributes[kSecValueData as String] as? Data,
                      let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                    outcome.failures.append(ImportFailure(title: describe(item),
                                                        reason: "不是合法的 DER 证书"))
                    continue
                }
                attributes.removeValue(forKey: kSecValueData as String)
                attributes[kSecValueRef as String] = certificate
            }

            let carriedBestEffort = attributes.keys.contains { bestEffortAttributes.contains($0) }

            // 一旦确认系统不收，后面的就别再白试一次了 ——
            // 否则整批每条都要发两次 SecItemAdd
            if bestEffortRejected {
                for key in bestEffortAttributes { attributes.removeValue(forKey: key) }
            }

            var status = SecItemAdd(attributes as CFDictionary, nil)

            // 系统不认这些「尽量保真」的属性时，摘掉再试一次，
            // 别让一个可选属性把整条条目挡在外面
            if status == errSecParam,
               attributes.keys.contains(where: { bestEffortAttributes.contains($0) }) {
                for key in bestEffortAttributes { attributes.removeValue(forKey: key) }
                status = SecItemAdd(attributes as CFDictionary, nil)
                if status == errSecSuccess {
                    bestEffortRejected = true
                    outcome.degraded += 1
                }
            } else if bestEffortRejected, status == errSecSuccess, carriedBestEffort {
                // 只算「本来带着这些属性、并且确实写进去了」的那些。
                // 不加这两个条件的话，一旦确认系统拒收，后面每一条都会被计入 ——
                // 包括本来就没有这些属性的，和干脆失败了的。
                outcome.degraded += 1
            }

            switch status {
            case errSecSuccess:
                outcome.added += 1

            case errSecDuplicateItem:
                guard replaceExisting else {
                    outcome.failures.append(ImportFailure(title: describe(item),
                                                        reason: message(for: status)))
                    continue
                }
                switch replace(attributes: attributes, itemClass: item.itemClass) {
                case .done:
                    outcome.replaced += 1
                case .failed(let replaceStatus):
                    outcome.failures.append(ImportFailure(title: describe(item),
                                                        reason: message(for: replaceStatus)))
                case .ambiguous:
                    outcome.failures.append(ImportFailure(
                        title: describe(item),
                        reason: "文件里的属性不足以唯一定位这条，覆盖会波及同组其它条目，已跳过"))
                }

            default:
                outcome.failures.append(ImportFailure(title: describe(item),
                                                        reason: message(for: status)))
            }
        }

        progress?(items.count, items.count)
        return outcome
    }

    /// 条目已存在时改为更新：用主键定位，只写非主键的部分。
    ///
    /// 定位查询是从**文件里有的**主键属性拼出来的，文件缺哪个就少哪个 ——
    /// 证书尤其明显：它的可写属性只有 labl/pdmn/agrp/sync，`ctyp`/`issr`/`slnr`
    /// 一个都不在其中，查询会退化成「这个组里的所有证书」。
    /// 而 `SecItemUpdate` 改的是**全部命中项**，那样一次导入就会把整组证书的
    /// 标签和保护级别一起改掉。所以动手前先数一遍，超过一条就不改。
    private enum ReplaceOutcome {
        case done
        case failed(OSStatus)
        /// 定位查询会命中不止一条，改下去等于批量改写别人的条目
        case ambiguous
    }

    private static func replace(attributes: [String: Any],
                               itemClass: KeychainItemClass) -> ReplaceOutcome {
        var query: [String: Any] = [kSecClass as String: itemClass.secClass]
        let primaryKeys = Set(itemClass.primaryKeyAttributes)
        for key in primaryKeys {
            if let value = attributes[key] { query[key] = value }
        }
        // 同步属性缺省按 false 处理，显式给出才不会漏掉 iCloud 条目
        if query[kSecAttrSynchronizable as String] == nil {
            query[kSecAttrSynchronizable as String] = false
        }

        guard matchCount(for: query) <= 1 else { return .ambiguous }

        var changes: [String: Any] = [:]
        for (key, value) in attributes
        where !primaryKeys.contains(key) && key != (kSecClass as String) {
            changes[key] = value
        }
        // 证书的身份就是那份 DER：主键既然对上了，就是同一张证书，
        // 没有「更新内容」可言。而 kSecValueRef 也不是 SecItemUpdate 能收的东西。
        changes.removeValue(forKey: kSecValueRef as String)
        guard !changes.isEmpty else { return .done }

        let status = SecItemUpdate(query as CFDictionary, changes as CFDictionary)
        return status == errSecSuccess ? .done : .failed(status)
    }

    /// 有些条目在原理上就导不进来，与其让它撞进 SecItemAdd 拿一个 -50，
    /// 不如提前识别并说清楚为什么。
    private static func unimportableReason(_ item: KeychainExport.ParsedItem) -> String? {
        // 文件里的值就解不出来，写进去只会造出一条内容不对的条目
        if let failure = item.decodeFailure { return "文件内容有误：\(failure)" }

        guard item.itemClass == .key else { return nil }

        // 安全隔区里生成的密钥：材料从不离开芯片，导出文件里本来就没有 v_Data，
        // 任何工具都无法重建
        if let token = KeychainItem.stringValue(item.attributes["tkid"]), !token.isEmpty {
            return "由安全隔区（\(token)）生成，密钥材料从不离开芯片，无法导入"
        }

        // 不可导出的密钥同理：导出时就没带出内容
        if item.attributes[kSecValueData as String] == nil {
            return "导出文件里没有密钥内容（该密钥不可导出），无法重建"
        }

        return nil
    }

    private static func describe(_ item: KeychainExport.ParsedItem) -> String {
        let candidates = [kSecAttrService, kSecAttrServer, kSecAttrLabel, kSecAttrAccount]
            .map { $0 as String }
        for key in candidates {
            if let text = KeychainItem.stringValue(item.attributes[key]), !text.isEmpty {
                return text
            }
        }
        return "(\(item.itemClass.displayName)条目)"
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
