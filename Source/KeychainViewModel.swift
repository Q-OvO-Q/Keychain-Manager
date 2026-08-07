import Foundation
import Security

let untaggedFilterKey = "__untagged__"

/// 筛选面板用的计数条目。
/// 用结构体而不是具名元组：Swift 不支持指向元组元素的 KeyPath，
/// `ForEach(..., id: \.group)` 对元组编译不过。
struct ClassCount: Identifiable {
    let itemClass: KeychainItemClass
    let count: Int
    var id: String { itemClass.rawValue }
}

struct GroupCount: Identifiable {
    let group: String
    let count: Int
    var id: String { group }
}

/// 列表状态与全部业务动作。
///
/// 所有 `@Published` 属性只在主线程写入；keychain 查询放到后台队列执行后再回主线程提交。
/// 旧实现在后台线程里直接读写 `@State` 与 `items`，既有数据竞争，
/// 也会因为 `items` 还没被赋值而算出错误的提示文案。
final class KeychainViewModel: ObservableObject {

    // MARK: - 持久化设置

    private let targetGroupKey = "targetAccessGroup"
    private let allGroupsKey = "useAllAccessibleGroups"
    private let enabledClassesKey = "enabledItemClasses"
    private let includeProtectedKey = "includeProtectedItems"

    @Published var targetGroup: String {
        didSet { UserDefaults.standard.set(targetGroup, forKey: targetGroupKey) }
    }

    /// 不限定 Access Group 查询。默认开启：这样既能看到全部有权访问的条目，
    /// 也不会因为通配符 Group 缺少 entitlement 而查不到任何东西。
    @Published var useAllGroups: Bool {
        didSet { UserDefaults.standard.set(useAllGroups, forKey: allGroupsKey) }
    }

    @Published var enabledClasses: Set<KeychainItemClass> {
        didSet {
            UserDefaults.standard.set(enabledClasses.map(\.rawValue), forKey: enabledClassesKey)
        }
    }

    /// 枚举时是否允许系统弹出验证。
    ///
    /// 关闭（默认）时跳过需要验证的条目：不会弹框、也不会因为整批认证失败而丢掉整个类别，
    /// 代价是受保护条目不出现在列表里。
    /// 开启后受保护条目会被列出，但可能弹出 Face ID；某个组验证失败时会自动退回跳过重查，
    /// 因此最差也不会比关闭时少拿到条目。
    @Published var includeProtectedItems: Bool {
        didSet { UserDefaults.standard.set(includeProtectedItems, forKey: includeProtectedKey) }
    }

    // MARK: - 数据

    @Published private(set) var items: [KeychainItem] = []
    @Published private(set) var isLoading = false
    @Published private(set) var isUnlocking = false
    @Published private(set) var isDeleting = false
    @Published var statusMessage = "正在读取描述文件…"
    @Published var alertMessage: String?

    @Published private(set) var detectedGroups: [String] = []
    @Published private(set) var profileSummary: String?

    /// 本次查询中每个失败的 (类别, Access Group)。
    /// 弹验证的到底是哪个组，只能靠它定位 —— 状态栏放不下，界面上可点开查看全部。
    @Published private(set) var enumerationFailures: [String] = []

    // MARK: - 筛选与选择

    @Published var searchText = ""
    @Published var selectedTagFilter = ""
    /// nil 表示不限类别
    @Published var classFilter: KeychainItemClass?
    /// 空串表示不限 Access Group
    @Published var groupFilter = ""
    @Published var isSelectionMode = false
    @Published var selectedIDs: Set<String> = []

    // MARK: - 初始化

    init() {
        let defaults = UserDefaults.standard
        targetGroup = defaults.string(forKey: targetGroupKey) ?? ""
        useAllGroups = defaults.object(forKey: allGroupsKey) as? Bool ?? true
        includeProtectedItems = defaults.object(forKey: includeProtectedKey) as? Bool ?? false

        if let raw = defaults.array(forKey: enabledClassesKey) as? [String] {
            let restored = raw.compactMap { KeychainItemClass(rawValue: $0) }
            enabledClasses = restored.isEmpty ? [.genericPassword, .internetPassword] : Set(restored)
        } else {
            // 默认只查密码类，密钥与证书按需开启
            enabledClasses = [.genericPassword, .internetPassword]
        }
    }

    // MARK: - 派生状态

    var currentScope: KeychainScope? {
        if useAllGroups { return .allAccessible }
        let group = targetGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        return group.isEmpty ? nil : .group(group)
    }

    var scopeDescription: String {
        currentScope?.displayName ?? "未指定"
    }

    /// 筛选维度。算某个维度的计数时要排除它自己，否则计数不会随其它维度联动
    private enum Facet {
        case itemClass, group, tag
    }

    var filteredItems: [KeychainItem] {
        narrowed(excluding: nil)
    }

    /// 应用除 `facet` 之外的全部筛选条件。
    /// 传 nil 表示全都应用，即列表实际显示的内容。
    private func narrowed(excluding facet: Facet?) -> [KeychainItem] {
        var result = items

        if facet != .itemClass, let classFilter {
            result = result.filter { $0.itemClass == classFilter }
        }

        if facet != .group, !groupFilter.isEmpty {
            result = result.filter { $0.accessGroup == groupFilter }
        }

        if facet != .tag {
            switch selectedTagFilter {
            case "":
                break
            case untaggedFilterKey:
                result = result.filter { $0.appTag.isEmpty }
            default:
                result = result.filter { $0.appTag == selectedTagFilter }
            }
        }

        // 搜索词对所有维度都生效，计数才和看到的列表对得上
        let keyword = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !keyword.isEmpty {
            // searchIndex 是查询结束时预先拼好的，这里只做子串比较
            result = result.filter {
                $0.searchIndex.contains(keyword) || $0.appTag.lowercased().contains(keyword)
            }
        }

        return result
    }

    var hasActiveFilter: Bool {
        classFilter != nil || !groupFilter.isEmpty || !selectedTagFilter.isEmpty
    }

    /// 各筛选维度「全部」一项对应的基数
    var classFacetTotal: Int { narrowed(excluding: .itemClass).count }
    var groupFacetTotal: Int { narrowed(excluding: .group).count }

    /// 类别计数，已应用组 / 标签 / 搜索的筛选
    var classCounts: [ClassCount] {
        let base = narrowed(excluding: .itemClass)
        return KeychainItemClass.allCases.compactMap { itemClass in
            let count = base.filter { $0.itemClass == itemClass }.count
            return count > 0 ? ClassCount(itemClass: itemClass, count: count) : nil
        }
    }

    /// Access Group 计数，已应用类别 / 标签 / 搜索的筛选，按条目数从多到少
    var groupCounts: [GroupCount] {
        var counts: [String: Int] = [:]
        for item in narrowed(excluding: .group) where !item.accessGroup.isEmpty {
            counts[item.accessGroup, default: 0] += 1
        }
        return counts
            .map { GroupCount(group: $0.key, count: $0.value) }
            .sorted {
                $0.count != $1.count
                    ? $0.count > $1.count
                    : $0.group.localizedStandardCompare($1.group) == .orderedAscending
            }
    }

    func clearFilters() {
        classFilter = nil
        groupFilter = ""
        selectedTagFilter = ""
    }

    /// 标签计数，已应用类别 / 组 / 搜索的筛选
    var tagCounts: [String: Int] {
        var counts: [String: Int] = [:]
        for item in narrowed(excluding: .tag) {
            let tag = item.appTag
            let key = tag.isEmpty ? untaggedFilterKey : tag
            counts[key, default: 0] += 1
        }
        return counts
    }

    /// 标签筛选条里「全部」对应的基数
    var tagFacetTotal: Int { narrowed(excluding: .tag).count }

    var unreadableCount: Int {
        items.filter { $0.dataStatus != nil && $0.dataStatus != errSecSuccess }.count
    }

    var selectedItems: [KeychainItem] {
        items.filter { selectedIDs.contains($0.id) }
    }

    func item(withID id: String) -> KeychainItem? {
        items.first { $0.id == id }
    }

    // MARK: - 启动

    func bootstrap() {
        guard items.isEmpty, !isLoading else { return }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // 代码签名里的 entitlements 才是内核实际执行的那一份，
            // 描述文件只作补充（它可能包含签名后被移除的组，留着无妨）
            let entitlements = EntitlementsReader.parse()
            let signedGroups = entitlements.map { EntitlementsReader.accessGroups(from: $0) } ?? []
            let profile = ProvisioningProfileParser.parse()

            var groups = signedGroups
            var seen = Set(groups)
            for group in profile?.allAccessGroups ?? [] where seen.insert(group).inserted {
                groups.append(group)
            }

            let summary = KeychainViewModel.describeSources(signedGroupCount: signedGroups.count,
                                                            profile: profile)

            DispatchQueue.main.async {
                guard let self else { return }

                self.detectedGroups = groups
                self.profileSummary = summary

                if self.targetGroup.isEmpty, let first = groups.first {
                    self.targetGroup = first
                }
                if groups.isEmpty {
                    self.statusMessage = "未能读取 entitlements，请手动指定 Access Group"
                }

                self.refresh()
            }
        }
    }

    private static func describeSources(signedGroupCount: Int,
                                       profile: ProvisioningProfile?) -> String? {
        var parts: [String] = []
        if signedGroupCount > 0 {
            parts.append("签名 entitlements：\(signedGroupCount) 个组")
        } else {
            parts.append("未能读取签名 entitlements")
        }
        if let profile {
            parts.append(profile.summary)
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    // MARK: - 查询

    func refresh() {
        guard !isLoading else { return }

        guard let scope = currentScope else {
            statusMessage = "请选择「全部可访问」或输入一个 Access Group"
            return
        }

        let classes = KeychainItemClass.allCases.filter { enabledClasses.contains($0) }
        guard !classes.isEmpty else {
            items = []
            selectedIDs.removeAll()
            statusMessage = "请至少选择一个条目类别"
            return
        }

        isLoading = true
        statusMessage = "正在查询…"

        // 「全部可访问」靠逐组枚举实现，需要完整的组列表
        let knownGroups = detectedGroups
        let includeProtected = includeProtectedItems

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = KeychainStore.fetchItems(scope: scope,
                                                  classes: classes,
                                                  knownGroups: knownGroups,
                                                  includeProtected: includeProtected) { text in
                DispatchQueue.main.async { self?.statusMessage = text }
            }
            DispatchQueue.main.async {
                self?.apply(result)
            }
        }
    }

    private func apply(_ result: KeychainFetchResult) {
        isLoading = false
        items = result.items
        selectedIDs.formIntersection(Set(result.items.map(\.id)))

        // 先给新增条目补上标签，再判断哪些标签成了孤儿
        applyPendingTagIfNeeded()

        mergeDiscoveredGroups(from: result.items)

        // 清理孤立标签的前提是「这次真的把该看的都看全了」：
        // 枚举无失败，且受保护条目没有被跳过（跳过时它们不在结果里，
        // 无从区分「已删除」和「只是没列出来」）。
        // 清理范围还要限定在本次查询的类别内 —— 否则取消勾选某个类别后刷新，
        // 该类别的标签会被整批当成孤儿抹掉。
        if result.classErrors.isEmpty && includeProtectedItems {
            let existingKeys = Set(result.items.map(\.tagKey))
            let groups = Set(result.items.map(\.accessGroup)).filter { !$0.isEmpty }
            let classNames = Set(enabledClasses.map(\.displayName))
            TagManager.shared.cleanupOrphanedTags(existingKeys: existingKeys,
                                                  inAccessGroups: groups,
                                                  forClasses: classNames)
        }

        enumerationFailures = result.classErrors.map(\.description)

        var parts = ["共 \(result.items.count) 条"]
        if unreadableCount > 0 {
            parts.append("\(unreadableCount) 条受保护/不可读")
        }
        if !enumerationFailures.isEmpty {
            parts.append("\(enumerationFailures.count) 项查询失败（点击查看）")
        }
        statusMessage = parts.joined(separator: " · ")

        resetTagFilterIfNeeded()
    }

    /// 把查询结果里实际出现过的 Access Group 并入可选列表。
    ///
    /// 正常情况下签名 entitlements 已经给全了；这里兜住解析失败、
    /// 或条目落在 entitlements 未列出的组里的情况。
    private func mergeDiscoveredGroups(from items: [KeychainItem]) {
        let discovered = Set(items.map(\.accessGroup)).filter { !$0.isEmpty }
        let missing = discovered.subtracting(detectedGroups)
        guard !missing.isEmpty else { return }

        // 保留 entitlements 给出的原有顺序，新发现的追加在后。
        // localizedStandardCompare 让 shared.2 排在 shared.10 前面而不是字典序
        detectedGroups += missing.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    // MARK: - 删除

    /// 逐条删除并核对结果。失败的条目会留在列表里并给出原因，
    /// 不再出现「删除成功、刷新后又冒出来」的假象。
    /// 删除放到后台队列执行。
    ///
    /// 每条最多要走 4 次同步 keychain 调用（持久引用 → 完整主键 → 退化主键 → 存在性核对），
    /// 批量选中上千条时就是上千次同步 IPC。留在主线程会直接卡死界面，
    /// 数量再大还会被看门狗杀掉。
    func delete(_ targets: [KeychainItem]) {
        guard !targets.isEmpty, !isDeleting else { return }

        isDeleting = true
        statusMessage = "正在删除 0/\(targets.count)…"

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var deletedIDs: Set<String> = []
            var deletedTagKeys: Set<String> = []
            var failures: [KeychainOperationFailure] = []

            for (index, item) in targets.enumerated() {
                let status = KeychainStore.delete(item)
                if status == errSecSuccess {
                    deletedIDs.insert(item.id)
                    deletedTagKeys.insert(item.tagKey)
                } else {
                    failures.append(KeychainOperationFailure(item: item, status: status))
                }

                if index % 20 == 0 {
                    let done = index
                    DispatchQueue.main.async {
                        self?.statusMessage = "正在删除 \(done)/\(targets.count)…"
                    }
                }
            }

            DispatchQueue.main.async {
                self?.finishDelete(deletedIDs: deletedIDs,
                                   deletedTagKeys: deletedTagKeys,
                                   failures: failures)
            }
        }
    }

    private func finishDelete(deletedIDs: Set<String>,
                             deletedTagKeys: Set<String>,
                             failures: [KeychainOperationFailure]) {
        isDeleting = false

        items.removeAll { deletedIDs.contains($0.id) }
        selectedIDs.subtract(deletedIDs)

        // 多条条目可能共用同一个 tagKey，只清理确实没有条目再引用的标签
        let remainingKeys = Set(items.map(\.tagKey))
        let orphaned = deletedTagKeys.subtracting(remainingKeys)
        if !orphaned.isEmpty {
            TagManager.shared.removeTags(for: Array(orphaned))
        }

        resetTagFilterIfNeeded()

        if failures.isEmpty {
            statusMessage = "已删除 \(deletedIDs.count) 条 · 剩余 \(items.count) 条"
        } else {
            statusMessage = "删除 \(deletedIDs.count) 条成功，\(failures.count) 条失败"
            alertMessage = KeychainViewModel.describe(failures: failures)
        }
    }

    func deleteFiltered(at offsets: IndexSet) {
        let visible = filteredItems
        let targets = offsets.compactMap { index -> KeychainItem? in
            visible.indices.contains(index) ? visible[index] : nil
        }
        delete(targets)
    }

    private static func describe(failures: [KeychainOperationFailure]) -> String {
        let shown = failures.prefix(6).map { failure in
            "「\(failure.item.displayTitle)」\(KeychainStore.message(for: failure.status))"
        }
        var text = shown.joined(separator: "\n")
        if failures.count > shown.count {
            text += "\n…另有 \(failures.count - shown.count) 条失败"
        }
        return text
    }

    // MARK: - 新增

    /// 新增条目后待应用的标签。写入时 Access Group 可能由系统决定，
    /// 无法预先算出 tagKey，只能等刷新拿到真实条目再打标签。
    ///
    /// 靠「刷新后多出来的条目」来认，而不是拿属性去比对：密钥和证书没有 title，
    /// 按 title + account 匹配对它们永远匹配不上，标签会被静默丢掉。
    private struct PendingTag {
        let tag: String
        let knownIDs: Set<String>
    }

    private var pendingTag: PendingTag?

    func add(_ newItem: KeychainStore.NewItem, tag: String) -> Bool {
        let status = KeychainStore.add(newItem)
        guard status == errSecSuccess else {
            alertMessage = "新增失败：\(KeychainStore.message(for: status))"
            return false
        }

        let trimmedTag = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedTag.isEmpty {
            pendingTag = PendingTag(tag: trimmedTag, knownIDs: Set(items.map(\.id)))
        }

        statusMessage = "已新增「\(newItem.title)」"
        refresh()
        return true
    }

    private func applyPendingTagIfNeeded() {
        guard let pending = pendingTag else { return }
        pendingTag = nil

        let keys = items
            .filter { !pending.knownIDs.contains($0.id) }
            .map(\.tagKey)

        guard !keys.isEmpty else { return }
        TagManager.shared.setTag(pending.tag, for: keys)
    }

    // MARK: - 解锁受保护条目

    /// 主动解锁：这是唯一允许弹出生物识别的入口。
    /// 验证框会阻塞发起线程，因此必须放到后台队列，否则主线程卡住会被看门狗杀掉。
    func unlockData(for item: KeychainItem, completion: @escaping (KeychainItem?) -> Void) {
        guard !isUnlocking else { return }
        isUnlocking = true

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let outcome = KeychainStore.copyData(for: item, allowAuthenticationUI: true)

            DispatchQueue.main.async {
                guard let self else { return }
                self.isUnlocking = false

                var updated: KeychainItem?
                if let index = self.items.firstIndex(where: { $0.id == item.id }) {
                    self.items[index].data = outcome.data
                    self.items[index].dataStatus = outcome.status
                    // 解锁后内容才可读，检索串要跟着补上
                    self.items[index].searchIndex = KeychainStore.makeSearchIndex(for: self.items[index])
                    updated = self.items[index]
                }

                if outcome.status != errSecSuccess {
                    self.alertMessage = KeychainViewModel.describeUnlockFailure(outcome.status)
                }
                completion(updated)
            }
        }
    }

    private static func describeUnlockFailure(_ status: OSStatus) -> String {
        guard status == errSecAuthFailed else {
            return "解锁失败：\(KeychainStore.message(for: status))"
        }
        // 验证已经通过却仍然 -25293，说明卡在访问控制而不是生物识别本身
        return """
        解锁失败：认证失败 (-25293)

        如果 Face ID 验证本身是通过的，那么问题不在验证，而在条目的访问控制：\
        SecAccessControl 会绑定创建它的那个 App 的身份，共享 Access Group 只让你\
        看得到这条目，不代表能满足它的解锁条件。这种情况下本 App 读不出其内容，\
        但仍然可以查看元数据、改标签和删除。
        """
    }

    // MARK: - 导入 / 导出

    /// 待导出的 JSON，非 nil 时界面弹出保存面板
    @Published var exportDocument: JSONDocument?
    @Published private(set) var exportFileName = "keychain_export.json"
    @Published private(set) var isImporting = false
    /// 导入结果详情，供结果弹窗展示
    @Published var importReport: [String]?

    /// 把给定条目编码成 JSON。
    ///
    /// 受保护、数据读不出来的条目仍会导出属性，只是缺 `v_Data` —— 与其整条丢掉，
    /// 不如把能带走的带走，并在提示里说明有几条是这种情况。
    func export(_ targets: [KeychainItem]) {
        guard !targets.isEmpty else {
            statusMessage = "没有可导出的条目"
            return
        }

        let groups = Set(targets.map(\.accessGroup)).filter { !$0.isEmpty }
        // 格式里 access_group 是单值；跨组时留空，导入端按每条自带的 agrp 走
        let accessGroup = groups.count == 1 ? (groups.first ?? "") : ""

        do {
            let data = try KeychainExport.makeJSON(items: targets, accessGroup: accessGroup)
            exportFileName = KeychainExport.suggestedFileName(accessGroup: accessGroup)
            exportDocument = JSONDocument(data: data)

            let withoutData = targets.filter { !$0.isDataReadable }.count
            var parts = ["已准备 \(targets.count) 条"]
            if groups.count > 1 { parts.append("跨 \(groups.count) 个组") }
            if withoutData > 0 { parts.append("\(withoutData) 条数据不可读，仅导出属性") }
            statusMessage = parts.joined(separator: " · ")
        } catch {
            alertMessage = "导出失败：\(error.localizedDescription)"
        }
    }

    /// 解析并写入一份导出文件。
    ///
    /// `overrideGroup` 为空时沿用文件里每条自带的 `agrp`。
    func importFile(at url: URL, overrideGroup: String, replaceExisting: Bool) {
        guard !isImporting else { return }

        // 文件来自「文件」App，必须先取得安全作用域访问权
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: url)
            importJSON(data, overrideGroup: overrideGroup, replaceExisting: replaceExisting)
        } catch {
            alertMessage = "读取失败：\(error.localizedDescription)"
        }
    }

    /// 直接从一段 JSON 字节导入。文件选取器不可用时（粘贴）走这条。
    func importJSON(_ data: Data, overrideGroup: String, replaceExisting: Bool) {
        guard !isImporting else { return }

        let parsed: KeychainExport.ParsedFile
        do {
            parsed = try KeychainExport.parse(data)
        } catch {
            alertMessage = "解析失败：\(error.localizedDescription)"
            return
        }

        isImporting = true
        statusMessage = "正在导入 0/\(parsed.items.count)…"

        let group = overrideGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        let items = parsed.items

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let outcome = KeychainStore.importItems(items,
                                                    overrideGroup: group.isEmpty ? nil : group,
                                                    replaceExisting: replaceExisting) { done, total in
                if done % 20 == 0 {
                    DispatchQueue.main.async {
                        self?.statusMessage = "正在导入 \(done)/\(total)…"
                    }
                }
            }

            DispatchQueue.main.async {
                self?.finishImport(outcome)
            }
        }
    }

    private func finishImport(_ outcome: KeychainStore.ImportOutcome) {
        isImporting = false

        var parts = ["新增 \(outcome.added) 条"]
        if outcome.replaced > 0 { parts.append("覆盖 \(outcome.replaced) 条") }
        // 系统拒收了某些可选属性、摘掉才写进去的：没失败，但不是原样还原
        if outcome.degraded > 0 { parts.append("\(outcome.degraded) 条未能完整还原") }
        if !outcome.failures.isEmpty { parts.append("失败 \(outcome.failures.count) 条") }
        statusMessage = parts.joined(separator: " · ")

        if !outcome.failures.isEmpty {
            importReport = outcome.failures.map { "「\($0.title)」\($0.reason)" }
        }

        // 写入后必须重查：新条目的持久引用、系统补上的属性都只能从钥匙串拿
        refresh()
    }

    // MARK: - 修改元数据

    /// 改完立刻重查该条目的属性，让详情页显示的是系统里真实的值而不是我们以为写进去的值
    func updateAttributes(_ item: KeychainItem, changes: [String: Any]) -> Bool {
        let status = KeychainStore.updateAttributes(item, changes: changes)
        guard status == errSecSuccess else {
            alertMessage = "保存元数据失败：\(KeychainStore.message(for: status))"
            return false
        }
        // 就地重读这一条，而不是为一次改动重跑整轮逐组查询
        if let index = items.firstIndex(where: { $0.id == item.id }),
           let reloaded = KeychainStore.reload(item) {
            items[index] = reloaded
        }

        statusMessage = "已更新「\(item.displayTitle)」的元数据"
        return true
    }

    // MARK: - 修改数据

    func updateData(_ item: KeychainItem, to data: Data) -> Bool {
        let status = KeychainStore.updateData(item, to: data)
        guard status == errSecSuccess else {
            alertMessage = "保存失败：\(KeychainStore.message(for: status))"
            return false
        }

        if let index = items.firstIndex(where: { $0.id == item.id }) {
            items[index].data = data
            items[index].dataStatus = errSecSuccess
            // 检索串是查询结束时拼好的，数据变了不重算就搜不到新内容、反而能搜到旧内容
            items[index].searchIndex = KeychainStore.makeSearchIndex(for: items[index])
        }
        statusMessage = "已保存「\(item.displayTitle)」"
        return true
    }

    // MARK: - 标签

    func setTag(_ tag: String, for item: KeychainItem) {
        TagManager.shared.setTag(tag, for: item.tagKey)
        objectWillChange.send()
        resetTagFilterIfNeeded()
    }

    func applyTagToSelection(_ tag: String) {
        let targets = selectedItems
        guard !targets.isEmpty else { return }
        TagManager.shared.setTag(tag, for: targets.map(\.tagKey))
        objectWillChange.send()
        let trimmed = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        statusMessage = trimmed.isEmpty
            ? "已清除 \(targets.count) 条标签"
            : "已为 \(targets.count) 条设置标签「\(trimmed)」"
        resetTagFilterIfNeeded()
    }

    func clearTagForSelection() {
        applyTagToSelection("")
    }

    // MARK: - 选择

    func toggleSelection(_ id: String) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }

    func selectAllVisible() {
        selectedIDs = Set(filteredItems.map(\.id))
    }

    func clearSelection() {
        selectedIDs.removeAll()
    }

    func exitSelectionMode() {
        isSelectionMode = false
        selectedIDs.removeAll()
    }

    // MARK: - 其它

    func clearDisplay() {
        items = []
        selectedIDs.removeAll()
        clearFilters()
        enumerationFailures = []
        statusMessage = "已清空显示，点击刷新重新查询"
    }

    /// 筛选条件已无匹配项时自动放开，避免列表空白却看不出原因
    private func resetTagFilterIfNeeded() {
        if let classFilter, !items.contains(where: { $0.itemClass == classFilter }) {
            self.classFilter = nil
        }

        if !groupFilter.isEmpty, !items.contains(where: { $0.accessGroup == groupFilter }) {
            groupFilter = ""
        }

        guard !selectedTagFilter.isEmpty else { return }

        let stillMatches: Bool
        if selectedTagFilter == untaggedFilterKey {
            stillMatches = items.contains { $0.appTag.isEmpty }
        } else {
            stillMatches = items.contains { $0.appTag == selectedTagFilter }
        }

        if !stillMatches {
            selectedTagFilter = ""
        }
    }
}
