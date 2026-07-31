import Foundation
import Security

let untaggedFilterKey = "__untagged__"

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

    // MARK: - 数据

    @Published private(set) var items: [KeychainItem] = []
    @Published private(set) var isLoading = false
    @Published private(set) var isUnlocking = false
    @Published var statusMessage = "正在读取描述文件…"
    @Published var alertMessage: String?

    @Published private(set) var detectedGroups: [String] = []
    @Published private(set) var profileSummary: String?

    // MARK: - 筛选与选择

    @Published var searchText = ""
    @Published var selectedTagFilter = ""
    @Published var isSelectionMode = false
    @Published var selectedIDs: Set<String> = []

    // MARK: - 初始化

    init() {
        let defaults = UserDefaults.standard
        targetGroup = defaults.string(forKey: targetGroupKey) ?? ""
        useAllGroups = defaults.object(forKey: allGroupsKey) as? Bool ?? true

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

    var filteredItems: [KeychainItem] {
        var result = items

        switch selectedTagFilter {
        case "":
            break
        case untaggedFilterKey:
            result = result.filter { $0.appTag.isEmpty }
        default:
            result = result.filter { $0.appTag == selectedTagFilter }
        }

        let keyword = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !keyword.isEmpty {
            result = result.filter { item in
                item.displayTitle.lowercased().contains(keyword)
                    || item.account.lowercased().contains(keyword)
                    || item.accessGroup.lowercased().contains(keyword)
                    || item.appTag.lowercased().contains(keyword)
                    || (item.isDataReadable
                        && (String(data: item.data ?? Data(), encoding: .utf8)?.lowercased().contains(keyword) ?? false))
            }
        }

        return result
    }

    var tagCounts: [String: Int] {
        var counts: [String: Int] = [:]
        for item in items {
            let tag = item.appTag
            let key = tag.isEmpty ? untaggedFilterKey : tag
            counts[key, default: 0] += 1
        }
        return counts
    }

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

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = KeychainStore.fetchItems(scope: scope,
                                                  classes: classes,
                                                  knownGroups: knownGroups) { text in
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

        // 只有全部类别都枚举成功，才敢按结果清理标签
        if result.classErrors.isEmpty {
            let existingKeys = Set(result.items.map(\.tagKey))
            let groups = Set(result.items.map(\.accessGroup)).filter { !$0.isEmpty }
            TagManager.shared.cleanupOrphanedTags(existingKeys: existingKeys, inAccessGroups: groups)
        }

        var parts = ["共 \(result.items.count) 条"]
        if unreadableCount > 0 {
            parts.append("\(unreadableCount) 条受保护/不可读")
        }
        if !result.classErrors.isEmpty {
            // 逐组枚举下失败项可能很多（例如某个组对每个类别都失败），只列前两条
            let shown = result.classErrors.prefix(2).map(\.description)
            var detail = shown.joined(separator: "；")
            if result.classErrors.count > shown.count {
                detail += "；另有 \(result.classErrors.count - shown.count) 项失败"
            }
            parts.append(detail)
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
    func delete(_ targets: [KeychainItem]) {
        guard !targets.isEmpty else { return }

        var deletedIDs: Set<String> = []
        var deletedTagKeys: Set<String> = []
        var failures: [KeychainOperationFailure] = []

        for item in targets {
            let status = KeychainStore.delete(item)
            if status == errSecSuccess {
                deletedIDs.insert(item.id)
                deletedTagKeys.insert(item.tagKey)
            } else {
                failures.append(KeychainOperationFailure(item: item, status: status))
            }
        }

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
    private struct PendingTag {
        let itemClass: KeychainItemClass
        let title: String
        let account: String
        let tag: String
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
            pendingTag = PendingTag(itemClass: newItem.itemClass,
                                    title: newItem.title,
                                    account: newItem.account,
                                    tag: trimmedTag)
        }

        statusMessage = "已新增「\(newItem.title)」"
        refresh()
        return true
    }

    private func applyPendingTagIfNeeded() {
        guard let pending = pendingTag else { return }
        pendingTag = nil

        let keys = items
            .filter {
                $0.itemClass == pending.itemClass
                    && $0.displayTitle == pending.title
                    && $0.account == pending.account
            }
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
                    updated = self.items[index]
                }

                if outcome.status != errSecSuccess {
                    self.alertMessage = "解锁失败：\(KeychainStore.message(for: outcome.status))"
                }
                completion(updated)
            }
        }
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
        selectedTagFilter = ""
        statusMessage = "已清空显示，点击刷新重新查询"
    }

    /// 当前标签筛选已无匹配项时退回「全部」，避免列表空白无从下手
    private func resetTagFilterIfNeeded() {
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
