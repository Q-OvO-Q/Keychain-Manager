import SwiftUI
import Security

// MARK: - 数据模型
struct KeychainItem: Identifiable, Hashable {
    let id = UUID()
    let itemClass: CFString // kSecClassGenericPassword 或 kSecClassInternetPassword
    let itemClassDisplay: String // "通用" 或 "网络"
    
    // 核心标识
    let title: String   // genp用service, inet用server
    let account: String
    let accessGroup: String
    
    // 数据
    let rawData: Data
    let isStringData: Bool // 是否原本就是文本
    
    // 所有原始属性 (用于展示详情)
    let rawAttributes: [String: String]
    
    // App 标签
    var appTag: String {
        get { TagManager.shared.getTag(for: uniqueKey) }
        set { TagManager.shared.setTag(newValue, for: uniqueKey) }
    }
    
    // 唯一标识符，用于存储tag
    var uniqueKey: String {
        // 使用更安全的分隔符避免冲突
        let separator = "|||"
        return "\(itemClassDisplay)\(separator)\(title)\(separator)\(account)\(separator)\(accessGroup)"
    }
    
    // 静态方法用于生成唯一key
    static func makeUniqueKey(classDisplay: String, title: String, account: String, accessGroup: String) -> String {
        let separator = "|||"
        return "\(classDisplay)\(separator)\(title)\(separator)\(account)\(separator)\(accessGroup)"
    }
}

// MARK: - Tag管理器
class TagManager: ObservableObject {
    static let shared = TagManager()
    private let userDefaults = UserDefaults.standard
    private let tagsKey = "KeychainItemTags"
    
    @Published var allTags: Set<String> = []
    
    init() {
        loadAllTags()
    }
    
    func getTag(for key: String) -> String {
        if let tags = userDefaults.dictionary(forKey: tagsKey) as? [String: String] {
            return tags[key] ?? ""
        }
        return ""
    }
    
    func setTag(_ tag: String, for key: String) {
        var tags = userDefaults.dictionary(forKey: tagsKey) as? [String: String] ?? [:]
        if tag.isEmpty {
            tags.removeValue(forKey: key)
        } else {
            tags[key] = tag
        }
        userDefaults.set(tags, forKey: tagsKey)
        loadAllTags()
    }
    
    /// 清理孤立标签：移除属于指定 Access Group 但不再有对应 Keychain 条目的标签
    func cleanupOrphanedTags(existingItemKeys: Set<String>, inAccessGroups groups: Set<String>) {
        guard !groups.isEmpty else { return }
        var tags = userDefaults.dictionary(forKey: tagsKey) as? [String: String] ?? [:]
        let originalCount = tags.count
        
        tags = tags.filter { key, _ in
            // uniqueKey 格式: classDisplay|||title|||account|||accessGroup
            let components = key.components(separatedBy: "|||")
            guard components.count >= 4 else { return true }
            let keyGroup = components[components.count - 1]
            // 仅清理属于已加载 Access Group 的条目
            if groups.contains(keyGroup) {
                return existingItemKeys.contains(key)
            }
            return true
        }
        
        if tags.count != originalCount {
            userDefaults.set(tags, forKey: tagsKey)
            loadAllTags()
        }
    }
    
    private func loadAllTags() {
        let newTags: Set<String>
        if let tags = userDefaults.dictionary(forKey: tagsKey) as? [String: String] {
            newTags = Set(tags.values.filter { !$0.isEmpty })
        } else {
            newTags = []
        }
        if Thread.isMainThread {
            allTags = newTags
        } else {
            DispatchQueue.main.async {
                self.allTags = newTags
            }
        }
    }
}

// MARK: - 主视图
private let untaggedFilterKey = "__untagged__"

struct ContentView: View {
    @AppStorage("targetAccessGroup") private var targetGroup: String = ""
    @State private var items: [KeychainItem] = []
    @State private var statusMessage = "正在检测可用的 Keychain Access Groups..."
    @StateObject private var tagManager = TagManager.shared
    @State private var selectedTagFilter: String = ""
    
    // 批量选择相关
    @State private var isSelectionMode = false
    @State private var selectedItems: Set<UUID> = []
    @State private var showBatchTagSheet = false
    @State private var batchTagValue = ""
    
    // 描述文件相关
    @State private var detectedGroups: [String] = []
    @State private var showManualInput = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // 顶部区域
                VStack(spacing: 8) {
                    // Access Group 选择区
                    if !detectedGroups.isEmpty && !showManualInput {
                        accessGroupSection()
                    } else {
                        manualInputSection()
                    }
                    
                    // 操作按钮
                    HStack {
                        Button("刷新列表") { fetchItems() }
                            .buttonStyle(.borderedProminent)
                        
                        Button("清空显示") {
                            items.removeAll()
                            selectedItems.removeAll()
                        }
                        .buttonStyle(.bordered)
                        
                        Button(isSelectionMode ? "退出选择" : "批量选择") {
                            isSelectionMode.toggle()
                            if !isSelectionMode {
                                selectedItems.removeAll()
                            }
                        }
                        .buttonStyle(.bordered)
                    }
                    
                    // 批量操作按钮
                    if isSelectionMode {
                        VStack(spacing: 6) {
                            HStack {
                                Text("已选择 \(selectedItems.count) 项")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                
                                Spacer()
                                
                                Button("全选") {
                                    selectedItems = Set(filteredItems.map { $0.id })
                                }
                                .font(.caption)
                                .buttonStyle(.bordered)
                                .disabled(filteredItems.isEmpty)
                                
                                Button("全不选") {
                                    selectedItems.removeAll()
                                }
                                .font(.caption)
                                .buttonStyle(.bordered)
                                .disabled(selectedItems.isEmpty)
                            }
                            .padding(.horizontal)
                            
                            HStack {
                                Button("批量标签") {
                                    showBatchTagSheet = true
                                }
                                .buttonStyle(.borderedProminent)
                                .disabled(selectedItems.isEmpty)
                                
                                Button("批量取消标签") {
                                    batchUntag()
                                }
                                .buttonStyle(.bordered)
                                .disabled(selectedItems.isEmpty)
                                
                                Button("批量删除") {
                                    batchDelete()
                                }
                                .buttonStyle(.bordered)
                                .tint(.red)
                                .disabled(selectedItems.isEmpty)
                            }
                            .padding(.horizontal)
                        }
                    }
                    
                    // Tag 筛选器
                    tagFilterSection()
                    
                    Text(statusMessage).font(.caption).foregroundColor(.gray)
                }
                .padding(.top, 10)
                
                // 列表区
                List {
                    ForEach(filteredItems) { item in
                        HStack(spacing: 10) {
                            if isSelectionMode {
                                Image(systemName: selectedItems.contains(item.id) ? "checkmark.circle.fill" : "circle")
                                    .foregroundColor(selectedItems.contains(item.id) ? .blue : .gray)
                                    .onTapGesture {
                                        toggleSelection(for: item.id)
                                    }
                            }
                            
                            if isSelectionMode {
                                itemRowView(for: item)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        toggleSelection(for: item.id)
                                    }
                            } else {
                                NavigationLink(destination: ItemDetailView(item: item, onUpdate: fetchItems)) {
                                    itemRowView(for: item)
                                }
                            }
                        }
                    }
                    .onDelete(perform: isSelectionMode ? nil : deleteItems)
                }
                .listStyle(.plain)
            }
            .navigationTitle("Keychain Manager")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    NavigationLink(destination: AddItemView(targetGroup: targetGroup, onSave: fetchItems)) {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showBatchTagSheet) {
                BatchTagSheet(
                    tagManager: tagManager,
                    batchTagValue: $batchTagValue,
                    onSave: {
                        applyBatchTag()
                        showBatchTagSheet = false
                    }
                )
            }
            .onAppear {
                loadProvisioningProfile()
            }
        }
    }
    
    // 筛选后的items
    var filteredItems: [KeychainItem] {
        if selectedTagFilter.isEmpty {
            return items
        } else if selectedTagFilter == untaggedFilterKey {
            return items.filter { $0.appTag.isEmpty }
        } else {
            return items.filter { $0.appTag == selectedTagFilter }
        }
    }
    
    // 各标签的 item 数量统计
    var tagCounts: [String: Int] {
        var counts: [String: Int] = [:]
        for item in items {
            let tag = item.appTag
            if tag.isEmpty {
                counts[untaggedFilterKey] = (counts[untaggedFilterKey] ?? 0) + 1
            } else {
                counts[tag] = (counts[tag] ?? 0) + 1
            }
        }
        return counts
    }
    
    // MARK: - Helper Views
    
    /// 自动检测到的 Access Group 选择区
    @ViewBuilder
    func accessGroupSection() -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label("Keychain Access Groups", systemImage: "key.fill")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Button(action: { showManualInput = true }) {
                    Label("手动输入", systemImage: "keyboard")
                        .font(.caption)
                }
            }
            .padding(.horizontal)
            
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(detectedGroups, id: \.self) { group in
                        Button(action: {
                            targetGroup = group
                            fetchItems()
                        }) {
                            Text(group)
                                .font(.caption)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(targetGroup == group ? Color.accentColor : Color.gray.opacity(0.2))
                                .foregroundColor(targetGroup == group ? .white : .primary)
                                .cornerRadius(15)
                        }
                    }
                }
                .padding(.horizontal)
            }
        }
    }
    
    /// 手动输入 Access Group
    @ViewBuilder
    func manualInputSection() -> some View {
        VStack(spacing: 4) {
            if !detectedGroups.isEmpty {
                HStack {
                    Text("手动输入 Access Group")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("返回自动检测") {
                        showManualInput = false
                    }
                    .font(.caption)
                }
                .padding(.horizontal)
            }
            
            TextField("Access Group (例如 TEAMID.* 或 TEAMID.com.app)", text: $targetGroup)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .autocapitalization(.none)
                .padding(.horizontal)
        }
    }
    
    /// Tag 筛选区
    @ViewBuilder
    func tagFilterSection() -> some View {
        if !items.isEmpty && (!tagManager.allTags.isEmpty || tagCounts[untaggedFilterKey] != nil) {
            let counts = tagCounts
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    // 全部
                    filterChip(
                        label: "全部",
                        count: items.count,
                        isSelected: selectedTagFilter.isEmpty
                    ) {
                        selectedTagFilter = ""
                        selectedItems.removeAll()
                    }
                    
                    // 各标签
                    ForEach(Array(tagManager.allTags).sorted(), id: \.self) { tag in
                        if let count = counts[tag] {
                            filterChip(
                                label: tag,
                                count: count,
                                isSelected: selectedTagFilter == tag
                            ) {
                                selectedTagFilter = tag
                                selectedItems.removeAll()
                            }
                        }
                    }
                    
                    // 未标记
                    if let untaggedCount = counts[untaggedFilterKey], untaggedCount > 0 {
                        filterChip(
                            label: "未标记",
                            count: untaggedCount,
                            isSelected: selectedTagFilter == untaggedFilterKey
                        ) {
                            selectedTagFilter = untaggedFilterKey
                            selectedItems.removeAll()
                        }
                    }
                }
                .padding(.horizontal)
            }
        }
    }
    
    /// 筛选 Chip
    @ViewBuilder
    func filterChip(label: String, count: Int, isSelected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text("\(label)(\(count))")
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(isSelected ? Color.blue : Color.gray.opacity(0.2))
                .foregroundColor(isSelected ? .white : .primary)
                .cornerRadius(15)
        }
    }
    
    @ViewBuilder
    func itemRowView(for item: KeychainItem) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                // 类型标签
                Text(item.itemClassDisplay)
                    .font(.system(size: 10, weight: .bold))
                    .padding(3)
                    .background(item.itemClassDisplay == "网络" ? Color.green.opacity(0.2) : Color.blue.opacity(0.2))
                    .cornerRadius(4)
                
                // App Tag 标签
                if !item.appTag.isEmpty {
                    Text(item.appTag)
                        .font(.system(size: 10, weight: .bold))
                        .padding(3)
                        .background(Color.orange.opacity(0.2))
                        .foregroundColor(.orange)
                        .cornerRadius(4)
                }
                
                Spacer()
                
                // 数据预览
                Text(dataPreview(for: item))
                    .font(.caption2)
                    .foregroundColor(.gray)
                    .lineLimit(1)
            }
            
            // 标题 (Service / Server)
            Text(item.title)
                .font(.subheadline)
                .fontWeight(.medium)
                .lineLimit(1)
            
            // 底部行：账号 + Access Group
            HStack {
                Text(item.account.isEmpty ? "无账号" : item.account)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                Spacer()
                
                Text(item.accessGroup)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
    
    /// 数据预览文本
    func dataPreview(for item: KeychainItem) -> String {
        if item.isStringData {
            let str = String(data: item.rawData, encoding: .utf8) ?? ""
            if str.isEmpty { return "空" }
            return str.count > 16 ? String(str.prefix(16)) + "…" : str
        } else {
            return "HEX:\(item.rawData.count)B"
        }
    }
    
    // MARK: - 查询逻辑 (核心优化)
    
    /// 若当前标签筛选已无匹配项，自动重置为"全部"
    private func resetTagFilterIfNeeded(for itemList: [KeychainItem]) {
        guard !selectedTagFilter.isEmpty else { return }
        if selectedTagFilter == untaggedFilterKey {
            if !itemList.contains(where: { $0.appTag.isEmpty }) {
                selectedTagFilter = ""
            }
        } else {
            if !itemList.contains(where: { $0.appTag == selectedTagFilter }) {
                selectedTagFilter = ""
            }
        }
    }
    
    func fetchItems() {
        if targetGroup.isEmpty {
            statusMessage = "请输入目标 Group"
            return
        }
        
        var newItems: [KeychainItem] = []
        let classes = [kSecClassGenericPassword, kSecClassInternetPassword]
        
        for secClass in classes {
            let query: [String: Any] = [
                kSecClass as String: secClass,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
                kSecReturnData as String: true,
                kSecAttrAccessGroup as String: targetGroup
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            if status == errSecSuccess, let results = result as? [[String: Any]] {
                for res in results {
                    newItems.append(parseItem(res, secClass: secClass))
                }
            }
        }
        
        // 清理孤立标签 (属于当前加载的 Access Group 但已无对应条目)
        let existingKeys = Set(newItems.map { $0.uniqueKey })
        let derivedAccessGroups = Set(newItems.map { $0.accessGroup })
        let accessGroups: Set<String> = derivedAccessGroups.isEmpty ? Set([targetGroup]) : derivedAccessGroups
        TagManager.shared.cleanupOrphanedTags(existingItemKeys: existingKeys, inAccessGroups: accessGroups)
        
        DispatchQueue.main.async {
            self.items = newItems
            self.statusMessage = "找到 \(newItems.count) 条数据"
            // 清除可能失效的选择 (刷新后 UUID 已变化)
            self.selectedItems.removeAll()
            self.resetTagFilterIfNeeded(for: newItems)
        }
    }
    
    // 解析单条数据
    func parseItem(_ dict: [String: Any], secClass: CFString) -> KeychainItem {
        // 1. 提取所有属性用于展示
        var attributes: [String: String] = [:]
        for (key, value) in dict {
            attributes[key] = "\(value)"
        }
        
        // 2. 识别关键字段
        let account = dict[kSecAttrAccount as String] as? String ?? ""
        let group = dict[kSecAttrAccessGroup as String] as? String ?? ""
        let data = dict[kSecValueData as String] as? Data ?? Data()
        
        // 3. 处理标题：网络密码用 Server，通用密码用 Service
        var title = "未知"
        let classDisplay: String
        
        if secClass == kSecClassInternetPassword {
            classDisplay = "网络"
            if let server = dict[kSecAttrServer as String] as? String {
                title = server
            } else {
                title = "未知 Server"
            }
        } else {
            classDisplay = "通用"
            if let service = dict[kSecAttrService as String] as? String {
                title = service
            } else {
                title = "未知 Service"
            }
        }
        
        // 4. 判断数据是否为纯文本
        // 尝试转UTF8，如果转不出来，或者包含大量不可见字符，就视为二进制
        let isString = (String(data: data, encoding: .utf8) != nil)
        
        return KeychainItem(
            itemClass: secClass,
            itemClassDisplay: classDisplay,
            title: title,
            account: account,
            accessGroup: group,
            rawData: data,
            isStringData: isString,
            rawAttributes: attributes
        )
    }
    
    func deleteItems(at offsets: IndexSet) {
        // offsets 对应 filteredItems 的索引，而非 items
        let itemsToDelete = offsets.map { filteredItems[$0] }
        for item in itemsToDelete {
            var query: [String: Any] = [
                kSecClass as String: item.itemClass,
                kSecAttrAccount as String: item.account,
                kSecAttrAccessGroup as String: item.accessGroup
            ]
            
            if item.itemClass == kSecClassInternetPassword {
                query[kSecAttrServer as String] = item.title
            } else {
                query[kSecAttrService as String] = item.title
            }
            
            SecItemDelete(query as CFDictionary)
            TagManager.shared.setTag("", for: item.uniqueKey)
        }
        let idsToDelete = Set(itemsToDelete.map { $0.id })
        items.removeAll { idsToDelete.contains($0.id) }
        resetTagFilterIfNeeded(for: items)
    }
    
    // MARK: - 批量操作方法
    func toggleSelection(for id: UUID) {
        if selectedItems.contains(id) {
            selectedItems.remove(id)
        } else {
            selectedItems.insert(id)
        }
    }
    
    func applyBatchTag() {
        let selectedKeyItems = items.filter { selectedItems.contains($0.id) }
        for item in selectedKeyItems {
            TagManager.shared.setTag(batchTagValue, for: item.uniqueKey)
        }
        fetchItems()
        batchTagValue = ""
    }
    
    func batchUntag() {
        let selectedKeyItems = items.filter { selectedItems.contains($0.id) }
        for item in selectedKeyItems {
            TagManager.shared.setTag("", for: item.uniqueKey)
        }
        fetchItems()
    }
    
    func batchDelete() {
        let selectedKeyItems = items.filter { selectedItems.contains($0.id) }
        for item in selectedKeyItems {
            var query: [String: Any] = [
                kSecClass as String: item.itemClass,
                kSecAttrAccount as String: item.account,
                kSecAttrAccessGroup as String: item.accessGroup
            ]
            
            if item.itemClass == kSecClassInternetPassword {
                query[kSecAttrServer as String] = item.title
            } else {
                query[kSecAttrService as String] = item.title
            }
            
            SecItemDelete(query as CFDictionary)
            TagManager.shared.setTag("", for: item.uniqueKey)
        }
        items.removeAll { selectedItems.contains($0.id) }
        selectedItems.removeAll()
        isSelectionMode = false
        resetTagFilterIfNeeded(for: items)
    }
    
    // MARK: - 描述文件解析
    func loadProvisioningProfile() {
        // 将描述文件解析和钥匙串枚举移到后台队列，避免阻塞主线程渲染
        DispatchQueue.global(qos: .userInitiated).async {
            if let profile = ProvisioningProfileParser.parse() {
                // 使用 allAccessGroups 汇总所有可用的 Keychain Access Group
                // 包含: 通配符、keychain-access-groups、application-identifier、application-groups
                let groups = profile.allAccessGroups
                
                // 计算将要使用的 targetGroup
                var selectedGroup = self.targetGroup
                if selectedGroup.isEmpty, let first = groups.first {
                    selectedGroup = first
                }
                
                // 在主线程更新 UI 状态
                DispatchQueue.main.async {
                    self.detectedGroups = groups
                    if self.targetGroup.isEmpty, !selectedGroup.isEmpty {
                        self.targetGroup = selectedGroup
                    }
                }
                
                // 在后台线程执行耗时的钥匙串查询
                if !selectedGroup.isEmpty {
                    self.fetchItems()
                }
                
                // 根据查询结果更新状态提示
                if self.items.isEmpty && !groups.isEmpty {
                    DispatchQueue.main.async {
                        self.statusMessage = "已从描述文件检测到 \(groups.count) 个 Access Group，点击选择后刷新"
                    }
                }
            } else {
                DispatchQueue.main.async {
                    self.showManualInput = true
                    self.statusMessage = "未检测到描述文件，请手动输入 Access Group"
                }
            }
        }
    }
}

// MARK: - 详情与修改页 (支持 Hex)
struct ItemDetailView: View {
    let item: KeychainItem
    var onUpdate: () -> Void
    
    @State private var contentString: String = ""
    @State private var isEditingHex: Bool = false
    @State private var appTag: String = ""
    @StateObject private var tagManager = TagManager.shared
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        Form {
            // 基础信息区
            Section(header: Text("核心识别信息 (不可改)")) {
                LabeledContent("类型", value: item.itemClassDisplay)
                LabeledContent("标识 (Svc/Svr)", value: item.title)
                LabeledContent("账号 (Account)", value: item.account)
                LabeledContent("组 (Group)", value: item.accessGroup)
            }
            
            // App Tag 编辑区
            Section(header: Text("App 标签")) {
                HStack {
                    TextField("输入 App 名称", text: $appTag)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    Button("保存") {
                        saveTag()
                    }
                    .buttonStyle(.borderedProminent)
                }
                
                if !tagManager.allTags.isEmpty {
                    Text("已有标签：")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(Array(tagManager.allTags).sorted(), id: \.self) { tag in
                                Button(action: {
                                    appTag = tag
                                    saveTag()
                                }) {
                                    Text(tag)
                                        .font(.caption)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(Color.orange.opacity(0.2))
                                        .foregroundColor(.orange)
                                        .cornerRadius(10)
                                }
                            }
                        }
                    }
                }
            }
            
            // 数据编辑区
            Section(header: Text("加密数据 (Data)")) {
                Picker("编辑模式", selection: $isEditingHex) {
                    Text("文本 (UTF8)").tag(false)
                    Text("十六进制 (Hex)").tag(true)
                }
                .pickerStyle(.segmented)
                .padding(.bottom, 5)
                
                TextEditor(text: $contentString)
                    .frame(height: 120)
                    .font(.system(.body, design: .monospaced)) // 等宽字体方便看 Hex
                    .onChange(of: isEditingHex) { _, newValue in
                        // 切换模式时转换当前显示的内容
                        if newValue {
                            // 文本 -> Hex
                            if let data = contentString.data(using: .utf8) {
                                contentString = data.hexString
                            }
                        } else {
                            // Hex -> 文本
                            if let data = contentString.hexData, let str = String(data: data, encoding: .utf8) {
                                contentString = str
                            } else {
                                contentString = "无法转为 UTF8，请切回 Hex 模式"
                            }
                        }
                    }
                
                Button("保存修改") {
                    saveChanges()
                }
                .frame(maxWidth: .infinity)
                .foregroundColor(.red)
            }
            
            // 完整属性展示区
            Section(header: Text("所有元数据 (All Attributes)")) {
                ForEach(item.rawAttributes.sorted(by: <), id: \.key) { key, value in
                    VStack(alignment: .leading) {
                        Text(key)
                            .font(.caption)
                            .foregroundColor(.blue)
                        Text(value)
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .navigationTitle("Item 详情")
        .onAppear {
            // 初始化显示
            if item.isStringData {
                contentString = String(data: item.rawData, encoding: .utf8) ?? ""
                isEditingHex = false
            } else {
                contentString = item.rawData.hexString
                isEditingHex = true
            }
            appTag = item.appTag
        }
    }
    
    func saveTag() {
        TagManager.shared.setTag(appTag, for: item.uniqueKey)
        onUpdate()
    }
    
    func saveChanges() {
        var finalData: Data?
        
        if isEditingHex {
            finalData = contentString.hexData
        } else {
            finalData = contentString.data(using: .utf8)
        }
        
        guard let dataToSave = finalData else { return }
        
        // 构造查询主键
        var query: [String: Any] = [
            kSecClass as String: item.itemClass,
            kSecAttrAccount as String: item.account,
            kSecAttrAccessGroup as String: item.accessGroup
        ]
        
        if item.itemClass == kSecClassInternetPassword {
            query[kSecAttrServer as String] = item.title
        } else {
            query[kSecAttrService as String] = item.title
        }
        
        let attributes: [String: Any] = [
            kSecValueData as String: dataToSave
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess {
            onUpdate()
            presentationMode.wrappedValue.dismiss()
        } else {
            print("保存失败: \(status)")
        }
    }
}

// MARK: - 新增页面 (简单版)
struct AddItemView: View {
    let targetGroup: String
    var onSave: () -> Void
    @Environment(\.presentationMode) var pm
    
    @State private var type = 0 // 0: Genp, 1: Inet
    @State private var service = ""
    @State private var account = ""
    @State private var dataStr = ""
    @State private var appTag = ""
    @StateObject private var tagManager = TagManager.shared
    
    var body: some View {
        Form {
            Section {
                Picker("类型", selection: $type) {
                    Text("通用 (Generic)").tag(0)
                    Text("网络 (Internet)").tag(1)
                }
            }
            
            Section(header: Text(type == 0 ? "Service (服务名)" : "Server (服务器地址)")) {
                TextField(type == 0 ? "如 com.tencent.xin" : "如 google.com", text: $service)
            }
            
            Section(header: Text("Account (账号)")) {
                TextField("用户名/Email", text: $account)
            }
            
            Section(header: Text("Data (密码/数据)")) {
                TextField("内容", text: $dataStr)
            }
            
            Section(header: Text("App 标签 (可选)")) {
                TextField("输入 App 名称", text: $appTag)
                
                if !tagManager.allTags.isEmpty {
                    Text("已有标签：")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(Array(tagManager.allTags).sorted(), id: \.self) { tag in
                                Button(action: { appTag = tag }) {
                                    Text(tag)
                                        .font(.caption)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(Color.orange.opacity(0.2))
                                        .foregroundColor(.orange)
                                        .cornerRadius(10)
                                }
                            }
                        }
                    }
                }
            }
            
            Button("保存") {
                guard let data = dataStr.data(using: .utf8) else { return }
                var query: [String: Any] = [
                    kSecClass as String: (type == 0 ? kSecClassGenericPassword : kSecClassInternetPassword),
                    kSecAttrAccount as String: account,
                    kSecValueData as String: data,
                    kSecAttrAccessGroup as String: targetGroup
                ]
                
                if type == 0 {
                    query[kSecAttrService as String] = service
                } else {
                    query[kSecAttrServer as String] = service
                }
                
                SecItemAdd(query as CFDictionary, nil)
                
                // 保存 Tag
                if !appTag.isEmpty {
                    let classDisplay = type == 0 ? "通用" : "网络"
                    let uniqueKey = KeychainItem.makeUniqueKey(
                        classDisplay: classDisplay,
                        title: service,
                        account: account,
                        accessGroup: targetGroup
                    )
                    TagManager.shared.setTag(appTag, for: uniqueKey)
                }
                
                onSave()
                pm.wrappedValue.dismiss()
            }
        }
        .navigationTitle("新增条目")
    }
}

// MARK: - 批量标签弹窗
struct BatchTagSheet: View {
    @ObservedObject var tagManager: TagManager
    @Binding var batchTagValue: String
    var onSave: () -> Void
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("批量设置标签")) {
                    TextField("输入标签名称", text: $batchTagValue)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                }
                
                if !tagManager.allTags.isEmpty {
                    Section(header: Text("选择已有标签")) {
                        ForEach(Array(tagManager.allTags).sorted(), id: \.self) { tag in
                            Button(action: {
                                batchTagValue = tag
                            }) {
                                HStack {
                                    Text(tag)
                                        .foregroundColor(.primary)
                                    Spacer()
                                    if batchTagValue == tag {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(.blue)
                                    }
                                }
                            }
                        }
                    }
                }
                
                Section {
                    Button("应用标签") {
                        onSave()
                    }
                    .disabled(batchTagValue.isEmpty)
                    .frame(maxWidth: .infinity)
                }
            }
            .navigationTitle("批量标签")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
        }
    }
}
