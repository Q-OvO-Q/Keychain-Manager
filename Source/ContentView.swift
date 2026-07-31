import SwiftUI
import Security

struct KeychainItemRoute: Hashable {
    let id: String
}

// MARK: - 主视图

struct ContentView: View {

    @StateObject private var viewModel = KeychainViewModel()
    @ObservedObject private var tagManager = TagManager.shared

    @State private var showScopeSettings = false
    @State private var showAddItem = false
    @State private var showBatchTagSheet = false
    @State private var confirmBatchDelete = false
    @State private var showFailureDetail = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                scopeBar
                tagFilterBar
                itemList
                statusBar
            }
            .navigationTitle("Keychain Manager")
            .toolbar { toolbarContent }
            .searchable(text: $viewModel.searchText, prompt: "搜索标题 / 账号 / 组 / 内容")
            .navigationDestination(for: KeychainItemRoute.self) { route in
                ItemDetailView(viewModel: viewModel, itemID: route.id)
            }
            .safeAreaInset(edge: .bottom) {
                if viewModel.isSelectionMode {
                    selectionActionBar
                }
            }
        }
        // 挂在 NavigationStack 上而不是内层内容上：详情页里触发的错误提示同样需要弹出
        .sheet(isPresented: $showScopeSettings) {
            ScopeSettingsView(viewModel: viewModel)
        }
        .sheet(isPresented: $showAddItem) {
            AddItemView(viewModel: viewModel)
        }
        .sheet(isPresented: $showBatchTagSheet) {
            BatchTagSheet(count: viewModel.selectedIDs.count) { tag in
                viewModel.applyTagToSelection(tag)
            }
        }
        .sheet(isPresented: $showFailureDetail) {
            FailureDetailView(failures: viewModel.enumerationFailures)
        }
        .alert("操作未完成", isPresented: alertPresented) {
            Button("好", role: .cancel) {}
        } message: {
            Text(viewModel.alertMessage ?? "")
        }
        .confirmationDialog(
            "删除选中的 \(viewModel.selectedIDs.count) 条条目？",
            isPresented: $confirmBatchDelete,
            titleVisibility: .visible
        ) {
            Button("删除", role: .destructive) {
                viewModel.delete(viewModel.selectedItems)
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("此操作不可撤销。")
        }
        .onAppear { viewModel.bootstrap() }
    }

    private var alertPresented: Binding<Bool> {
        Binding(
            get: { viewModel.alertMessage != nil },
            set: { if !$0 { viewModel.alertMessage = nil } }
        )
    }

    // MARK: - 工具栏

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            Button(viewModel.isSelectionMode ? "完成" : "选择") {
                if viewModel.isSelectionMode {
                    viewModel.exitSelectionMode()
                } else {
                    viewModel.isSelectionMode = true
                }
            }
            .disabled(!viewModel.isSelectionMode && viewModel.items.isEmpty)
        }

        ToolbarItem(placement: .navigationBarTrailing) {
            Button { showAddItem = true } label: {
                Image(systemName: "plus")
            }
            .disabled(viewModel.isSelectionMode)
        }

        ToolbarItem(placement: .navigationBarTrailing) {
            Button { viewModel.refresh() } label: {
                if viewModel.isLoading {
                    ProgressView()
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .disabled(viewModel.isLoading)
        }
    }

    // MARK: - 作用域栏

    private var scopeBar: some View {
        Button {
            showScopeSettings = true
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "key.fill")
                    .font(.caption)
                VStack(alignment: .leading, spacing: 1) {
                    Text(viewModel.scopeDescription)
                        .font(.caption)
                        .fontWeight(.medium)
                        .lineLimit(1)
                    Text(enabledClassesDescription)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "slider.horizontal.3")
                    .font(.caption)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(Color.secondary.opacity(0.08))
    }

    private var enabledClassesDescription: String {
        let names = KeychainItemClass.allCases
            .filter { viewModel.enabledClasses.contains($0) }
            .map(\.displayName)
        return names.isEmpty ? "未选择类别" : "类别：" + names.joined(separator: " / ")
    }

    // MARK: - 标签筛选栏

    @ViewBuilder
    private var tagFilterBar: some View {
        let counts = viewModel.tagCounts
        let visibleTags = tagManager.allTags.filter { counts[$0] != nil }
        let untaggedCount = counts[untaggedFilterKey] ?? 0

        if !viewModel.items.isEmpty && (!visibleTags.isEmpty || untaggedCount > 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    filterChip(label: "全部",
                               count: viewModel.items.count,
                               isSelected: viewModel.selectedTagFilter.isEmpty) {
                        viewModel.selectedTagFilter = ""
                    }

                    ForEach(visibleTags, id: \.self) { tag in
                        filterChip(label: tag,
                                   count: counts[tag] ?? 0,
                                   isSelected: viewModel.selectedTagFilter == tag) {
                            viewModel.selectedTagFilter = tag
                        }
                    }

                    if untaggedCount > 0 {
                        filterChip(label: "未标记",
                                   count: untaggedCount,
                                   isSelected: viewModel.selectedTagFilter == untaggedFilterKey) {
                            viewModel.selectedTagFilter = untaggedFilterKey
                        }
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
            }
        }
    }

    private func filterChip(label: String,
                           count: Int,
                           isSelected: Bool,
                           action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text("\(label) \(count)")
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(isSelected ? Color.accentColor : Color.secondary.opacity(0.15))
                .foregroundStyle(isSelected ? Color.white : Color.primary)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    // MARK: - 列表

    @ViewBuilder
    private var itemList: some View {
        let visible = viewModel.filteredItems

        if visible.isEmpty {
            emptyState
        } else {
            List {
                ForEach(visible) { item in
                    if viewModel.isSelectionMode {
                        Button {
                            viewModel.toggleSelection(item.id)
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: viewModel.selectedIDs.contains(item.id)
                                      ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(viewModel.selectedIDs.contains(item.id)
                                                     ? Color.accentColor : Color.secondary)
                                KeychainItemRow(item: item)
                            }
                        }
                        .buttonStyle(.plain)
                    } else {
                        NavigationLink(value: KeychainItemRoute(id: item.id)) {
                            KeychainItemRow(item: item)
                        }
                    }
                }
                .onDelete(perform: deleteHandler)
            }
            .listStyle(.plain)
        }
    }

    /// 选择模式下禁用侧滑删除，避免与勾选手势冲突
    private var deleteHandler: ((IndexSet) -> Void)? {
        guard !viewModel.isSelectionMode else { return nil }
        return { offsets in viewModel.deleteFiltered(at: offsets) }
    }

    @ViewBuilder
    private var emptyState: some View {
        if viewModel.isLoading {
            VStack(spacing: 12) {
                ProgressView()
                Text(viewModel.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if viewModel.items.isEmpty {
            ContentUnavailableView {
                Label("没有可显示的条目", systemImage: "key.slash")
            } description: {
                Text(viewModel.statusMessage)
            } actions: {
                Button("调整作用域") { showScopeSettings = true }
                Button("重新查询") { viewModel.refresh() }
            }
        } else {
            ContentUnavailableView.search
        }
    }

    // MARK: - 批量操作栏

    private var selectionActionBar: some View {
        VStack(spacing: 8) {
            HStack {
                Text("已选择 \(viewModel.selectedIDs.count) 项")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("全选") { viewModel.selectAllVisible() }
                    .font(.caption)
                    .disabled(viewModel.filteredItems.isEmpty)
                Button("全不选") { viewModel.clearSelection() }
                    .font(.caption)
                    .disabled(viewModel.selectedIDs.isEmpty)
            }

            HStack(spacing: 10) {
                Button("设置标签") { showBatchTagSheet = true }
                    .buttonStyle(.borderedProminent)
                Button("清除标签") { viewModel.clearTagForSelection() }
                    .buttonStyle(.bordered)
                Button("删除") { confirmBatchDelete = true }
                    .buttonStyle(.bordered)
                    .tint(.red)
            }
            .disabled(viewModel.selectedIDs.isEmpty)
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
        .background(.bar)
    }

    // MARK: - 状态栏

    private var statusBar: some View {
        Button {
            guard !viewModel.enumerationFailures.isEmpty else { return }
            showFailureDetail = true
        } label: {
            HStack(spacing: 6) {
                if viewModel.isLoading {
                    ProgressView().scaleEffect(0.7)
                }
                Text(viewModel.statusMessage)
                    .font(.caption2)
                    .foregroundStyle(viewModel.enumerationFailures.isEmpty ? Color.secondary : Color.orange)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Spacer()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(viewModel.enumerationFailures.isEmpty)
        .padding(.horizontal)
        .padding(.vertical, 6)
        .background(Color.secondary.opacity(0.08))
    }
}

// MARK: - 列表行

struct KeychainItemRow: View {
    let item: KeychainItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                Text(item.itemClass.displayName)
                    .font(.system(size: 10, weight: .bold))
                    .padding(.horizontal, 4)
                    .padding(.vertical, 2)
                    .background(classColor.opacity(0.2))
                    .foregroundStyle(classColor)
                    .cornerRadius(4)

                if !item.appTag.isEmpty {
                    Text(item.appTag)
                        .font(.system(size: 10, weight: .bold))
                        .padding(.horizontal, 4)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.2))
                        .foregroundStyle(.orange)
                        .cornerRadius(4)
                }

                if item.isSynchronizable {
                    Image(systemName: "icloud")
                        .font(.system(size: 9))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text(dataPreview)
                    .font(.caption2)
                    .foregroundStyle(item.isDataReadable ? Color.secondary : Color.red)
                    .lineLimit(1)
            }

            Text(item.displayTitle)
                .font(.subheadline)
                .fontWeight(.medium)
                .lineLimit(1)

            HStack {
                Text(item.account.isEmpty ? "无账号" : item.account)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
                Text(item.accessGroup)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }

    private var classColor: Color {
        switch item.itemClass {
        case .genericPassword:  return .blue
        case .internetPassword: return .green
        case .key:              return .purple
        case .certificate:      return .brown
        }
    }

    /// 数据不可读时直接在行内标出原因，而不是显示成空内容
    private var dataPreview: String {
        guard let status = item.dataStatus else { return "未读取" }
        guard status == errSecSuccess, let data = item.data else {
            return status == errSecInteractionNotAllowed ? "受保护" : "读取失败"
        }
        if data.isEmpty { return "空" }
        if let text = data.utf8Text, text.rangeOfCharacter(from: .controlCharacters) == nil {
            return text.count > 16 ? String(text.prefix(16)) + "…" : text
        }
        return "HEX \(data.count)B"
    }
}

// MARK: - 作用域设置

struct ScopeSettingsView: View {
    @ObservedObject var viewModel: KeychainViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var groupFilter = ""

    /// 签名 entitlements 里动辄上百个组（LiveContainer 有 128 个 shared.N），需要筛选才能用
    private var matchingGroups: [String] {
        let keyword = groupFilter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !keyword.isEmpty else { return viewModel.detectedGroups }
        return viewModel.detectedGroups.filter { $0.lowercased().contains(keyword) }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("查询全部可访问条目", isOn: $viewModel.useAllGroups)
                } header: {
                    Text("查询范围")
                } footer: {
                    Text("开启后遍历下方全部 \(viewModel.detectedGroups.count) 个 Access Group。逐组查询可以避免某个组出问题时整个类别一起查不到。")
                }

                if !viewModel.useAllGroups {
                    Section("指定 Access Group") {
                        TextField("例如 TEAMID.com.example.app", text: $viewModel.targetGroup)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }

                    if !viewModel.detectedGroups.isEmpty {
                        Section {
                            if viewModel.detectedGroups.count > 8 {
                                TextField("筛选组名", text: $groupFilter)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                            }

                            ForEach(matchingGroups, id: \.self) { group in
                                Button {
                                    viewModel.targetGroup = group
                                } label: {
                                    HStack {
                                        Text(group)
                                            .font(.callout)
                                            .foregroundStyle(.primary)
                                        Spacer()
                                        if viewModel.targetGroup == group {
                                            Image(systemName: "checkmark")
                                                .foregroundStyle(Color.accentColor)
                                        }
                                    }
                                }
                            }
                        } header: {
                            Text("已识别的组（\(matchingGroups.count)/\(viewModel.detectedGroups.count)）")
                        }
                    }
                }

                Section {
                    Toggle("包含受保护条目", isOn: $viewModel.includeProtectedItems)
                } footer: {
                    Text("关闭时跳过需要验证的条目，不会弹出验证框。开启后这类条目才会出现在列表里，但系统可能弹出 Face ID；某个组验证失败时会自动退回跳过重查，因此不会比关闭时拿到更少的条目。")
                }

                Section {
                    ForEach(KeychainItemClass.allCases) { itemClass in
                        Toggle(itemClass.displayName, isOn: classBinding(itemClass))
                    }
                } header: {
                    Text("条目类别")
                } footer: {
                    Text("密钥与证书条目数量可能较多，按需开启。")
                }

                if let summary = viewModel.profileSummary {
                    Section("描述文件") {
                        Text(summary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    Button("清空当前显示") { viewModel.clearDisplay() }
                }
            }
            .navigationTitle("查询设置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("查询") {
                        dismiss()
                        viewModel.refresh()
                    }
                    .fontWeight(.semibold)
                }
            }
        }
    }

    private func classBinding(_ itemClass: KeychainItemClass) -> Binding<Bool> {
        Binding(
            get: { viewModel.enabledClasses.contains(itemClass) },
            set: { isOn in
                if isOn {
                    viewModel.enabledClasses.insert(itemClass)
                } else {
                    viewModel.enabledClasses.remove(itemClass)
                }
            }
        )
    }
}

// MARK: - 查询失败详情

/// 逐组枚举下失败项可能有几十条，状态栏放不下。
/// 弹验证的到底是哪个组、哪个类别，靠这里定位。
struct FailureDetailView: View {
    let failures: [String]

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(Array(failures.enumerated()), id: \.offset) { _, failure in
                        Text(failure)
                            .font(.caption)
                            .textSelection(.enabled)
                    }
                } footer: {
                    Text("每一行是一个「类别 + Access Group」组合。若某组报认证相关错误，说明受保护条目就在该组里。")
                }
            }
            .navigationTitle("查询失败 \(failures.count) 项")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}

// MARK: - 批量标签弹窗

struct BatchTagSheet: View {
    let count: Int
    var onApply: (String) -> Void

    @ObservedObject private var tagManager = TagManager.shared
    @Environment(\.dismiss) private var dismiss
    @State private var tagValue = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("输入标签名称", text: $tagValue)
                        .textInputAutocapitalization(.never)
                } header: {
                    Text("为选中的 \(count) 条设置标签")
                }

                if !tagManager.allTags.isEmpty {
                    Section("选择已有标签") {
                        ForEach(tagManager.allTags, id: \.self) { tag in
                            Button {
                                tagValue = tag
                            } label: {
                                HStack {
                                    Text(tag).foregroundStyle(.primary)
                                    Spacer()
                                    if tagValue == tag {
                                        Image(systemName: "checkmark")
                                            .foregroundStyle(Color.accentColor)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("批量标签")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("应用") {
                        onApply(tagValue)
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(tagValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
