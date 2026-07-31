import SwiftUI
import Security

struct AddItemView: View {

    @ObservedObject var viewModel: KeychainViewModel
    @ObservedObject private var tagManager = TagManager.shared
    @Environment(\.dismiss) private var dismiss

    @State private var itemClass: KeychainItemClass = .genericPassword
    @State private var title = ""
    @State private var account = ""
    @State private var label = ""
    @State private var content = ""
    @State private var isHexMode = false
    @State private var accessible = kSecAttrAccessibleWhenUnlocked as String
    @State private var accessGroup = ""
    @State private var tagValue = ""
    @State private var itemDescription = ""
    @State private var comment = ""
    @State private var isInvisible = false
    @State private var isNegative = false

    /// 通配符 Group 只是权限声明，不能作为写入目标
    private var writableGroups: [String] {
        viewModel.detectedGroups.filter { !KeychainStore.isWildcardGroup($0) }
    }

    private var parsedData: Data? {
        isHexMode ? content.hexData : content.data(using: .utf8)
    }

    private var canSave: Bool {
        !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && parsedData != nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("类别") {
                    Picker("类别", selection: $itemClass) {
                        Text("通用密码").tag(KeychainItemClass.genericPassword)
                        Text("网络密码").tag(KeychainItemClass.internetPassword)
                    }
                    .pickerStyle(.segmented)
                }

                Section(itemClass == .internetPassword ? "Server（服务器）" : "Service（服务名）") {
                    TextField(itemClass == .internetPassword ? "如 example.com" : "如 com.example.app",
                              text: $title)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("Account（账号，可留空）") {
                    TextField("用户名 / Email", text: $account)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                dataSection

                Section {
                    Picker("可访问性", selection: $accessible) {
                        ForEach(AccessibleOption.all) { option in
                            Text(option.title).tag(option.value)
                        }
                    }
                } header: {
                    Text("保护级别")
                } footer: {
                    Text("决定条目在设备锁定时是否可读，写入后不可修改。")
                }

                accessGroupSection

                Section {
                    TextField("标签 (labl)", text: $label)
                        .textInputAutocapitalization(.never)
                    TextField("描述 (desc)", text: $itemDescription)
                        .textInputAutocapitalization(.never)
                    TextField("备注 (icmt)", text: $comment)
                        .textInputAutocapitalization(.never)
                    Toggle("隐藏 (invi)", isOn: $isInvisible)
                    Toggle("占位条目 (nega)", isOn: $isNegative)
                } header: {
                    Text("元数据（可选）")
                } footer: {
                    Text("与详情页「可修改的元数据」一致，写入后仍可修改。")
                }

                tagSection
            }
            .navigationTitle("新增条目")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("保存") { save() }
                        .fontWeight(.semibold)
                        .disabled(!canSave)
                }
            }
            .onAppear(perform: prepareDefaultGroup)
        }
    }

    // MARK: - 分区

    @ViewBuilder
    private var dataSection: some View {
        Section {
            Picker("输入模式", selection: $isHexMode) {
                Text("文本 (UTF-8)").tag(false)
                Text("十六进制").tag(true)
            }
            .pickerStyle(.segmented)

            TextEditor(text: $content)
                .frame(height: 90)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                // 同详情页：Form 里的 TextEditor 底色会盖住分隔线
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.secondary.opacity(0.08))
                )
        } header: {
            Text("Data（内容）")
        } footer: {
            if let data = parsedData {
                Text("\(data.count) 字节")
            } else {
                Text("十六进制内容不合法：长度需为偶数且只含 0-9 / a-f。")
                    .foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder
    private var accessGroupSection: some View {
        Section {
            TextField("留空则写入应用默认组", text: $accessGroup)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            ForEach(writableGroups, id: \.self) { group in
                Button {
                    accessGroup = group
                } label: {
                    HStack {
                        Text(group)
                            .font(.callout)
                            .foregroundStyle(.primary)
                        Spacer()
                        if accessGroup == group {
                            Image(systemName: "checkmark")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
            }
        } header: {
            Text("Access Group")
        } footer: {
            if KeychainStore.isWildcardGroup(accessGroup) {
                Text("通配符 Group 只是权限声明，不能作为写入目标；保存时会忽略该值并写入应用默认组。")
                    .foregroundStyle(.orange)
            } else {
                Text("必须是本应用 entitlements 中已声明的组，否则会返回 -34018。")
            }
        }
    }

    @ViewBuilder
    private var tagSection: some View {
        Section("App 标签（可选）") {
            TextField("输入 App 名称", text: $tagValue)
                .textInputAutocapitalization(.never)

            if !tagManager.allTags.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(tagManager.allTags, id: \.self) { tag in
                            Button {
                                tagValue = tag
                            } label: {
                                Text(tag)
                                    .font(.caption)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.orange.opacity(0.2))
                                    .foregroundStyle(.orange)
                                    .clipShape(Capsule())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.vertical, 2)
                }
                // 同详情页：ScrollView 会画不透明底色盖住分隔线，
                // 且只补上方那条，避免在 section 末尾多画一条
                .scrollContentBackground(.hidden)
                .listRowSeparator(.visible, edges: .top)
            }
        }
    }

    // MARK: - 动作

    /// 预填一个可写入的组：当前作用域指定的组若不是通配符就沿用，否则留空用应用默认组
    private func prepareDefaultGroup() {
        guard accessGroup.isEmpty, let scope = viewModel.currentScope else { return }
        if case .group(let group) = scope, !KeychainStore.isWildcardGroup(group) {
            accessGroup = group
        }
    }

    private func save() {
        guard let data = parsedData else { return }

        var newItem = KeychainStore.NewItem()
        newItem.itemClass = itemClass
        newItem.title = title.trimmingCharacters(in: .whitespacesAndNewlines)
        newItem.account = account
        newItem.data = data
        newItem.accessGroup = accessGroup
        newItem.accessible = accessible
        newItem.label = label
        newItem.itemDescription = itemDescription
        newItem.comment = comment
        newItem.isInvisible = isInvisible
        newItem.isNegative = isNegative

        if viewModel.add(newItem, tag: tagValue) {
            dismiss()
        }
    }
}
