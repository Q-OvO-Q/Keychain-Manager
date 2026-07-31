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
    @State private var creator = ""
    @State private var typeCode = ""
    @State private var isInvisible = false
    @State private var isNegative = false
    @State private var synchronizable = false
    @State private var generic = ""
    @State private var securityDomain = ""
    @State private var networkProtocol = ""
    @State private var authenticationType = ""
    @State private var port = ""
    @State private var path = ""
    @State private var keyClass = ""
    @State private var keyType = ""
    @State private var applicationTag = ""

    /// 通配符 Group 只是权限声明，不能作为写入目标
    private var writableGroups: [String] {
        viewModel.detectedGroups.filter { !KeychainStore.isWildcardGroup($0) }
    }

    private var parsedData: Data? {
        isHexMode ? content.hexData : content.data(using: .utf8)
    }

    private var canSave: Bool {
        guard let data = parsedData else { return false }
        switch itemClass {
        case .genericPassword, .internetPassword:
            return !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .key, .certificate:
            // 这两类没有标题，条目内容完全由数据决定，空数据无从写起
            return !data.isEmpty
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("类别") {
                    Picker("类别", selection: $itemClass) {
                        ForEach(KeychainItemClass.allCases) { itemClass in
                            Text(itemClass.displayName).tag(itemClass)
                        }
                    }
                    .pickerStyle(.segmented)
                }

                identitySection

                dataSection

                Section {
                    Picker("可访问性 (pdmn)", selection: $accessible) {
                        ForEach(AccessibleOption.all) { option in
                            Text(option.title).tag(option.value)
                        }
                    }
                    Toggle("iCloud 同步 (sync)", isOn: $synchronizable)
                } header: {
                    Text("保护级别")
                } footer: {
                    Text("可访问性决定条目在设备锁定时是否可读。同步属性是主键的一部分，两者写入后都不可再改。")
                }

                accessGroupSection

                Section {
                    TextField("标签 (labl)", text: $label)
                        .textInputAutocapitalization(.never)

                    // 其余描述性字段只有密码类的表里才有对应的列
                    if itemClass.supportsDataEditing {
                        TextField("描述 (desc)", text: $itemDescription)
                            .textInputAutocapitalization(.never)
                        TextField("备注 (icmt)", text: $comment)
                            .textInputAutocapitalization(.never)
                        TextField("创建者 (crtr)，如 aapl 或十进制", text: $creator)
                            .font(.system(.body, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        TextField("类型码 (type)，如 aapl 或十进制", text: $typeCode)
                            .font(.system(.body, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Toggle("隐藏 (invi)", isOn: $isInvisible)
                        Toggle("占位条目 (nega)", isOn: $isNegative)
                    }
                } header: {
                    Text("元数据（可选）")
                } footer: {
                    if itemClass.supportsDataEditing {
                        Text("与详情页「可修改的元数据」一致，写入后仍可修改。crtr / type 解析不出四字符码或十进制时会被忽略。")
                    } else {
                        Text("\(itemClass.displayName)条目只有 labl 一项描述性字段可设，其余属性由系统从数据本身派生。")
                    }
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

    /// 各类别构成主键的那些字段。它们只能在新增时定：
    /// 一旦写入，改动等于把条目挪到另一个主键上。
    @ViewBuilder
    private var identitySection: some View {
        switch itemClass {
        case .genericPassword:
            Section("主键字段") {
                labeledField("Service (svce)", "如 com.example.app", $title)
                labeledField("Account (acct)", "用户名 / Email，可留空", $account)
                labeledField("Generic (gena)", "通用字段，可留空", $generic)
            }

        case .internetPassword:
            Section {
                labeledField("Server (srvr)", "如 example.com", $title)
                labeledField("Account (acct)", "用户名 / Email，可留空", $account)
                labeledField("Security Domain (sdmn)", "可留空", $securityDomain)
                Picker("Protocol (ptcl)", selection: $networkProtocol) {
                    ForEach(KeychainStore.AttributeOption.protocols) { option in
                        Text(option.title).tag(option.value)
                    }
                }
                Picker("Auth Type (atyp)", selection: $authenticationType) {
                    ForEach(KeychainStore.AttributeOption.authenticationTypes) { option in
                        Text(option.title).tag(option.value)
                    }
                }
                labeledField("Port (port)", "如 443，可留空", $port)
                    .keyboardType(.numberPad)
                labeledField("Path (path)", "如 /login，可留空", $path)
            } header: {
                Text("主键字段")
            } footer: {
                Text("网络密码的主键包含这 7 项，写入后都不可再改。")
            }

        case .key:
            Section {
                Picker("Key Class (kcls)", selection: $keyClass) {
                    ForEach(KeychainStore.AttributeOption.keyClasses) { option in
                        Text(option.title).tag(option.value)
                    }
                }
                Picker("Key Type (type)", selection: $keyType) {
                    ForEach(KeychainStore.AttributeOption.keyTypes) { option in
                        Text(option.title).tag(option.value)
                    }
                }
                labeledField("Application Tag (atag)", "自定义标识，可留空", $applicationTag)
            } header: {
                Text("密钥属性")
            } footer: {
                Text("下方数据须是与所选类别 / 算法匹配的原始密钥字节，格式不符时系统会拒绝写入并报错。")
            }

        case .certificate:
            Section {
                EmptyView()
            } footer: {
                Text("证书由下方数据决定：请填入 DER 编码的证书（建议用十六进制输入）。主体、签发者、序列号都由系统从证书本身解析，无需也无法手填。")
            }
        }
    }

    private func labeledField(_ title: String,
                             _ placeholder: String,
                             _ text: Binding<String>) -> some View {
        HStack {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 132, alignment: .leading)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
    }

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
            // 同详情页：合并成同一个 Form 行，中间自己画 Divider。
            // 系统分割线在这个位置会被上方那行的控件背景盖住。
            VStack(spacing: 0) {
                TextField("输入 App 名称", text: $tagValue)
                    .textInputAutocapitalization(.never)
                    .padding(.vertical, 6)

                if !tagManager.allTags.isEmpty {
                    Divider()

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
                        .padding(.vertical, 8)
                    }
                    .scrollContentBackground(.hidden)
                }
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
        newItem.creator = creator
        newItem.typeCode = typeCode
        newItem.synchronizable = synchronizable
        newItem.generic = generic
        newItem.securityDomain = securityDomain
        newItem.networkProtocol = networkProtocol
        newItem.authenticationType = authenticationType
        newItem.port = port
        newItem.path = path
        newItem.keyClass = keyClass
        newItem.keyType = keyType
        newItem.applicationTag = applicationTag
        newItem.isInvisible = isInvisible
        newItem.isNegative = isNegative

        if viewModel.add(newItem, tag: tagValue) {
            dismiss()
        }
    }
}
