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
    @State private var applicationLabel = ""
    @State private var keySizeInBits = ""
    @State private var effectiveKeySize = ""
    @State private var isPermanent = false
    @State private var canEncrypt = false
    @State private var canDecrypt = false
    @State private var canDerive = false
    @State private var canSign = false
    @State private var canVerify = false
    @State private var canWrap = false
    @State private var canUnwrap = false

    /// 通配符组同样可以写入 —— 钥匙串把它当普通组名存，查询也只按字面匹配
    private var writableGroups: [String] {
        viewModel.detectedGroups
    }

    /// 输入框内容直接当筛选词；已精确命中某个组时不再收窄，
    /// 否则点一下列表就只剩这一项
    private var matchingGroups: [String] {
        let keyword = accessGroup.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !keyword.isEmpty else { return writableGroups }
        if writableGroups.contains(where: { $0.lowercased() == keyword }) { return writableGroups }
        return writableGroups.filter { $0.lowercased().contains(keyword) }
    }

    private var parsedData: Data? {
        isHexMode ? content.hexData : content.data(using: .utf8)
    }

    private var canSave: Bool {
        guard let data = parsedData else { return false }
        switch itemClass {
        case .genericPassword, .internetPassword:
            // service / server 允许为空（keychain 本身接受），
            // 但两者与 account 全空就成了无从辨认的条目，要求至少填一个
            let hasTitle = !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            let hasAccount = !account.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            return hasTitle || hasAccount
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

                metadataSection

                protectionSection

                tagSection

                // 组列表最长，放最后 —— 放中间的话得滑过上百行才够到后面的字段
                accessGroupSection
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

    /// 纯文本字段，不与开关、选择器混排
    @ViewBuilder
    /// 该类别可编辑的属性键。与详情页共用同一份定义 ——
    /// 之前这里按 supportsDataEditing 粗暴地一刀切，
    /// 于是 crtr 对密钥「可编辑、可导入，却没法在新增时填」。
    private var editableKeys: Set<String> {
        Set(KeychainStore.EditableAttribute.available(for: itemClass).map(\.key))
    }

    private func canEdit(_ attribute: KeychainStore.EditableAttribute) -> Bool {
        editableKeys.contains(attribute.key)
    }

    private var metadataSection: some View {
        Section {
            if canEdit(.label) {
                TextField("标签 (labl)", text: $label)
                    .textInputAutocapitalization(.never)
            }
            if canEdit(.description) {
                TextField("描述 (desc)", text: $itemDescription)
                    .textInputAutocapitalization(.never)
            }
            if canEdit(.comment) {
                TextField("备注 (icmt)", text: $comment)
                    .textInputAutocapitalization(.never)
            }
            if canEdit(.creator) {
                TextField("创建者 (crtr) — aapl 或十进制", text: $creator)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            if canEdit(.type) {
                TextField("类型码 (type) — aapl 或十进制", text: $typeCode)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }

            // 开关放本节末尾：同类控件聚在一起，但不脱离「元数据」这个分组
            if canEdit(.invisible) {
                Toggle("隐藏 (invi)", isOn: $isInvisible)
            }
            if canEdit(.negative) {
                Toggle("占位条目 (nega)", isOn: $isNegative)
            }
        } header: {
            Text("元数据（可选）")
        } footer: {
            if canEdit(.creator) {
                Text("这些写入后都还能改。crtr / type 填不出四字符码或十进制时会被忽略。")
            } else {
                Text("这些写入后都还能改。")
            }
        }
    }

    @ViewBuilder
    private var protectionSection: some View {
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
            Text("两项写入后都不可再改。")
        }
    }

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
                labeledField("Port (port)", "如 443，可留空", $port)
                    .keyboardType(.numberPad)
                labeledField("Path (path)", "如 /login，可留空", $path)

                // 选择器放本节末尾，不夹在文本框中间
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
            } header: {
                Text("主键字段")
            } footer: {
                Text("这 7 项构成主键，写入后不可再改。")
            }

        case .key:
            Section {
                labeledField("Key Size (bsiz)", "位数，如 2048", $keySizeInBits)
                    .keyboardType(.numberPad)
                labeledField("Effective Size (esiz)", "位数，可留空", $effectiveKeySize)
                    .keyboardType(.numberPad)
                labeledField("Application Label (klbl)", "可留空", $applicationLabel)
                labeledField("Application Tag (atag)", "可留空", $applicationTag)

                // 选择器放本节末尾，不夹在文本框中间
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
            } header: {
                Text("主键字段")
            } footer: {
                Text("密钥的主键由这 6 项构成，写入后都不可再改。导入原始密钥时系统推断不出位数，bsiz 留空通常会直接返回 -50。")
            }

            Section("用途标志") {
                Toggle("永久存储 (perm)", isOn: $isPermanent)
                Toggle("可加密 (encr)", isOn: $canEncrypt)
                Toggle("可解密 (decr)", isOn: $canDecrypt)
                Toggle("可派生 (drve)", isOn: $canDerive)
                Toggle("可签名 (sign)", isOn: $canSign)
                Toggle("可验签 (vrfy)", isOn: $canVerify)
                Toggle("可包装密钥 (wrap)", isOn: $canWrap)
                Toggle("可解包密钥 (unwp)", isOn: $canUnwrap)
            }

        case .certificate:
            EmptyView()
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

    private var dataSectionTitle: String {
        switch itemClass {
        case .certificate: return "证书数据 (DER)"
        case .key:         return "密钥数据"
        default:           return "数据 (kSecValueData)"
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
            Text(dataSectionTitle)
        } footer: {
            if parsedData == nil {
                Text("十六进制不合法：长度需为偶数，且只含 0-9 / a-f。")
                    .foregroundStyle(.orange)
            } else if itemClass == .certificate {
                Text("须是 DER 编码的证书，请用十六进制输入。主体、签发者、序列号由系统从证书中解析。")
            } else if itemClass == .key {
                Text("须是与上方类别 / 算法匹配的原始密钥字节。")
            } else {
                Text("\(parsedData?.count ?? 0) 字节")
            }
        }
    }

    @ViewBuilder
    private var accessGroupSection: some View {
        Section {
            // 与查询设置页一致：一个输入框兼作手动输入与列表筛选
            TextField("输入组名，或用于筛选下方列表", text: $accessGroup)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            ForEach(matchingGroups, id: \.self) { group in
                Button {
                    accessGroup = group
                } label: {
                    HStack {
                        Text(group)
                            .font(.callout)
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            // 组名的区别在尾部编号上，掐中间才看得见
                            .truncationMode(.middle)
                        Spacer()
                        if accessGroup == group {
                            Image(systemName: "checkmark")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
            }
        } header: {
            Text("Access Group（\(matchingGroups.count)/\(writableGroups.count)）")
        } footer: {
            if accessGroup.isEmpty {
                Text("留空则写入应用默认组。")
            } else {
                Text("须是签名 entitlements 里声明过的组，否则保存时返回 -34018。")
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
        if case .group(let group) = scope {
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
        newItem.applicationLabel = applicationLabel
        newItem.keySizeInBits = keySizeInBits
        newItem.effectiveKeySize = effectiveKeySize
        newItem.isPermanent = isPermanent
        newItem.canEncrypt = canEncrypt
        newItem.canDecrypt = canDecrypt
        newItem.canDerive = canDerive
        newItem.canSign = canSign
        newItem.canVerify = canVerify
        newItem.canWrap = canWrap
        newItem.canUnwrap = canUnwrap
        newItem.isInvisible = isInvisible
        newItem.isNegative = isNegative

        if viewModel.add(newItem, tag: tagValue) {
            dismiss()
        }
    }
}
