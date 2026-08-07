import SwiftUI
import UIKit
import Security

/// 展示用的一行键值。用结构体而不是元组：Swift 不支持指向元组元素的 KeyPath，
/// ForEach 拿元组编译不过。
struct LabeledValue: Identifiable {
    let label: String
    let value: String
    var id: String { label }
}

struct ItemDetailView: View {

    @ObservedObject var viewModel: KeychainViewModel
    let itemID: String

    @ObservedObject private var tagManager = TagManager.shared
    @Environment(\.dismiss) private var dismiss

    @State private var content = ""
    @State private var isHexMode = false
    @State private var conversionWarning: String?
    @State private var saveNotice: String?
    @State private var tagValue = ""
    @State private var didLoad = false
    @State private var confirmDelete = false
    @State private var didRequestDelete = false
    /// 只存被改动过的属性，未改动的直接读条目当前值
    @State private var editedAttributes: [String: Any] = [:]
    /// 数据解析结果。解析要跑一遍引用图，不放进 computed property 里每帧重算
    @State private var decoded: DecodedPayload?
    /// 解析视图里被改过的字段，key 是 DecodedField.id
    @State private var decodedEdits: [String: String] = [:]
    /// 解析区自己的保存提示。放在数据区的 saveNotice 里用户看不到——
    /// 按钮在这一段，提示却在上面那一段
    @State private var decodedNotice: String?

    private var item: KeychainItem? { viewModel.item(withID: itemID) }

    var body: some View {
        Group {
            if let item {
                form(for: item)
            } else {
                ContentUnavailableView {
                    Label("条目已不存在", systemImage: "trash")
                } description: {
                    Text("该条目已被删除，或在当前作用域下不再可见。")
                }
            }
        }
        .navigationTitle("条目详情")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - 表单

    private func form(for item: KeychainItem) -> some View {
        Form {
            identitySection(item)
            certificateSection(item)
            tagSection(item)
            dataSection(item)
            decodedDataSection(item)
            editableAttributesSection(item)
            attributesSection(item)
            deleteSection(item)
        }
        .onAppear { load(item) }
        .onChange(of: content) { _, _ in refreshDecoded() }
        .confirmationDialog("删除这条条目？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                didRequestDelete = true
                viewModel.delete([item])
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("此操作不可撤销。")
        }
        // 删除改成异步执行后，触发的当下条目还在，只能等它真的消失了再退出
        .onChange(of: viewModel.items.count) { _, _ in
            if didRequestDelete, viewModel.item(withID: itemID) == nil {
                dismiss()
            }
        }
    }

    // MARK: 核心标识

    @ViewBuilder
    private func identitySection(_ item: KeychainItem) -> some View {
        // 直接遍历该类别的主键属性来渲染，而不是写死 Service / Account 两行。
        // 写死的版本对密钥和证书是错的：把 klbl 标成「Service」、显示一个恒为空的
        // 「Account」，而它们真正的主键（kcls / type / bsiz、ctyp / issr / slnr）
        // 一个都没露出来。照着 primaryKeyAttributes 走就不会再漏。
        Section {
            infoRow("类别", item.itemClass.displayName)
            ForEach(item.itemClass.primaryKeyAttributes, id: \.self) { key in
                infoRow(KeychainAttributeFormatter.label(for: key), primaryKeyValue(item, key))
            }
        } header: {
            Text("核心标识（构成主键，不可修改）")
        } footer: {
            if !item.canBeTargeted {
                Text("系统没回传能唯一定位这条的属性。删除它会波及同组其它条目，因此已禁用。")
                    .foregroundStyle(.orange)
            }
        }
    }

    private func primaryKeyValue(_ item: KeychainItem, _ key: String) -> String {
        // sync 系统常常不回传，缺省即为「否」，显示成「未设置」会误导
        if key == kSecAttrSynchronizable as String {
            return item.isSynchronizable ? "是" : "否"
        }
        guard let value = item.rawAttributes[key] else { return "未设置" }
        return KeychainAttributeFormatter.value(value, forKey: key)
    }

    // MARK: 证书解析

    /// `subj` / `issr` 存的是 DER 编码的 X.509 名称，按十六进制显示等于没显示。
    /// 用证书本身解析出可读信息补上。
    private func certificateDetails(_ item: KeychainItem) -> [LabeledValue] {
        guard item.itemClass == .certificate,
              item.isDataReadable,
              let data = item.data,
              let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            return []
        }

        var rows: [LabeledValue] = []

        if let summary = SecCertificateCopySubjectSummary(certificate) as String?, !summary.isEmpty {
            rows.append(LabeledValue(label: "主体摘要", value: summary))
        }

        var commonName: CFString?
        if SecCertificateCopyCommonName(certificate, &commonName) == errSecSuccess,
           let name = commonName as String?, !name.isEmpty {
            rows.append(LabeledValue(label: "Common Name", value: name))
        }

        var emails: CFArray?
        if SecCertificateCopyEmailAddresses(certificate, &emails) == errSecSuccess,
           let list = emails as? [String], !list.isEmpty {
            rows.append(LabeledValue(label: "邮箱", value: list.joined(separator: ", ")))
        }

        rows.append(LabeledValue(label: "DER 长度", value: "\(data.count) 字节"))
        return rows
    }

    @ViewBuilder
    private func certificateSection(_ item: KeychainItem) -> some View {
        let rows = certificateDetails(item)
        if !rows.isEmpty {
            Section {
                ForEach(rows) { row in
                    infoRow(row.label, row.value)
                }
            } header: {
                Text("证书内容")
            } footer: {
                Text("由证书数据本身解析，不是存储的属性。")
            }
        }
    }

    // MARK: 标签

    private func tagSection(_ item: KeychainItem) -> some View {
        Section("App 标签") {
            // 输入行与标签行合并成**同一个 Form 行**，中间自己画 Divider。
            //
            // 试过两轮系统分割线都不行：先是 listRowSeparator 默认作用于上下两条边，
            // 在 section 末尾多画了一条；改成只要 top 之后，那条线仍然被上方那行的
            // 控件背景盖住 —— 说明它是被覆盖而不是没被请求。
            // 放进同一行的内容里，兄弟行的背景就盖不到它了。
            VStack(spacing: 0) {
                HStack {
                    TextField("输入 App 名称", text: $tagValue)
                        .textInputAutocapitalization(.never)
                    Button("保存") {
                        viewModel.setTag(tagValue, for: item)
                        saveNotice = tagValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            ? "已清除标签"
                            : "已保存标签"
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }
                .padding(.vertical, 6)

                if !tagManager.allTags.isEmpty {
                    Divider()

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(tagManager.allTags, id: \.self) { tag in
                                Button {
                                    tagValue = tag
                                    viewModel.setTag(tag, for: item)
                                    saveNotice = "已保存标签"
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

    // MARK: 数据

    @ViewBuilder
    private func dataSection(_ item: KeychainItem) -> some View {
        Section {
            if let status = item.dataStatus, status != errSecSuccess {
                Label(KeychainStore.message(for: status), systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)

                // 枚举时一律跳过验证，受保护条目只能在这里由用户主动解锁
                if status == errSecInteractionNotAllowed {
                    Button {
                        unlock(item)
                    } label: {
                        HStack {
                            Label("解锁读取", systemImage: "faceid")
                            if viewModel.isUnlocking {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(viewModel.isUnlocking)
                }
            }

            Picker("编辑模式", selection: modeBinding) {
                Text("文本 (UTF-8)").tag(false)
                Text("十六进制").tag(true)
            }
            .pickerStyle(.segmented)

            if let conversionWarning {
                Text(conversionWarning)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            // TextEditor 在 Form 里会画一块不透明底色，铺满整行并盖住分隔线。
            // 关掉它自带的背景，再自己画一个带内边距的圆角框。
            TextEditor(text: $content)
                .frame(height: 130)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.secondary.opacity(0.08))
                )

            // 同上：字节数行与保存按钮合并成同一个 Form 行，中间自己画 Divider
            VStack(spacing: 0) {
                HStack {
                    Text(byteCountDescription)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        copy(content)
                    } label: {
                        Label("复制", systemImage: "doc.on.doc")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.vertical, 6)

                Divider()

                Button("保存修改") { save(item) }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    // 同一行里有两个按钮，样式必须显式指定，
                    // 否则整行点击都会触发其中一个
                    .buttonStyle(.borderless)
                    .disabled(!item.itemClass.supportsDataEditing || !item.canBeTargeted)

                // 保存提示也收进同一行：单独成行的话，它和按钮之间那条
                // 系统分割线又会被盖住（和标签区当初一模一样的问题）
                if let saveNotice {
                    Divider()

                    Text(saveNotice)
                        .font(.caption)
                        .foregroundStyle(.green)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 6)
                }
            }
        } header: {
            Text("数据 (kSecValueData)")
        } footer: {
            if !item.itemClass.supportsDataEditing {
                Text("\(item.itemClass.displayName)的数据不可改，只能查看或删除整条。")
            }
        }
    }

    /// 用自定义 Binding 而非 onChange 切换模式：
    /// 转换失败时直接拒绝切换，既不会破坏用户已输入的内容，也不会触发 onChange 递归。
    private var modeBinding: Binding<Bool> {
        Binding(
            get: { isHexMode },
            set: { newValue in
                guard newValue != isHexMode else { return }

                if newValue {
                    guard let data = content.data(using: .utf8) else {
                        conversionWarning = "当前文本无法编码为 UTF-8，已保持文本模式。"
                        return
                    }
                    content = data.hexString
                } else {
                    guard let data = content.hexData else {
                        conversionWarning = "十六进制内容不合法（长度需为偶数且只含 0-9a-f），已保持十六进制模式。"
                        return
                    }
                    guard let text = data.utf8Text else {
                        conversionWarning = "该数据不是合法 UTF-8 文本，已保持十六进制模式。"
                        return
                    }
                    content = text
                }

                conversionWarning = nil
                isHexMode = newValue
            }
        )
    }

    private var byteCountDescription: String {
        let data = isHexMode ? content.hexData : content.data(using: .utf8)
        guard let data else { return "内容不合法" }
        return "\(data.count) 字节"
    }

    // MARK: 数据解析

    /// 大量条目的数据其实是 binary plist（多数还是 NSKeyedArchiver 归档），
    /// 在上面的数据区只能看见十六进制，根本无从下手改。这里把它解开成一个个
    /// 字段直接编辑，保存时按原格式重新编码 —— 引用图不动，只替换改过的那几处。
    @ViewBuilder
    private func decodedDataSection(_ item: KeychainItem) -> some View {
        if let payload = decoded {
            Section {
                // 行的写法一律跟着本文件既有的 attributeRow 走：单层 HStack、
                // 固定宽标签、不加 padding、不套 VStack。自己发明的写法
                // 会把系统分隔线盖住，这个坑踩过好几次了。
                ForEach(payload.fields) { field in
                    decodedFieldRow(field)
                }

                if payload.isEditable {
                    Button("按字段保存") { saveDecoded(item, payload: payload) }
                        .disabled(!item.itemClass.supportsDataEditing
                                  || !item.canBeTargeted
                                  || decodedEdits.isEmpty)
                }

                if let decodedNotice {
                    Text(decodedNotice)
                        .font(.caption)
                        .foregroundStyle(.green)
                }

                NavigationLink {
                    decodedStructurePage(payload)
                } label: {
                    Text("完整结构")
                }
            } header: {
                Text("数据解析（\(payload.formatName)）")
            } footer: {
                decodedFooter(payload, item: item)
            }
        }
    }

    /// 全文是一大段等宽文本，塞进 Form 的行里怎么排都难看，单独开一页
    private func decodedStructurePage(_ payload: DecodedPayload) -> some View {
        ScrollView([.horizontal, .vertical]) {
            Text(payload.text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding()
        }
        .navigationTitle(payload.formatName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            Button {
                copy(payload.text)
            } label: {
                Label("复制", systemImage: "doc.on.doc")
            }
        }
    }

    @ViewBuilder
    private func decodedFieldRow(_ field: DecodedField) -> some View {
        // 路径可能很长（a.b.c[0].d），从头部截断，保留最具体的那一段；
        // 改过的标成橙色——一条归档能解出上千个字段，不标根本找不到改过哪几个
        let label = Text(field.label)
            .font(.caption)
            .foregroundStyle(isEdited(field) ? Color.orange : Color.secondary)
            .lineLimit(1)
            .truncationMode(.head)

        switch field.kind {
        case .boolean:
            Toggle(isOn: decodedBoolBinding(field)) { label }

        case .string, .integer, .real:
            HStack {
                label.frame(width: 116, alignment: .leading)
                TextField("空", text: decodedBinding(field))
                    .font(.system(.callout, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }

        case .date, .data, .null:
            HStack {
                label.frame(width: 116, alignment: .leading)
                Text(field.value)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func isEdited(_ field: DecodedField) -> Bool {
        decodedEdits[field.id].map { $0 != field.value } ?? false
    }

    private func decodedBinding(_ field: DecodedField) -> Binding<String> {
        Binding(
            get: { decodedEdits[field.id] ?? field.value },
            set: {
                decodedEdits[field.id] = $0
                // 又开始改了，上一次的「已写入」提示就不该再挂着
                decodedNotice = nil
            }
        )
    }

    private func decodedBoolBinding(_ field: DecodedField) -> Binding<Bool> {
        Binding(
            get: { (decodedEdits[field.id] ?? field.value) == "true" },
            set: {
                decodedEdits[field.id] = $0 ? "true" : "false"
                decodedNotice = nil
            }
        )
    }

    @ViewBuilder
    private func decodedFooter(_ payload: DecodedPayload, item: KeychainItem) -> some View {
        if !payload.isEditable {
            Text("这段数据没有可改的字段，只能查看。")
        } else if !item.itemClass.supportsDataEditing {
            Text("\(item.itemClass.displayName)的数据不可改。")
        } else {
            Text("保存会按原格式重新编码，只替换改过的字段。"
                 + "标签里出现「/」表示这一处被多条路径共用，改一次会同时生效。")
        }
    }

    private func saveDecoded(_ item: KeychainItem, payload: DecodedPayload) {
        do {
            let data = try payload.encoded(with: decodedEdits)
            guard viewModel.updateData(item, to: data) else { return }
            // 重新读一遍：原始数据区和解析结果都要跟着变。
            // 这一步会清掉 decodedEdits，所以提示要在它之后再设。
            if let updated = viewModel.item(withID: itemID) {
                loadContent(from: updated)
            }
            decodedNotice = "已按字段写入 \(data.count) 字节"
        } catch {
            viewModel.alertMessage = error.localizedDescription
        }
    }

    // MARK: 可修改的元数据

    @ViewBuilder
    private func editableAttributesSection(_ item: KeychainItem) -> some View {
        // 按控件类型排序，文本 / 四字符码 / 选择器 / 开关各自成段
        let editable = KeychainStore.EditableAttribute.ordered(for: item.itemClass)

        if !editable.isEmpty {
            Section {
                ForEach(editable) { attribute in
                    switch attribute.kind {
                    case .boolean:
                        Toggle(attribute.displayName, isOn: booleanBinding(attribute))
                            .font(.callout)

                    case .accessibility:
                        Picker(attribute.displayName, selection: accessibleBinding) {
                            ForEach(AccessibleOption.options(including: accessibleBinding.wrappedValue)) { option in
                                Text(option.title).tag(option.value)
                            }
                        }
                        .font(.callout)

                    case .fourCharCode:
                        attributeRow(attribute) {
                            // 之前这里传的是空占位符，值为空时整行看不出是「未设置」还是坏了
                            TextField("未设置", text: fourCharCodeBinding(attribute))
                                .font(.system(.callout, design: .monospaced))
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }

                    case .text:
                        attributeRow(attribute) {
                            TextField("未设置", text: textBinding(attribute))
                                .font(.callout)
                                .textInputAutocapitalization(.never)
                        }
                    }
                }

                Button("保存元数据") { saveAttributes(item) }
                    .disabled(!item.canBeTargeted || editedAttributes.isEmpty)
            } header: {
                Text("可修改的元数据")
            } footer: {
                Text("这里列出了该类别所有能改的属性。未列出的要么构成主键，要么由系统从数据中解析。")
            }
        }
    }

    private func attributeRow<Field: View>(_ attribute: KeychainStore.EditableAttribute,
                                          @ViewBuilder field: () -> Field) -> some View {
        HStack {
            Text(attribute.displayName)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 116, alignment: .leading)
            field()
        }
    }

    /// 四字符码字段：输入 'aapl' 这样四个字符，或直接写十进制
    private func fourCharCodeBinding(_ attribute: KeychainStore.EditableAttribute) -> Binding<String> {
        Binding(
            get: {
                if let edited = editedAttributes[attribute.key] {
                    return KeychainStore.FourCharCode.text(from: edited)
                }
                guard let item else { return "" }
                return KeychainStore.FourCharCode.text(from: item.rawAttributes[attribute.key])
            },
            set: { text in
                // 解析不出来就不写进改动集，避免把非法值发给 SecItemUpdate
                if let number = KeychainStore.FourCharCode.number(from: text) {
                    editedAttributes[attribute.key] = number
                } else {
                    editedAttributes.removeValue(forKey: attribute.key)
                }
            }
        )
    }

    private func textBinding(_ attribute: KeychainStore.EditableAttribute) -> Binding<String> {
        Binding(
            get: {
                if let edited = editedAttributes[attribute.key] as? String { return edited }
                guard let item else { return "" }
                return KeychainItem.stringValue(item.rawAttributes[attribute.key]) ?? ""
            },
            set: { editedAttributes[attribute.key] = $0 }
        )
    }

    private func booleanBinding(_ attribute: KeychainStore.EditableAttribute) -> Binding<Bool> {
        Binding(
            get: {
                if let edited = editedAttributes[attribute.key] as? Bool { return edited }
                guard let item else { return false }
                return (item.rawAttributes[attribute.key] as? NSNumber)?.boolValue ?? false
            },
            set: { editedAttributes[attribute.key] = $0 }
        )
    }

    private var accessibleBinding: Binding<String> {
        let key = KeychainStore.EditableAttribute.accessible.key
        return Binding(
            get: {
                if let edited = editedAttributes[key] as? String { return edited }
                guard let item else { return "" }
                return KeychainItem.stringValue(item.rawAttributes[key]) ?? ""
            },
            set: { editedAttributes[key] = $0 }
        )
    }

    private func saveAttributes(_ item: KeychainItem) {
        if viewModel.updateAttributes(item, changes: editedAttributes) {
            editedAttributes.removeAll()
            saveNotice = "元数据已更新"
        }
    }

    // MARK: 全部属性

    /// 该类别已知、但这条条目上没有值的属性
    private func unsetAttributes(_ item: KeychainItem) -> [String] {
        item.itemClass.knownAttributes
            .filter { item.rawAttributes[$0] == nil }
            .sorted()
    }

    @ViewBuilder
    private func attributesSection(_ item: KeychainItem) -> some View {
        Section {
            ForEach(item.rawAttributes.keys.sorted(), id: \.self) { key in
                if let value = item.rawAttributes[key] {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(KeychainAttributeFormatter.label(for: key))
                            .font(.caption)
                            .foregroundStyle(Color.accentColor)
                        Text(KeychainAttributeFormatter.value(value, forKey: key))
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 2)
                }
            }
        } header: {
            Text("已设置的元数据（\(item.rawAttributes.count)）")
        } footer: {
            Text("系统实际回传的全部属性。")
        }

        let unset = unsetAttributes(item)
        if !unset.isEmpty {
            Section {
                ForEach(unset, id: \.self) { key in
                    HStack {
                        Text(KeychainAttributeFormatter.label(for: key))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("未设置")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            } header: {
                Text("未设置的元数据（\(unset.count)）")
            } footer: {
                Text("这些属性在本条目上没有值。系统只回传有值的键，所以它们不在上一节里。")
            }
        }
    }

    // MARK: 删除

    private func deleteSection(_ item: KeychainItem) -> some View {
        Section {
            Button("删除此条目", role: .destructive) { confirmDelete = true }
                .frame(maxWidth: .infinity)
                .disabled(!item.canBeTargeted || viewModel.isDeleting)
        }
    }

    // MARK: - 动作

    private func load(_ item: KeychainItem) {
        guard !didLoad else { return }
        didLoad = true

        tagValue = item.appTag
        loadContent(from: item)
    }

    /// 只刷新数据内容，不动标签输入框（解锁后复用）
    private func loadContent(from item: KeychainItem) {
        decodedEdits.removeAll()
        decodedNotice = nil

        guard item.isDataReadable, let data = item.data else {
            content = ""
            isHexMode = false
            decoded = nil
            return
        }

        if let text = data.utf8Text {
            content = text
            isHexMode = false
        } else {
            content = data.hexString
            isHexMode = true
        }
        decoded = DataDecoder.decode(data)
    }

    /// 用户在原始数据区改过之后，解析结果就对不上了，得跟着重算
    private func refreshDecoded() {
        guard let data = isHexMode ? content.hexData : content.data(using: .utf8) else {
            decoded = nil
            return
        }
        decoded = DataDecoder.decode(data)
        decodedEdits.removeAll()
    }

    private func unlock(_ item: KeychainItem) {
        viewModel.unlockData(for: item) { updated in
            guard let updated, updated.isDataReadable else { return }
            conversionWarning = nil
            loadContent(from: updated)
            saveNotice = "已解锁，读取到 \(updated.data?.count ?? 0) 字节"
        }
    }

    private func save(_ item: KeychainItem) {
        let data: Data?
        if isHexMode {
            data = content.hexData
        } else {
            data = content.data(using: .utf8)
        }

        guard let data else {
            // 旧实现在这里直接 return，用户以为保存成功了
            viewModel.alertMessage = isHexMode
                ? "十六进制内容不合法：长度需为偶数且只含 0-9 / a-f。"
                : "文本无法编码为 UTF-8。"
            return
        }

        if viewModel.updateData(item, to: data) {
            saveNotice = "已写入 \(data.count) 字节"
        } else {
            saveNotice = nil
        }
    }

    private func copy(_ text: String) {
        UIPasteboard.general.string = text
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 96, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(.callout)
                .textSelection(.enabled)
                .lineLimit(3)
                // 组名之类的长值，区别常在尾部
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
            if !value.isEmpty {
                Button {
                    copy(value)
                } label: {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .buttonStyle(.plain)
            }
        }
    }
}
