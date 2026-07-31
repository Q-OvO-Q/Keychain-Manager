import SwiftUI
import UIKit
import Security

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
    /// 只存被改动过的属性，未改动的直接读条目当前值
    @State private var editedAttributes: [String: Any] = [:]

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
            tagSection(item)
            dataSection(item)
            editableAttributesSection(item)
            attributesSection(item)
            deleteSection(item)
        }
        .onAppear { load(item) }
        .confirmationDialog("删除这条条目？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                viewModel.delete([item])
                if viewModel.item(withID: itemID) == nil { dismiss() }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("此操作不可撤销。")
        }
    }

    // MARK: 核心标识

    @ViewBuilder
    private func identitySection(_ item: KeychainItem) -> some View {
        Section {
            infoRow("类别", item.itemClass.displayName)
            infoRow(item.itemClass == .internetPassword ? "Server" : "Service", item.displayTitle)
            infoRow("Account", item.account)
            infoRow("Access Group", item.accessGroup)
            infoRow("iCloud 同步", item.isSynchronizable ? "是" : "否")
            if let accessible = KeychainItem.stringValue(item.rawAttributes[kSecAttrAccessible as String]) {
                infoRow("可访问性", KeychainAttributeFormatter.accessibilityDescription(accessible))
            }
        } header: {
            Text("核心标识（构成主键，不可修改）")
        } footer: {
            if !item.canBeTargeted {
                Text("系统未回传该条目的持久引用与主键属性，为避免误删同组其它条目，已禁用删除与修改。")
                    .foregroundStyle(.orange)
            }
        }
    }

    // MARK: 标签

    private func tagSection(_ item: KeychainItem) -> some View {
        Section("App 标签") {
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

            if !tagManager.allTags.isEmpty {
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
                    .padding(.vertical, 2)
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

            if let saveNotice {
                Text(saveNotice)
                    .font(.caption)
                    .foregroundStyle(.green)
            }

            Button("保存修改") { save(item) }
                .frame(maxWidth: .infinity)
                .disabled(!item.itemClass.supportsDataEditing || !item.canBeTargeted)
        } header: {
            Text("数据 (kSecValueData)")
        } footer: {
            if !item.itemClass.supportsDataEditing {
                Text("\(item.itemClass.displayName)条目的数据由系统管理，仅支持查看与删除。")
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

    // MARK: 可修改的元数据

    @ViewBuilder
    private func editableAttributesSection(_ item: KeychainItem) -> some View {
        let editable = KeychainStore.EditableAttribute.available(for: item.itemClass)

        if !editable.isEmpty {
            Section {
                ForEach(editable) { attribute in
                    if attribute.isBoolean {
                        Toggle(attribute.displayName, isOn: booleanBinding(attribute))
                            .font(.callout)
                    } else if attribute == .accessible {
                        Picker(attribute.displayName, selection: accessibleBinding) {
                            ForEach(AccessibleOption.options(including: accessibleBinding.wrappedValue)) { option in
                                Text(option.title).tag(option.value)
                            }
                        }
                        .font(.callout)
                    } else {
                        HStack {
                            Text(attribute.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(width: 96, alignment: .leading)
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
                Text("主键属性（账号 / 服务 / 组 / 同步）不可改：改动等于把条目挪到另一个主键上，会和已有条目冲突。")
            }
        }
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
                        Text(KeychainAttributeFormatter.value(value))
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
            Text("这里是系统实际回传的全部属性，一个不漏。")
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
                Text("SecItemCopyMatching 只回传有值的键，这些属性在本条目上为空，因此不出现在上面那一节。「可修改的元数据」是固定列出的，所以其中几项会在这里而不在上面。")
            }
        }
    }

    // MARK: 删除

    private func deleteSection(_ item: KeychainItem) -> some View {
        Section {
            Button("删除此条目", role: .destructive) { confirmDelete = true }
                .frame(maxWidth: .infinity)
                .disabled(!item.canBeTargeted)
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
        guard item.isDataReadable, let data = item.data else {
            content = ""
            isHexMode = false
            return
        }

        if let text = data.utf8Text {
            content = text
            isHexMode = false
        } else {
            content = data.hexString
            isHexMode = true
        }
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
