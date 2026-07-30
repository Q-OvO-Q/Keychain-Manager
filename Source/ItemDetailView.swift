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

            TextEditor(text: $content)
                .frame(height: 130)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

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

    // MARK: 全部属性

    private func attributesSection(_ item: KeychainItem) -> some View {
        Section("全部元数据") {
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
