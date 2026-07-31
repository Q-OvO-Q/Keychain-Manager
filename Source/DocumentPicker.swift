import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// 直接包 `UIDocumentPickerViewController`，不用 SwiftUI 的 `.fileImporter`。
///
/// `.fileImporter` 挂在 sheet 内部时会出现「文件可选、点了没反应、也不返回」的情况 ——
/// 回调压根不触发。自己拿住控制器和委托就没有这层不确定性。
///
/// `asCopy: true` 让系统先把文件拷进本 App 的临时目录，
/// 于是不需要 security-scoped 访问权，又少一处会失败的环节。
struct DocumentPicker: UIViewControllerRepresentable {
    var contentTypes: [UTType] = [.json, .text, .plainText, .data, .item]
    var onPick: (URL) -> Void
    var onCancel: () -> Void = {}

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: contentTypes,
                                                    asCopy: true)
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick, onCancel: onCancel)
    }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        private let onPick: (URL) -> Void
        private let onCancel: () -> Void

        init(onPick: @escaping (URL) -> Void, onCancel: @escaping () -> Void) {
            self.onPick = onPick
            self.onCancel = onCancel
        }

        func documentPicker(_ controller: UIDocumentPickerViewController,
                           didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else {
                onCancel()
                return
            }
            onPick(url)
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onCancel()
        }
    }
}
