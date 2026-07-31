import SwiftUI
import UniformTypeIdentifiers

/// `fileExporter` 需要的最小 FileDocument 包装。
///
/// 内容已经由 `KeychainExport` 编码好，这里只负责把字节交给系统的保存面板。
struct JSONDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }

    var data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
