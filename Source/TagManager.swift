import Foundation

/// App 标签存储。
///
/// 标签是本地元数据，与 keychain 条目通过 `KeychainItem.tagKey` 关联。
/// 全部读写都走内存缓存 —— 旧实现每次读标签都要反序列化一遍 UserDefaults 字典，
/// 而 SwiftUI 每帧会为每一行调用一次。
final class TagManager: ObservableObject {

    static let shared = TagManager()

    private let userDefaults = UserDefaults.standard
    private let tagsKey = "KeychainItemTags"
    private let separator = "|||"

    private var tags: [String: String]

    /// 去重并排序后的标签集合，供筛选与选择列表直接使用
    @Published private(set) var allTags: [String] = []

    /// 仅用于触发 SwiftUI 刷新：标签值本身变化但 allTags 不变时（例如把标签改成一个已存在的名字），
    /// 只靠 allTags 无法通知视图重绘
    @Published private(set) var revision: Int = 0

    private init() {
        tags = userDefaults.dictionary(forKey: tagsKey) as? [String: String] ?? [:]
        allTags = TagManager.sortedTags(from: tags)
    }

    // MARK: - 读

    func tag(for key: String) -> String {
        tags[key] ?? ""
    }

    // MARK: - 写

    func setTag(_ tag: String, for key: String) {
        setTag(tag, for: [key])
    }

    /// 批量写入。旧实现逐条调用 setTag，每条都要重新读写整个 UserDefaults 字典并重算标签集合。
    func setTag(_ tag: String, for keys: [String]) {
        guard !keys.isEmpty else { return }
        let trimmed = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        var changed = false

        for key in keys {
            if trimmed.isEmpty {
                if tags.removeValue(forKey: key) != nil { changed = true }
            } else if tags[key] != trimmed {
                tags[key] = trimmed
                changed = true
            }
        }

        if changed { persist() }
    }

    func removeTags(for keys: [String]) {
        setTag("", for: keys)
    }

    /// 清理孤立标签：条目已不存在但标签还留着。
    ///
    /// 只处理本次确实成功枚举过的 Access Group —— 查询失败时条目列表为空，
    /// 若照样清理就会把用户的标签全部误删。
    func cleanupOrphanedTags(existingKeys: Set<String>, inAccessGroups groups: Set<String>) {
        guard !groups.isEmpty else { return }

        let survivors = tags.filter { key, _ in
            let components = key.components(separatedBy: separator)
            // tagKey 格式: classDisplay|||title|||account|||accessGroup
            guard components.count >= 4, let keyGroup = components.last else { return true }
            guard groups.contains(keyGroup) else { return true }
            return existingKeys.contains(key)
        }

        if survivors.count != tags.count {
            tags = survivors
            persist()
        }
    }

    // MARK: - 内部

    private func persist() {
        userDefaults.set(tags, forKey: tagsKey)
        let sorted = TagManager.sortedTags(from: tags)
        allTags = sorted
        revision &+= 1
    }

    private static func sortedTags(from tags: [String: String]) -> [String] {
        Set(tags.values.filter { !$0.isEmpty }).sorted {
            $0.localizedCaseInsensitiveCompare($1) == .orderedAscending
        }
    }
}
