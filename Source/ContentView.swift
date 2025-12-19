import SwiftUI
import Security

struct KeychainItem: Identifiable, Hashable {
    let id = UUID()
    let service: String
    let account: String
    let accessGroup: String
    let dataString: String
    let rawData: Data
    let itemClass: CFString // kSecClassGenericPassword or kSecClassInternetPassword
}

struct ContentView: View {
    // 用户手动输入 Access Group，例如 "ZYVN84RRCJ.*"
    // 因为 App 运行时很难知道自己被签了什么 TeamID，必须手动填
    @AppStorage("targetAccessGroup") private var targetGroup: String = ""
    @State private var items: [KeychainItem] = []
    @State private var showingAddSheet = false
    @State private var statusMessage = "准备就绪"

    var body: some View {
        NavigationView {
            VStack {
                // 顶部控制区
                VStack(spacing: 10) {
                    TextField("输入 Access Group (如 A1B2C3D4.*)", text: $targetGroup)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .padding(.horizontal)
                    
                    HStack {
                        Button("刷新/查询") { fetchItems() }
                            .buttonStyle(.borderedProminent)
                        Button("清空列表") { items.removeAll() }
                            .buttonStyle(.bordered)
                    }
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                .padding(.top)

                // 列表区
                List {
                    ForEach(items, id: \.self) { item in
                        NavigationLink(destination: ItemDetailView(item: item, targetGroup: targetGroup, onUpdate: fetchItems)) {
                            VStack(alignment: .leading) {
                                Text(item.service).font(.headline)
                                Text(item.account).font(.subheadline).foregroundColor(.secondary)
                                Text(item.accessGroup).font(.caption2).foregroundColor(.blue)
                            }
                        }
                    }
                    .onDelete(perform: deleteItems)
                }
                .listStyle(.plain)
            }
            .navigationTitle("Keychain Manager")
            .toolbar {
                Button(action: { showingAddSheet = true }) {
                    Image(systemName: "plus")
                }
            }
            .sheet(isPresented: $showingAddSheet) {
                AddItemView(targetGroup: targetGroup, onSave: fetchItems)
            }
        }
    }

    // MARK: - 核心：查询逻辑
    func fetchItems() {
        if targetGroup.isEmpty {
            statusMessage = "请输入 Access Group，例如 'ZYVN84RRCJ.*'"
            return
        }
        
        var newItems: [KeychainItem] = []
        let classes = [kSecClassGenericPassword, kSecClassInternetPassword]
        
        for secClass in classes {
            let query: [String: Any] = [
                kSecClass as String: secClass,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
                kSecReturnData as String: true,
                // ⚠️ 关键：指定我们要扫荡那个公共垃圾桶
                kSecAttrAccessGroup as String: targetGroup
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            if status == errSecSuccess, let results = result as? [[String: Any]] {
                for res in results {
                    let svc = res[kSecAttrService as String] as? String ?? "未知服务"
                    let acc = res[kSecAttrAccount as String] as? String ?? "未知账号"
                    let grp = res[kSecAttrAccessGroup as String] as? String ?? "未知组"
                    let data = res[kSecValueData as String] as? Data ?? Data()
                    let str = String(data: data, encoding: .utf8) ?? "HEX: \(data.map { String(format: "%02hhx", $0) }.joined())"
                    
                    newItems.append(KeychainItem(service: svc, account: acc, accessGroup: grp, dataString: str, rawData: data, itemClass: secClass))
                }
            }
        }
        
        DispatchQueue.main.async {
            self.items = newItems
            self.statusMessage = "查询成功: 找到 \(newItems.count) 条数据"
        }
    }

    // MARK: - 核心：删除逻辑
    func deleteItems(at offsets: IndexSet) {
        for index in offsets {
            let item = items[index]
            let query: [String: Any] = [
                kSecClass as String: item.itemClass,
                kSecAttrService as String: item.service,
                kSecAttrAccount as String: item.account,
                kSecAttrAccessGroup as String: targetGroup
            ]
            SecItemDelete(query as CFDictionary)
        }
        items.remove(atOffsets: offsets)
    }
}

// 详情页与修改功能
struct ItemDetailView: View {
    let item: KeychainItem
    let targetGroup: String
    var onUpdate: () -> Void
    @State private var editedData: String = ""
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        Form {
            Section(header: Text("基础信息")) {
                HStack { Text("Service"); Spacer(); Text(item.service) }
                HStack { Text("Account"); Spacer(); Text(item.account) }
                HStack { Text("Group"); Spacer(); Text(item.accessGroup) }
            }
            
            Section(header: Text("数据内容 (可修改)")) {
                TextEditor(text: $editedData)
                    .frame(height: 100)
            }
            
            Button("保存修改") {
                updateItem()
            }
            .foregroundColor(.red)
        }
        .navigationTitle("详情")
        .onAppear { editedData = item.dataString }
    }
    
    // MARK: - 核心：更新逻辑
    func updateItem() {
        guard let data = editedData.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: item.itemClass,
            kSecAttrService as String: item.service,
            kSecAttrAccount as String: item.account,
            kSecAttrAccessGroup as String: targetGroup
        ]
        
        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess {
            onUpdate()
            presentationMode.wrappedValue.dismiss()
        }
    }
}

// 添加页面
struct AddItemView: View {
    let targetGroup: String
    var onSave: () -> Void
    @Environment(\.presentationMode) var presentationMode
    
    @State private var service = ""
    @State private var account = ""
    @State private var dataStr = ""
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("新增条目")) {
                    TextField("Service (包名)", text: $service)
                    TextField("Account (账号)", text: $account)
                    TextField("Data (密码/Token)", text: $dataStr)
                }
                Section(footer: Text("将强制写入组: \(targetGroup)")) {}
            }
            .navigationTitle("添加数据")
            .toolbar {
                Button("保存") { save() }
            }
        }
    }
    
    // MARK: - 核心：新增逻辑
    func save() {
        guard let data = dataStr.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessGroup as String: targetGroup // 强制指定组
        ]
        
        SecItemAdd(query as CFDictionary, nil)
        onSave()
        presentationMode.wrappedValue.dismiss()
    }
}
