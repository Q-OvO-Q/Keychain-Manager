import SwiftUI
import Security

// MARK: - 数据模型
struct KeychainItem: Identifiable, Hashable {
    let id = UUID()
    let itemClass: CFString // kSecClassGenericPassword 或 kSecClassInternetPassword
    let itemClassDisplay: String // "通用" 或 "网络"
    
    // 核心标识
    let title: String   // genp用service, inet用server
    let account: String
    let accessGroup: String
    
    // 数据
    let rawData: Data
    let isStringData: Bool // 是否原本就是文本
    
    // 所有原始属性 (用于展示详情)
    let rawAttributes: [String: String]
}

// MARK: - 主视图
struct ContentView: View {
    @AppStorage("targetAccessGroup") private var targetGroup: String = ""
    @State private var items: [KeychainItem] = []
    @State private var statusMessage = "输入 TeamID.* 后点击刷新"
    
    var body: some View {
        NavigationView {
            VStack {
                // 顶部输入区
                VStack(spacing: 8) {
                    TextField("Access Group (例如 ZYVN.com.test 或 ZYVN.*)", text: $targetGroup)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .padding(.horizontal)
                    
                    HStack {
                        Button("刷新列表") { fetchItems() }
                            .buttonStyle(.borderedProminent)
                        Button("清空显示") { items.removeAll() }
                            .buttonStyle(.bordered)
                    }
                    Text(statusMessage).font(.caption).foregroundColor(.gray)
                }
                .padding(.top, 10)
                
                // 列表区
                List {
                    ForEach(items) { item in
                        NavigationLink(destination: ItemDetailView(item: item, targetGroup: targetGroup, onUpdate: fetchItems)) {
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        // 类型标签
                                        Text(item.itemClassDisplay)
                                            .font(.system(size: 10, weight: .bold))
                                            .padding(3)
                                            .background(item.itemClassDisplay == "网络" ? Color.green.opacity(0.2) : Color.blue.opacity(0.2))
                                            .cornerRadius(4)
                                        
                                        Text(item.title) // Service 或 Server
                                            .font(.headline)
                                            .lineLimit(1)
                                    }
                                    
                                    Text(item.account.isEmpty ? "无账号" : item.account)
                                        .font(.subheadline)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                // 右侧显示一小段数据预览
                                Text(item.isStringData ? String(data: item.rawData, encoding: .utf8)! : "HEX")
                                    .font(.caption)
                                    .foregroundColor(.gray)
                                    .frame(width: 40)
                            }
                        }
                    }
                    .onDelete(perform: deleteItems)
                }
                .listStyle(.plain)
            }
            .navigationTitle("Keychain Manager")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    NavigationLink(destination: AddItemView(targetGroup: targetGroup, onSave: fetchItems)) {
                        Image(systemName: "plus")
                    }
                }
            }
        }
    }
    
    // MARK: - 查询逻辑 (核心优化)
    func fetchItems() {
        if targetGroup.isEmpty {
            statusMessage = "请输入目标 Group"
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
                kSecAttrAccessGroup as String: targetGroup
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            if status == errSecSuccess, let results = result as? [[String: Any]] {
                for res in results {
                    newItems.append(parseItem(res, secClass: secClass))
                }
            }
        }
        
        DispatchQueue.main.async {
            self.items = newItems
            self.statusMessage = "找到 \(newItems.count) 条数据"
        }
    }
    
    // 解析单条数据
    func parseItem(_ dict: [String: Any], secClass: CFString) -> KeychainItem {
        // 1. 提取所有属性用于展示
        var attributes: [String: String] = [:]
        for (key, value) in dict {
            attributes[key] = "\(value)"
        }
        
        // 2. 识别关键字段
        let account = dict[kSecAttrAccount as String] as? String ?? ""
        let group = dict[kSecAttrAccessGroup as String] as? String ?? ""
        let data = dict[kSecValueData as String] as? Data ?? Data()
        
        // 3. 处理标题：网络密码用 Server，通用密码用 Service
        var title = "未知"
        let classDisplay: String
        
        if secClass == kSecClassInternetPassword {
            classDisplay = "网络"
            if let server = dict[kSecAttrServer as String] as? String {
                title = server
            } else {
                title = "未知 Server"
            }
        } else {
            classDisplay = "通用"
            if let service = dict[kSecAttrService as String] as? String {
                title = service
            } else {
                title = "未知 Service"
            }
        }
        
        // 4. 判断数据是否为纯文本
        // 尝试转UTF8，如果转不出来，或者包含大量不可见字符，就视为二进制
        let isString = (String(data: data, encoding: .utf8) != nil)
        
        return KeychainItem(
            itemClass: secClass,
            itemClassDisplay: classDisplay,
            title: title,
            account: account,
            accessGroup: group,
            rawData: data,
            isStringData: isString,
            rawAttributes: attributes
        )
    }
    
    func deleteItems(at offsets: IndexSet) {
        for index in offsets {
            let item = items[index]
            // 删除时必须精准匹配所有主键
            var query: [String: Any] = [
                kSecClass as String: item.itemClass,
                kSecAttrAccount as String: item.account,
                kSecAttrAccessGroup as String: targetGroup
            ]
            
            if item.itemClass == kSecClassInternetPassword {
                query[kSecAttrServer as String] = item.title
            } else {
                query[kSecAttrService as String] = item.title
            }
            
            SecItemDelete(query as CFDictionary)
        }
        items.remove(atOffsets: offsets)
    }
}

// MARK: - 详情与修改页 (支持 Hex)
struct ItemDetailView: View {
    let item: KeychainItem
    let targetGroup: String
    var onUpdate: () -> Void
    
    @State private var contentString: String = ""
    @State private var isEditingHex: Bool = false
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        Form {
            // 基础信息区
            Section(header: Text("核心识别信息 (不可改)")) {
                LabeledContent("类型", value: item.itemClassDisplay)
                LabeledContent("标识 (Svc/Svr)", value: item.title)
                LabeledContent("账号 (Account)", value: item.account)
                LabeledContent("组 (Group)", value: item.accessGroup)
            }
            
            // 数据编辑区
            Section(header: Text("加密数据 (Data)")) {
                Picker("编辑模式", selection: $isEditingHex) {
                    Text("文本 (UTF8)").tag(false)
                    Text("十六进制 (Hex)").tag(true)
                }
                .pickerStyle(.segmented)
                .padding(.bottom, 5)
                
                TextEditor(text: $contentString)
                    .frame(height: 120)
                    .font(.system(.body, design: .monospaced)) // 等宽字体方便看 Hex
                    .onChange(of: isEditingHex) { newValue in
                        // 切换模式时转换当前显示的内容
                        if newValue {
                            // 文本 -> Hex
                            if let data = contentString.data(using: .utf8) {
                                contentString = data.hexString
                            }
                        } else {
                            // Hex -> 文本
                            if let data = contentString.hexData, let str = String(data: data, encoding: .utf8) {
                                contentString = str
                            } else {
                                contentString = "无法转为 UTF8，请切回 Hex 模式"
                            }
                        }
                    }
                
                Button("保存修改") {
                    saveChanges()
                }
                .frame(maxWidth: .infinity)
                .foregroundColor(.red)
            }
            
            // 完整属性展示区
            Section(header: Text("所有元数据 (All Attributes)")) {
                ForEach(item.rawAttributes.sorted(by: <), id: \.key) { key, value in
                    VStack(alignment: .leading) {
                        Text(key)
                            .font(.caption)
                            .foregroundColor(.blue)
                        Text(value)
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .navigationTitle("Item 详情")
        .onAppear {
            // 初始化显示
            if item.isStringData {
                contentString = String(data: item.rawData, encoding: .utf8) ?? ""
                isEditingHex = false
            } else {
                contentString = item.rawData.hexString
                isEditingHex = true
            }
        }
    }
    
    func saveChanges() {
        var finalData: Data?
        
        if isEditingHex {
            finalData = contentString.hexData
        } else {
            finalData = contentString.data(using: .utf8)
        }
        
        guard let dataToSave = finalData else { return }
        
        // 构造查询主键
        var query: [String: Any] = [
            kSecClass as String: item.itemClass,
            kSecAttrAccount as String: item.account,
            kSecAttrAccessGroup as String: targetGroup
        ]
        
        if item.itemClass == kSecClassInternetPassword {
            query[kSecAttrServer as String] = item.title
        } else {
            query[kSecAttrService as String] = item.title
        }
        
        let attributes: [String: Any] = [
            kSecValueData as String: dataToSave
        ]
        
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess {
            onUpdate()
            presentationMode.wrappedValue.dismiss()
        } else {
            print("保存失败: \(status)")
        }
    }
}

// MARK: - 新增页面 (简单版)
struct AddItemView: View {
    let targetGroup: String
    var onSave: () -> Void
    @Environment(\.presentationMode) var pm
    
    @State private var type = 0 // 0: Genp, 1: Inet
    @State private var service = ""
    @State private var account = ""
    @State private var dataStr = ""
    
    var body: some View {
        Form {
            Section {
                Picker("类型", selection: $type) {
                    Text("通用 (Generic)").tag(0)
                    Text("网络 (Internet)").tag(1)
                }
            }
            
            Section(header: Text(type == 0 ? "Service (服务名)" : "Server (服务器地址)")) {
                TextField(type == 0 ? "如 com.tencent.xin" : "如 google.com", text: $service)
            }
            
            Section(header: Text("Account (账号)")) {
                TextField("用户名/Email", text: $account)
            }
            
            Section(header: Text("Data (密码/数据)")) {
                TextField("内容", text: $dataStr)
            }
            
            Button("保存") {
                let data = dataStr.data(using: .utf8)!
                var query: [String: Any] = [
                    kSecClass as String: (type == 0 ? kSecClassGenericPassword : kSecClassInternetPassword),
                    kSecAttrAccount as String: account,
                    kSecValueData as String: data,
                    kSecAttrAccessGroup as String: targetGroup
                ]
                
                if type == 0 {
                    query[kSecAttrService as String] = service
                } else {
                    query[kSecAttrServer as String] = service
                }
                
                SecItemAdd(query as CFDictionary, nil)
                onSave()
                pm.wrappedValue.dismiss()
            }
        }
        .navigationTitle("新增条目")
    }
}
