# Keychain Manager

一个用于查看、编辑、标记、删除、批量导入和导出 iOS Keychain 条目的 SwiftUI 工具。

## 功能

- 枚举通用密码（genp）、网络密码（inet）、密钥（key）、证书（cert）四类条目
- 查看条目的全部元数据，数据支持 UTF-8 / 十六进制双模式查看与修改
- 按 App 打标签，支持标签筛选、批量打标签 / 取消标签 / 删除
- 全文搜索（标题、账号、Access Group、标签、内容）
- 从内嵌的 `embedded.mobileprovision` 自动识别可用的 Keychain Access Group
- 以json格式批量导入和导出Keychain Items

## 构建

项目用 [XcodeGen](https://github.com/yonaskolb/XcodeGen) 生成工程：

```bash
xcodegen generate && open KeychainManager.xcodeproj
```

推送到 `main` 会触发 GitHub Actions 构建一个未签名的 IPA（见 `.github/workflows/build.yml`）。

## 关于 Access Group 与权限

Keychain 的可见范围完全由**签名时的 entitlements** 决定，与本工具无关：

- **全部可访问**（默认）：查询时不指定 `kSecAttrAccessGroup`，返回本应用有权访问的所有条目。
  这是最可靠的模式，建议优先使用。
- **指定 Access Group**：只有 entitlements 里已声明的组才查得到，否则返回
  `errSecMissingEntitlement (-34018)`，界面会直接显示该错误。
- 通配符组 `TEAMID.*` 需要签名时确实授予了通配符 keychain-access-groups 权限；

要看到其它 App 的条目，需要用带相应 keychain-access-groups 的证书和entitlements文件重签名。
