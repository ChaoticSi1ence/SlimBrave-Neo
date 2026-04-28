# 05. Windows PowerShell 实现

Windows 版本入口脚本：[SlimBrave.ps1](file:///workspace/SlimBrave.ps1)

该脚本以 WinForms GUI 的形式提供勾选项，并把选择写入 Brave 的 Windows 托管策略注册表路径。

## 启动与权限模型

脚本开头强制管理员权限：

- 若非管理员，则使用 `Start-Process ... -Verb RunAs` 触发 UAC 提权并退出当前进程  
  [SlimBrave.ps1:L1-L4](file:///workspace/SlimBrave.ps1#L1-L4)

GUI 依赖 .NET：

- `Add-Type -AssemblyName System.Windows.Forms / System.Drawing`  
  [SlimBrave.ps1:L6-L7](file:///workspace/SlimBrave.ps1#L6-L7)

## 策略落点（Registry）

- Machine scope（优先）：`HKLM:\SOFTWARE\Policies\BraveSoftware\Brave`
- User scope（兜底）：`HKCU:\SOFTWARE\Policies\BraveSoftware\Brave`

定义：

- [SlimBrave.ps1:L9-L12](file:///workspace/SlimBrave.ps1#L9-L12)

脚本会确保 machine key 存在：

- [SlimBrave.ps1:L13-L15](file:///workspace/SlimBrave.ps1#L13-L15)

## 关键辅助函数

### Set-DnsSettings

职责：写入 `DnsOverHttpsMode` 与（可选）`DnsOverHttpsTemplates`。

关键规则：

- 当用户选择 `custom` 时，强制要求 templates 非空，否则弹窗并返回失败
- `custom` 映射为 `DnsOverHttpsMode="secure"`，并写 templates

实现：

- [SlimBrave.ps1:L23-L52](file:///workspace/SlimBrave.ps1#L23-L52)

### Set-ListPolicy / Remove-ListPolicy

Chromium 在 Windows 上对“列表型策略”采用子键 + 数字序号的写法（而不是 JSON 数组字符串）。

该仓库将 list policy 写入为：

- `...\<PolicyName>\1 = "..."`  
- `...\<PolicyName>\2 = "..."`  

实现与注释：

- Set： [SlimBrave.ps1:L64-L83](file:///workspace/SlimBrave.ps1#L64-L83)
- Remove： [SlimBrave.ps1:L85-L97](file:///workspace/SlimBrave.ps1#L85-L97)

### Test-FeatureValueMatches / Test-ListPolicyMatches

用于“初始化回显”和“导入 dict 格式配置”时的值匹配：

- `Test-FeatureValueMatches`：DWord 做 int 比较；List 类型始终视为匹配（导入时只需 key 存在即可）  
  [SlimBrave.ps1:L99-L111](file:///workspace/SlimBrave.ps1#L99-L111)
- `Test-ListPolicyMatches`：读取子键项并与期望列表做包含关系判断  
  [SlimBrave.ps1:L113-L131](file:///workspace/SlimBrave.ps1#L113-L131)

## GUI 交互与核心行为

Windows 版本没有独立的“模块划分”，主要由 UI 构建代码 + 事件回调组成。

### Apply（应用设置）

Apply 的关键动作是遍历所有勾选项，按类型写入：

- DWord/String：`Set-ItemProperty`
- List：`Set-ListPolicy`
- DNS：`Set-DnsSettings`

Apply 回调片段可从这里开始向上追溯（包含对 DNS 的调用）：  
[SlimBrave.ps1:L507-L521](file:///workspace/SlimBrave.ps1#L507-L521)

### Reset（清空策略）

Reset 会删除 machine scope 的 registry tree，并在存在时删除 user scope，然后重新创建 machine key：

- [SlimBrave.ps1:L527-L562](file:///workspace/SlimBrave.ps1#L527-L562)

并在成功后取消勾选与重置 DNS 控件：

- [SlimBrave.ps1:L564-L576](file:///workspace/SlimBrave.ps1#L564-L576)

### Export（导出配置）

导出 JSON 使用“新 Features dict 格式”，确保多值策略可 round-trip：

- `Features` 为 ordered map：`policyKey -> value`
- 输出 `DnsMode` 与 `DnsTemplates`

实现：

- [SlimBrave.ps1:L583-L624](file:///workspace/SlimBrave.ps1#L583-L624)

注意：PowerShell 的 `Out-File` 编码行为会导致 Python 侧需要 BOM/UTF-16 兼容读取（见 [04](./04-python-linux-macos.md) 的 `read_json_file`）。

### Import（导入配置）

导入兼容两种格式：

- legacy：`Features` 为数组（只表示启用 key）；并用“每个 key 只应用第一次匹配”规避多值策略误选  
  [SlimBrave.ps1:L646-L662](file:///workspace/SlimBrave.ps1#L646-L662)
- 新格式：`Features` 为对象（key-value），并用 `Test-FeatureValueMatches` 判断值是否一致  
  [SlimBrave.ps1:L662-L672](file:///workspace/SlimBrave.ps1#L662-L672)

DNS mode/templates 也会一并导入与回填：

- [SlimBrave.ps1:L674-L685](file:///workspace/SlimBrave.ps1#L674-L685)

## 启动初始化：读取当前策略并预勾选

`Initialize-CurrentSettings` 会从 HKLM/HKCU 读取当前策略，并把匹配的项勾选上；HKLM 优先，HKCU 兜底：

- 实现：[SlimBrave.ps1:L708-L768](file:///workspace/SlimBrave.ps1#L708-L768)

脚本末尾执行初始化并打开窗体：

- [SlimBrave.ps1:L770-L772](file:///workspace/SlimBrave.ps1#L770-L772)

