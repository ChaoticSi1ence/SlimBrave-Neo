# 03. 策略模型（托管策略）

## 背景：Chromium/Brave 托管策略

SlimBrave Neo 的核心行为是写入 Chromium 的“企业托管策略”，Brave 启动时会读取这些策略并将其视为托管配置，从而在界面中锁定/强制某些选项。

- 文档说明：[README.md:L215-L228](file:///workspace/README.md#L215-L228)
- 策略可在 Brave 内部页面检查：`brave://policy`

## 三平台策略落点

- Linux（JSON 文件）
  - 默认目录：`/etc/brave/policies/managed`
  - 默认文件：`/etc/brave/policies/managed/slimbrave.json`
  - 常量定义：[slimbrave-linux.py:L23-L25](file:///workspace/slimbrave-linux.py#L23-L25)

- macOS（plist 文件）
  - 默认目录：`/Library/Managed Preferences`
  - 默认文件：`/Library/Managed Preferences/com.brave.Browser.plist`
  - 常量定义：[slimbrave-mac.py:L22-L27](file:///workspace/slimbrave-mac.py#L22-L27)

- Windows（注册表）
  - 机器策略：`HKLM:\SOFTWARE\Policies\BraveSoftware\Brave`
  - 用户策略：`HKCU:\SOFTWARE\Policies\BraveSoftware\Brave`
  - 路径定义：[SlimBrave.ps1:L9-L12](file:///workspace/SlimBrave.ps1#L9-L12)

## 策略数据模型（抽象）

该项目将策略抽象为：

- **功能项（Feature）**：一个可勾选的策略键值对（policyKey → value）
- **DnsMode / DnsTemplates**：DNS over HTTPS（DoH）的模式选择与模板 URL

Python 端使用 `CATEGORIES` 列表描述功能项（Feature）集合，并在 TUI 渲染为可勾选行：

- Feature 定义集合： [slimbrave-linux.py:L140-L206](file:///workspace/slimbrave-linux.py#L140-L206)
- 扁平化为行（rows）： [slimbrave-linux.py:L220-L249](file:///workspace/slimbrave-linux.py#L220-L249)

## DNS over HTTPS（DoH）规则

### 用户层面的模式

脚本与配置文件对 DNS 模式使用统一枚举：

`automatic | off | secure | custom`

定义见：

- Linux/macOS：`DNS_MODES` [slimbrave-linux.py:L208-L209](file:///workspace/slimbrave-linux.py#L208-L209)

### 实际写入的 Chromium 策略键

Chromium 对应策略键：

- `DnsOverHttpsMode`
- `DnsOverHttpsTemplates`

并且存在一个重要映射：

- 当用户选择 `custom` 时，实际写入 `DnsOverHttpsMode = "secure"`，同时写 `DnsOverHttpsTemplates = <url>`

实现位置：

- Linux `apply_policy`：[slimbrave-linux.py:L323-L360](file:///workspace/slimbrave-linux.py#L323-L360)
- Windows `Set-DnsSettings`：[SlimBrave.ps1:L23-L52](file:///workspace/SlimBrave.ps1#L23-L52)

### 失败保护

为了避免写入“DNS 断网”策略（custom 但没填模板 URL），Python 端会拒绝写入并返回错误信息：

- [slimbrave-linux.py:L336-L351](file:///workspace/slimbrave-linux.py#L336-L351)

## 原子写入（避免部分写入与符号链接风险）

Linux/macOS 的策略落盘使用 `_atomic_write()`：

- 在同目录创建 `mkstemp` 临时文件（O_EXCL），避免被符号链接劫持
- `os.replace` 原子替换目标文件，避免写一半进程退出导致策略文件损坏

实现：

- Linux：[slimbrave-linux.py:L49-L70](file:///workspace/slimbrave-linux.py#L49-L70)
- macOS（同名实现）：[slimbrave-mac.py:L59-L80](file:///workspace/slimbrave-mac.py#L59-L80)
