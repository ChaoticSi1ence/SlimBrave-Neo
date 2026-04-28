# 04. Python 端（Linux/macOS）实现

该部分覆盖两份 Python 脚本：

- Linux：[slimbrave-linux.py](file:///workspace/slimbrave-linux.py)
- macOS：[slimbrave-mac.py](file:///workspace/slimbrave-mac.py)

两者结构高度一致：同一套 TUI/CLI/导入导出逻辑；差异主要在策略落点（Linux 写 JSON 文件，macOS 写 plist 文件）以及 macOS 的 Brave 检测逻辑。

## 模块结构（从上到下）

以 Linux 脚本为例（macOS 结构相同）：

1. 常量与安全约束（策略路径、允许目录）
2. 文件写入工具：`_atomic_write`
3. Brave 安装检测：`detect_brave`
4. Feature 定义：`CATEGORIES` → `build_rows`
5. Policy I/O：`load_existing_policy / apply_policy / reset_policy / sync_rows_with_policy`
6. Config I/O（导入/导出）：`read_json_file / export_settings / import_settings`
7. TUI：`draw / prompt_text_input / main` 等
8. CLI：`cli_import / cli_export / cli_reset / parse_args`
9. 入口：`if __name__ == "__main__":` 负责 root 校验 + CLI/TUI 分流

## 核心数据结构：rows（TUI 行模型）

`build_rows()` 会把分类与功能项扁平化成一维数组 `rows`，每个元素是 dict，包含：

- Header 行：`{"type": ROW_HEADER, "text": ...}`
- Feature 行：`{"type": ROW_FEATURE, "key": policyKey, "value": policyValue, "checked": bool, "group": ...}`
- DNS 行：`{"type": ROW_DNS, "options": DNS_MODES, "selected": index}`
- DNS Template 行：`{"type": ROW_DNS_TEMPLATE, "value": url, "cursor": int, "scroll": int}`

定义与构造：

- 行类型常量与 `build_rows()`：[slimbrave-linux.py:L214-L249](file:///workspace/slimbrave-linux.py#L214-L249)

`group` 用于互斥项（目前用于 `IncognitoModeAvailability` 的 disable vs force）：

- 说明与定义：[slimbrave-linux.py:L136-L170](file:///workspace/slimbrave-linux.py#L136-L170)

## 关键流程（调用链）

### 入口分流（CLI vs TUI）

入口位于：

- Linux：[slimbrave-linux.py:L1098-L1138](file:///workspace/slimbrave-linux.py#L1098-L1138)
- macOS：[slimbrave-mac.py:L1135-L1175](file:///workspace/slimbrave-mac.py#L1135-L1175)

核心逻辑：

1. `parse_args()` 解析 `--import/--export/--reset/--policy-file/--doh-templates`
2. 若指定 `--policy-file`：校验路径必须位于允许目录（防止 root 下任意文件删除/覆盖）
3. 必须 root 执行（Linux/macOS 均检查 `os.geteuid() == 0`）
4. 有 CLI 参数则走 `cli_*`；否则 `curses.wrapper(main)` 进入 TUI

### TUI 启动序列

`main(stdscr)` 的启动序列（Linux，macOS 同结构）：

- `rows = build_rows()`
- `brave_info = detect_brave()`（用于标题显示与启动提示）
- `policy = load_existing_policy()` 读取系统上已有策略
- `sync_rows_with_policy(rows, policy)` 把现有策略回显为勾选状态
- 进入循环：渲染 `draw()` → 读取按键 → 更新 rows / 执行按钮动作

对应代码：

- `main` 开始部分：[slimbrave-linux.py:L757-L789](file:///workspace/slimbrave-linux.py#L757-L789)

### “Apply” 按钮做了什么

当用户在 TUI 点击 Apply：

1. 校验 DoH：custom 模式必须有 template URL
2. `apply_policy(rows)` 将 rows 转为 policy dict
3. `_atomic_write` 原子写入到系统策略路径

逻辑分散在：

- Apply 时校验：`main` 内分支 [slimbrave-linux.py:L974-L987](file:///workspace/slimbrave-linux.py#L974-L987)
- 实际落盘：`apply_policy` [slimbrave-linux.py:L323-L360](file:///workspace/slimbrave-linux.py#L323-L360)
- 原子写入：`_atomic_write` [slimbrave-linux.py:L49-L70](file:///workspace/slimbrave-linux.py#L49-L70)

## Policy I/O（策略读写）

### load_existing_policy

- Linux：读取 JSON 文件，失败返回空 dict：[slimbrave-linux.py:L314-L321](file:///workspace/slimbrave-linux.py#L314-L321)
- macOS：根据 `IS_MAC` 读取 plist（`plistlib.load`）或 JSON：[slimbrave-mac.py:L342-L355](file:///workspace/slimbrave-mac.py#L342-L355)

### apply_policy

职责：把 `rows` 中勾选项转换为 policy dict 并落盘。

关键点：

- 只写被勾选的 Feature（未勾选则不出现在 policy 中）
- DNS 模式 `custom` → 写入 `DnsOverHttpsMode="secure"` + `DnsOverHttpsTemplates=<url>`
- Linux 写 JSON；macOS 写 plist bytes（`plistlib.dumps`）

实现：

- Linux：[slimbrave-linux.py:L323-L360](file:///workspace/slimbrave-linux.py#L323-L360)
- macOS：[slimbrave-mac.py:L357-L397](file:///workspace/slimbrave-mac.py#L357-L397)

### sync_rows_with_policy

职责：把磁盘/系统上已有策略“回显”为 rows 勾选态，用于启动时预选。

关键点：

- Feature：要求 `policy[key] == row["value"]` 才勾选（避免同 key 多值时误选）
- DNS：如果 `DnsOverHttpsMode == "secure"` 且 templates 不为空，则 UI 显示为 `custom`

实现：

- Linux：[slimbrave-linux.py:L381-L403](file:///workspace/slimbrave-linux.py#L381-L403)
- macOS：[slimbrave-mac.py:L418-L440](file:///workspace/slimbrave-mac.py#L418-L440)

## Config I/O（导入/导出）

### read_json_file（BOM/编码兼容）

Windows PowerShell 的 `Out-File` 可能产生 UTF-16 BOM；因此 Python 导入时按 BOM 自动解码并清理 `\x00`：

- [slimbrave-linux.py:L287-L307](file:///workspace/slimbrave-linux.py#L287-L307)

### export_settings（导出）

导出文件结构示例：

```json
{
  "Features": { "MetricsReportingEnabled": false, "...": "..." },
  "DnsMode": "custom",
  "DnsTemplates": "https://example/dns-query"
}
```

实现：

- Linux：[slimbrave-linux.py:L409-L441](file:///workspace/slimbrave-linux.py#L409-L441)

### import_settings（导入）

导入兼容两种 `Features` 格式：

- 新格式（推荐）：object/dict，支持同 key 多值的精确回放
- 旧格式（legacy）：array/list，仅表示“启用该 key”，无法区分同 key 的不同 value；代码通过“每个 key 只匹配第一个 row”规避误选

实现：

- 解析 Features：`_parse_imported_features` [slimbrave-linux.py:L443-L457](file:///workspace/slimbrave-linux.py#L443-L457)
- 应用导入：`import_settings` [slimbrave-linux.py:L459-L507](file:///workspace/slimbrave-linux.py#L459-L507)

## CLI（非交互模式）

CLI 主要用于自动化脚本/配置管理：

- `cli_import(path, doh_templates="")`：导入 config → （可选覆盖 DoH templates）→ `apply_policy`  
  [slimbrave-linux.py:L1008-L1030](file:///workspace/slimbrave-linux.py#L1008-L1030)
- `cli_export(path)`：读取现有 policy → 同步到 rows → 导出 config  
  [slimbrave-linux.py:L1032-L1048](file:///workspace/slimbrave-linux.py#L1032-L1048)
- `cli_reset()`：删除 policy 文件  
  [slimbrave-linux.py:L1050-L1062](file:///workspace/slimbrave-linux.py#L1050-L1062)
- 参数定义：`parse_args()`  
  [slimbrave-linux.py:L1064-L1091](file:///workspace/slimbrave-linux.py#L1064-L1091)

## Linux vs macOS 差异点

- 策略格式
  - Linux：JSON 字符串写入
  - macOS：plist bytes 写入（`plistlib.dumps`）
  - 差异实现位于 macOS `apply_policy`：[slimbrave-mac.py:L386-L392](file:///workspace/slimbrave-mac.py#L386-L392)

- Brave 检测
  - macOS 检测 `/Applications/Brave Browser.app` 与用户目录 Application：[slimbrave-mac.py:L92-L108](file:///workspace/slimbrave-mac.py#L92-L108)
  - Linux 检测包含 arch/deb/rpm/flatpak/snap/PATH fallback：[slimbrave-linux.py:L77-L129](file:///workspace/slimbrave-linux.py#L77-L129)

