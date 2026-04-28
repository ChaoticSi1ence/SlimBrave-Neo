# 02. 仓库结构

## 顶层目录

仓库根目录：[workspace/](file:///workspace)

```
/
├── Presets/                         # 跨平台预置配置（JSON，可导入/导出）
├── assets/                          # 截图等资源
├── slimbrave-linux.py               # Linux 版本：curses TUI + CLI（需要 root）
├── slimbrave-mac.py                 # macOS 版本：curses TUI + CLI（需要 root，写 plist）
├── SlimBrave.ps1                    # Windows 版本：WinForms GUI（需要管理员）
├── README.md                        # 使用说明与快速开始
├── SECURITY.md                      # 官方分发与安全政策
└── LICENSE
```

## 运行入口

- Linux：脚本入口与 CLI/TUI 分流位于 [slimbrave-linux.py:L1098-L1138](file:///workspace/slimbrave-linux.py#L1098-L1138)
- macOS：脚本入口与 CLI/TUI 分流位于 [slimbrave-mac.py:L1135-L1175](file:///workspace/slimbrave-mac.py#L1135-L1175)
- Windows：脚本开头执行提权与 GUI 初始化位于 [SlimBrave.ps1:L1-L16](file:///workspace/SlimBrave.ps1#L1-L16)

## 预置配置（Presets）

预置目录（Presets）：[Presets/](file:///workspace/Presets)

- 预置文件采用统一 JSON 格式（详见 [06. 预置与配置格式](./06-presets-config.md)）
- 示例：
  - [Maximum Privacy Preset.json](file:///workspace/Presets/Maximum%20Privacy%20Preset.json)（最大隐私）
  - [Strict Parental Controls Preset.json](file:///workspace/Presets/Strict%20Parental%20Controls%20Preset.json)（严格家长控制）
