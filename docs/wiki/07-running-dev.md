# 07. 运行与开发

## 运行前提

该仓库不包含构建系统与依赖清单，运行方式即“直接执行脚本”（参见 [SECURITY.md](file:///workspace/SECURITY.md) 的 source-only 声明）。

### Linux

- Python 3（标准库即可）
- 需要 root（写入 `/etc/...` 托管策略目录）
- Brave Browser 已安装（用于实际生效；脚本仍可写策略文件）

### macOS

- Python 3（标准库即可，脚本会使用 `plistlib`）
- 需要 root（写入 `/Library/Managed Preferences/...`）
- Brave Browser 已安装

### Windows

- Windows 10/11 + PowerShell
- 需要管理员权限（UAC 提权）

## 快速开始（官方推荐命令）

来自 [README.md](file:///workspace/README.md)：

### Linux（TUI）

```bash
git clone https://github.com/ChaoticSi1ence/SlimBrave-Neo.git
cd SlimBrave-Neo
sudo python3 slimbrave-linux.py
```

### Linux（CLI）

```bash
sudo python3 slimbrave-linux.py --import "./Presets/Maximum Privacy Preset.json"
sudo python3 slimbrave-linux.py --export ~/SlimBraveNeoSettings.json
sudo python3 slimbrave-linux.py --reset
```

### macOS（TUI）

```bash
git clone https://github.com/ChaoticSi1ence/SlimBrave-Neo.git
cd SlimBrave-Neo
sudo python3 slimbrave-mac.py
```

### macOS（CLI）

```bash
sudo python3 slimbrave-mac.py --import "./Presets/Maximum Privacy Preset.json"
sudo python3 slimbrave-mac.py --export ~/SlimBraveNeoSettings.json
sudo python3 slimbrave-mac.py --reset
```

### Windows（一行下载并运行）

```powershell
iwr "https://raw.githubusercontent.com/ChaoticSi1ence/SlimBrave-Neo/main/SlimBrave.ps1" -OutFile "SlimBrave.ps1"; .\SlimBrave.ps1
```

## CLI 参数（Linux/macOS）

参数定义见：

- Linux：[slimbrave-linux.py:L1064-L1091](file:///workspace/slimbrave-linux.py#L1064-L1091)
- macOS：[slimbrave-mac.py:L1101-L1128](file:///workspace/slimbrave-mac.py#L1101-L1128)

常用项：

- `--import PATH`：导入配置并应用
- `--export PATH`：导出现有策略为配置文件
- `--reset`：删除策略文件
- `--policy-file PATH`：覆盖默认策略文件路径（受允许目录限制）
- `--doh-templates URL`：在导入后覆盖 DoH templates（用于脚本化）

## 验证生效

1. 执行 Apply / CLI import 后，重启 Brave
2. 打开 `brave://policy` 查看策略是否被识别为 managed policies

## 开发与调试建议（仓库视角）

该项目缺少单元测试与构建脚本，常见的本地验证方式：

- 直接运行 `python3 slimbrave-linux.py -h` 检查参数解析是否正常
- 在非 root 场景运行验证错误提示是否符合预期（脚本会拒绝执行）
- 在临时目录模拟 `--policy-file` 写入（注意：受允许目录限制）

