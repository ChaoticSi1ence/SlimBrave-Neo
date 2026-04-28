# 08. 安全与边界

## 官方分发边界

仓库明确声明只发布源码脚本，不包含任何编译产物或安装包：

- [SECURITY.md:L13-L26](file:///workspace/SECURITY.md#L13-L26)

这也意味着“代码审计面”非常集中：三平台入口脚本 + Presets JSON 即全部攻击面。

## root/管理员执行的安全护栏

Linux/macOS 的脚本必须 root 执行（写系统策略路径），因此仓库实现了两类关键防护：

### 1) `--policy-file` 路径白名单限制

如果允许任意 `--policy-file`，配合 `--reset` 可能导致在宽松的 sudoers 配置下删除任意文件。

因此脚本限制 `--policy-file` 必须落在允许目录下：

- Linux 允许目录常量： [slimbrave-linux.py:L31-L34](file:///workspace/slimbrave-linux.py#L31-L34)
- 校验函数： [slimbrave-linux.py:L37-L46](file:///workspace/slimbrave-linux.py#L37-L46)
- 入口处校验与拒绝： [slimbrave-linux.py:L1101-L1111](file:///workspace/slimbrave-linux.py#L1101-L1111)

macOS 同样实现允许目录与校验逻辑：

- [slimbrave-mac.py:L22-L56](file:///workspace/slimbrave-mac.py#L22-L56)

### 2) 原子写入与防符号链接攻击（anti-symlink）

`_atomic_write()` 使用 `tempfile.mkstemp` + `os.replace`，用于同时规避：

- 符号链接竞争（symlink race）/ 符号链接覆盖
- 进程中途退出导致策略文件半写入

实现：

- Linux： [slimbrave-linux.py:L49-L70](file:///workspace/slimbrave-linux.py#L49-L70)
- macOS： [slimbrave-mac.py:L59-L80](file:///workspace/slimbrave-mac.py#L59-L80)

## 配置文件输入的兼容性处理

跨平台导入/导出共享 JSON 配置，但 PowerShell 的输出可能包含 UTF-16 BOM。Python 端在导入时按 BOM 自动解码并剔除 `\x00`，降低“导入失败/解析异常”的风险：

- Linux `read_json_file`： [slimbrave-linux.py:L287-L307](file:///workspace/slimbrave-linux.py#L287-L307)

## 功能边界（不做什么）

- 不修改 Brave 安装目录文件、不注入扩展、不使用 hook/hack
- 只写托管策略（managed policies）；最终的生效依赖 Brave 自身按平台规范读取这些策略

参考说明：

- [README.md:L215-L228](file:///workspace/README.md#L215-L228)
