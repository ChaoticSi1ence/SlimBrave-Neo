# 06. Presets 与配置格式

## 文件位置

预置配置目录：[Presets/](file:///workspace/Presets)

这些 JSON 文件既可作为“预置 Preset”，也可作为导入/导出时的跨平台配置载体。

## 配置 Schema（推荐的新格式）

顶层结构：

```json
{
  "Features": {
    "<PolicyKey>": "<PolicyValue>",
    "...": "..."
  },
  "DnsMode": "automatic | off | secure | custom",
  "DnsTemplates": "https://.../dns-query"
}
```

字段含义：

- `Features`（必选）：策略键值映射（policyKey → value）
  - key 为 Chromium/Brave managed policy 的名字（例如 `MetricsReportingEnabled`）
  - value 为对应策略值（bool / number / string / array）
- `DnsMode`（可选）：DoH 模式（与 UI/CLI 一致）
- `DnsTemplates`（可选）：DoH 模板 URL；在 `DnsMode=custom`（或 secure 且希望指定模板）时使用

示例：

- [Maximum Privacy Preset.json](file:///workspace/Presets/Maximum%20Privacy%20Preset.json)
- [Strict Parental Controls Preset.json](file:///workspace/Presets/Strict%20Parental%20Controls%20Preset.json)

## 旧格式（legacy）：Features 数组

项目在导入逻辑中兼容旧格式：

```json
{ "Features": ["MetricsReportingEnabled", "QuicAllowed"] }
```

注意：该格式无法表达“同一个 policyKey 对应多个可能值”的场景（例如 `IncognitoModeAvailability` 的 1/2），因此导入时采用“每个 key 只匹配第一个 row”来规避误选。

实现：

- Python：`_parse_imported_features` + `import_settings`  
  [slimbrave-linux.py:L443-L507](file:///workspace/slimbrave-linux.py#L443-L507)
- Windows：Import 分支  
  [SlimBrave.ps1:L646-L662](file:///workspace/SlimBrave.ps1#L646-L662)

## 多值策略示例：IncognitoModeAvailability

该 key 在不同 value 下含义不同（并且互斥）：

- `1`：Disable Incognito
- `2`：Force Incognito

Python 通过 `group="incognito"` 实现互斥：

- [slimbrave-linux.py:L169-L170](file:///workspace/slimbrave-linux.py#L169-L170)

预置示例：

- Maximum Privacy：`IncognitoModeAvailability: 2`  
  [Maximum Privacy Preset.json:L23](file:///workspace/Presets/Maximum%20Privacy%20Preset.json#L23)
- Strict Parental Controls：`IncognitoModeAvailability: 1`  
  [Strict Parental Controls Preset.json:L5](file:///workspace/Presets/Strict%20Parental%20Controls%20Preset.json#L5)

## 列表型策略（List Policy）

部分策略的 value 为数组（例如 `BraveShieldsDisabledForUrls` 在 Python 中对应 `["https://*", "http://*"]`）：

- Python Feature 定义： [slimbrave-linux.py:L174-L190](file:///workspace/slimbrave-linux.py#L174-L190)

平台差异：

- Linux/macOS：策略文件支持 JSON array / plist array，直接写入即可
- Windows：需要写入注册表子键 + 数字序号项，代码通过 `Set-ListPolicy` 处理  
  [SlimBrave.ps1:L64-L83](file:///workspace/SlimBrave.ps1#L64-L83)

