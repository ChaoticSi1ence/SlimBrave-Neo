#!/usr/bin/env python3
"""SlimBrave Neo - Linux TUI for debloating and hardening Brave Browser.

Sets Chromium enterprise policies via JSON files at
/etc/brave/policies/managed/slimbrave.json. Requires root.

Supports interactive curses TUI and non-interactive CLI usage:
  sudo python3 slimbrave.py                        # TUI
  sudo python3 slimbrave.py --import preset.json   # CLI import
  sudo python3 slimbrave.py --export out.json      # CLI export
  sudo python3 slimbrave.py --reset                # CLI reset
"""

import argparse
import curses
import json
import os
import shutil
import subprocess
import sys
import tempfile

POLICY_DIR = "/etc/brave/policies/managed"
POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")

# Directories a `--policy-file` argument is permitted to target. The flag
# runs with root, so an unvalidated path combined with `--reset` would let a
# permissive sudoers rule delete arbitrary files (e.g. `--policy-file
# /etc/shadow --reset`). Chromium only reads policies from these locations,
# so legitimate use does not need to point anywhere else.
ALLOWED_POLICY_DIRS = (
    "/etc/brave/policies/managed",
    "/etc/chromium/policies/managed",
)


def _is_within_allowed_policy_dir(path):
    """Return True if `path`'s realpath lives under an allowed policy dir."""
    real_path = os.path.realpath(path)
    for allowed in ALLOWED_POLICY_DIRS:
        real_allowed = (
            os.path.realpath(allowed) if os.path.exists(allowed) else allowed
        )
        if real_path.startswith(real_allowed + os.sep):
            return True
    return False


def _atomic_write(path, data, *, binary=False, mode=0o644):
    """Write `data` to `path` atomically via a same-directory tempfile.

    `tempfile.mkstemp` uses O_CREAT|O_EXCL so it cannot be tricked into
    writing through a symlink, and `os.replace` atomically replaces the
    target directory entry without following a symlink that happened to
    exist there. Fixes two classes of root footgun at once: symlink
    races and partial-state writes if the process is killed mid-write.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".slimbrave.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb" if binary else "w") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# ---------------------------------------------------------------------------
# Brave browser detection
# ---------------------------------------------------------------------------


def detect_brave():
    """Detect Brave browser installation and packaging method.

    Returns a dict with keys: found, method, path, warnings.
    """
    # Arch (brave-bin AUR package)
    arch_path = "/opt/brave-bin/brave"
    if os.path.isfile(arch_path):
        return {"found": True, "method": "arch", "path": arch_path, "warnings": []}

    # Deb / RPM (official brave-browser package)
    for p in ("/opt/brave.com/brave/brave-browser", "/opt/brave.com/brave/brave"):
        if os.path.isfile(p):
            return {"found": True, "method": "deb/rpm", "path": p, "warnings": []}

    # Flatpak (com.brave.Browser from Flathub)
    try:
        result = subprocess.run(
            ["flatpak", "info", "com.brave.Browser"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return {
                "found": True, "method": "flatpak",
                "path": "com.brave.Browser",
                "warnings": [],
            }
    except FileNotFoundError:
        pass  # flatpak not installed

    # Snap
    snap_path = "/snap/brave/current/opt/brave.com/brave/brave"
    if os.path.isfile(snap_path) or os.path.isdir("/snap/brave/current"):
        return {
            "found": True, "method": "snap", "path": snap_path,
            "warnings": [
                "Snap 沙盒限制可能导致策略无法生效。"
                "建议使用原生安装包版本。"
            ],
        }

    # Fallback - check PATH
    for name in ("brave-browser-stable", "brave-browser", "brave"):
        found = shutil.which(name)
        if found:
            return {"found": True, "method": "unknown", "path": found, "warnings": []}

    return {
        "found": False, "method": "not found", "path": "",
        "warnings": [
            "未检测到 Brave 浏览器。仍会写入策略，但可能不会生效。"
        ],
    }


# ---------------------------------------------------------------------------
# Feature definitions - mirrors the Windows SlimBrave Neo PS1 categories
# ---------------------------------------------------------------------------

# Features with a `group` key are mutually exclusive within that group:
# checking one silently unchecks the others. Used today for
# IncognitoModeAvailability, where Disable (=1) and Force (=2) are
# conflicting values for the same policy.
CATEGORIES = [
    {
        "name": "遥测与报告",
        "features": [
            {"name": "禁用指标上报", "key": "MetricsReportingEnabled", "value": False},
            {"name": "禁用安全浏览报告上报", "key": "SafeBrowsingExtendedReportingEnabled", "value": False},
            {"name": "禁用 URL 匿名化数据收集", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False},
            {"name": "禁用 P3A 分析", "key": "BraveP3AEnabled", "value": False},
            {"name": "禁用统计心跳（Stats Ping）", "key": "BraveStatsPingEnabled", "value": False},
        ],
    },
    {
        "name": "隐私与安全",
        "features": [
            {"name": "禁用安全浏览", "key": "SafeBrowsingProtectionLevel", "value": 0},
            {"name": "禁用自动填充（地址）", "key": "AutofillAddressEnabled", "value": False},
            {"name": "禁用自动填充（信用卡）", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "禁用密码管理器", "key": "PasswordManagerEnabled", "value": False},
            {"name": "禁用浏览器登录", "key": "BrowserSignin", "value": 0},
            {"name": "启用“请勿跟踪”", "key": "EnableDoNotTrack", "value": True},
            {"name": "启用全局隐私控制（GPC）", "key": "BraveGlobalPrivacyControlEnabled", "value": True},
            {"name": "启用 De-AMP（移除 AMP 包装）", "key": "BraveDeAmpEnabled", "value": True},
            {"name": "启用去跳转追踪（Debouncing）", "key": "BraveDebouncingEnabled", "value": True},
            {"name": "移除跟踪型 URL 参数", "key": "BraveTrackingQueryParametersFilteringEnabled", "value": True},
            {"name": "降低语言指纹", "key": "BraveReduceLanguageEnabled", "value": True},
            {"name": "防止 WebRTC IP 泄漏", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp"},
            {"name": "禁用 QUIC 协议", "key": "QuicAllowed", "value": False},
            {"name": "阻止第三方 Cookie", "key": "BlockThirdPartyCookies", "value": True},
            {"name": "强制 Google 安全搜索（SafeSearch）", "key": "ForceGoogleSafeSearch", "value": True},
            {"name": "禁用隐身模式", "key": "IncognitoModeAvailability", "value": 1, "group": "incognito"},
            {"name": "强制隐身模式", "key": "IncognitoModeAvailability", "value": 2, "group": "incognito"},
        ],
    },
    {
        "name": "Brave 功能",
        "features": [
            {"name": "禁用 Brave Rewards", "key": "BraveRewardsDisabled", "value": True},
            {"name": "禁用 Brave Wallet", "key": "BraveWalletDisabled", "value": True},
            {"name": "禁用 Brave VPN", "key": "BraveVPNDisabled", "value": True},
            {"name": "禁用 Brave AI Chat", "key": "BraveAIChatEnabled", "value": False},
            {"name": "禁用 Brave Shields", "key": "BraveShieldsDisabledForUrls", "value": ["https://*", "http://*"]},
            {"name": "禁用 Brave News", "key": "BraveNewsDisabled", "value": True},
            {"name": "禁用 Brave Talk", "key": "BraveTalkDisabled", "value": True},
            {"name": "禁用 Brave Playlist", "key": "BravePlaylistEnabled", "value": False},
            {"name": "禁用 Web Discovery", "key": "BraveWebDiscoveryEnabled", "value": False},
            {"name": "禁用 Speedreader", "key": "BraveSpeedreaderEnabled", "value": False},
            {"name": "禁用 Tor", "key": "TorDisabled", "value": True},
            {"name": "禁用同步（Sync）", "key": "SyncDisabled", "value": True},
            {"name": "禁用 IPFS", "key": "IPFSEnabled", "value": False},
        ],
    },
    {
        "name": "性能与精简",
        "features": [
            {"name": "禁用后台模式", "key": "BackgroundModeEnabled", "value": False},
            {"name": "禁用购物清单", "key": "ShoppingListEnabled", "value": False},
            {"name": "总是外部打开 PDF", "key": "AlwaysOpenPdfExternally", "value": True},
            {"name": "禁用翻译", "key": "TranslateEnabled", "value": False},
            {"name": "禁用拼写检查", "key": "SpellcheckEnabled", "value": False},
            {"name": "禁用搜索建议", "key": "SearchSuggestEnabled", "value": False},
            {"name": "禁用打印", "key": "PrintingEnabled", "value": False},
            {"name": "禁用默认浏览器提示", "key": "DefaultBrowserSettingEnabled", "value": False},
            {"name": "禁用开发者工具", "key": "DeveloperToolsAvailability", "value": 2},
            {"name": "禁用 Wayback Machine", "key": "BraveWaybackMachineEnabled", "value": False},
        ],
    },
]

DNS_MODES = ["automatic", "off", "secure", "custom"]

# ---------------------------------------------------------------------------
# Build a flat list of rows for the TUI (headers + toggleable items + DNS)
# ---------------------------------------------------------------------------

ROW_HEADER = 0
ROW_FEATURE = 1
ROW_DNS = 2
ROW_DNS_TEMPLATE = 3


def build_rows():
    """Return a list of dicts describing each visual row."""
    rows = []
    for cat in CATEGORIES:
        rows.append({"type": ROW_HEADER, "text": cat["name"]})
        for feat in cat["features"]:
            rows.append({
                "type": ROW_FEATURE,
                "text": feat["name"],
                "key": feat["key"],
                "value": feat["value"],
                "group": feat.get("group"),
                "checked": False,
            })
    # DNS mode selector at the end
    rows.append({"type": ROW_HEADER, "text": "DNS over HTTPS（DoH）"})
    rows.append({
        "type": ROW_DNS,
        "text": "DNS 模式",
        "options": DNS_MODES,
        "selected": 0,  # index into DNS_MODES
    })
    rows.append({
        "type": ROW_DNS_TEMPLATE,
        "text": "DoH 模板",
        "value": "",        # the URL string
        "cursor": 0,        # cursor position within the text
        "scroll": 0,        # horizontal scroll offset for long URLs
    })
    return rows


def get_dns_mode(rows):
    """Return the currently selected DNS mode string."""
    for row in rows:
        if row["type"] == ROW_DNS:
            return row["options"][row["selected"]]
    return "automatic"


def get_dns_template(rows):
    """Return the current DoH template URL string."""
    for row in rows:
        if row["type"] == ROW_DNS_TEMPLATE:
            return row["value"]
    return ""


def toggle_feature_row(rows, target):
    """Flip `target`'s checked state. If it belongs to a group, uncheck the
    other group members first so at most one is active (e.g. Disable vs
    Force Incognito, which set conflicting values for the same policy)."""
    new_state = not target["checked"]
    target["checked"] = new_state
    group = target.get("group")
    if new_state and group:
        for row in rows:
            if row is target:
                continue
            if row.get("type") == ROW_FEATURE and row.get("group") == group:
                row["checked"] = False

# ---------------------------------------------------------------------------
# BOM-aware JSON reader (handles PowerShell UTF-16 exports)
# ---------------------------------------------------------------------------


def read_json_file(path):
    """Read a JSON file, handling BOM and encoding from PS1 exports."""
    with open(path, "rb") as f:
        data = f.read()

    # Detect BOM and decode accordingly
    if data[:2] == b"\xff\xfe":
        text = data[2:].decode("utf-16-le", errors="replace")
    elif data[:2] == b"\xfe\xff":
        text = data[2:].decode("utf-16-be", errors="replace")
    elif data[:3] == b"\xef\xbb\xbf":
        text = data[3:].decode("utf-8", errors="replace")
    else:
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = data.decode("utf-16-le", errors="replace")

    # Strip null bytes (UTF-16 artifacts in malformed files)
    text = text.replace("\x00", "")
    return json.loads(text)

# ---------------------------------------------------------------------------
# Policy I/O
# ---------------------------------------------------------------------------


def load_existing_policy():
    """Read the current policy file and return its dict, or empty dict."""
    try:
        with open(POLICY_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return {}


def apply_policy(rows):
    """Write checked features to the policy JSON file."""
    policy = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"]:
            policy[row["key"]] = row["value"]
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    # Refuse to write a broken DNS config: selecting "custom" without a
    # template URL would set DnsOverHttpsMode=secure with no server,
    # breaking DNS resolution in Brave.
    if dns_mode == "custom" and not dns_template:
        return False, "自定义 DNS 需要提供 DoH 模板 URL。"

    if dns_mode:
        # "custom" maps to "secure" in the actual Chromium policy
        if dns_mode == "custom":
            policy["DnsOverHttpsMode"] = "secure"
            policy["DnsOverHttpsTemplates"] = dns_template
        else:
            policy["DnsOverHttpsMode"] = dns_mode
            if dns_mode == "secure" and dns_template:
                policy["DnsOverHttpsTemplates"] = dns_template

    try:
        os.makedirs(POLICY_DIR, exist_ok=True)
        _atomic_write(POLICY_FILE, json.dumps(policy, indent=4))
        return True, "设置已应用。请重启 Brave 以生效。"
    except PermissionError:
        return False, "权限不足。请以 root 运行。"
    except OSError as e:
        return False, f"Failed to write policy: {e}"


def reset_policy(rows):
    """Delete the policy file and uncheck everything."""
    try:
        if os.path.exists(POLICY_FILE):
            os.remove(POLICY_FILE)
        for row in rows:
            if row["type"] == ROW_FEATURE:
                row["checked"] = False
            elif row["type"] == ROW_DNS:
                row["selected"] = 0
            elif row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = ""
                row["cursor"] = 0
                row["scroll"] = 0
        return True, "已重置所有设置。请重启 Brave 以生效。"
    except OSError as e:
        return False, f"Failed to reset: {e}"


def sync_rows_with_policy(rows, policy):
    """Pre-check rows that match an existing policy on disk."""
    if not policy:
        return
    for row in rows:
        if row["type"] == ROW_FEATURE:
            if row["key"] in policy and policy[row["key"]] == row["value"]:
                row["checked"] = True
        elif row["type"] == ROW_DNS:
            dns_val = policy.get("DnsOverHttpsMode")
            dns_tmpl = policy.get("DnsOverHttpsTemplates", "")
            # If mode is "secure" and a template is set, show as "custom"
            if dns_val == "secure" and dns_tmpl:
                if "custom" in row["options"]:
                    row["selected"] = row["options"].index("custom")
            elif dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl = policy.get("DnsOverHttpsTemplates", "")
            if tmpl:
                row["value"] = tmpl
                row["cursor"] = len(tmpl)

# ---------------------------------------------------------------------------
# Import / Export (PS1-compatible JSON format)
# ---------------------------------------------------------------------------


def export_settings(rows, path):
    """Export current TUI selections to a SlimBrave Neo JSON config file.

    Writes the new key-value map format so multi-value policies (e.g.
    IncognitoModeAvailability, which can be 1 for Disable or 2 for Force)
    round-trip cleanly instead of collapsing to just a key name.
    """
    features = {}
    dns_mode = None
    dns_template = ""
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"]:
            features[row["key"]] = row["value"]
        elif row["type"] == ROW_DNS:
            dns_mode = row["options"][row["selected"]]
        elif row["type"] == ROW_DNS_TEMPLATE:
            dns_template = row["value"].strip()

    settings = {"Features": features}
    if dns_mode:
        settings["DnsMode"] = dns_mode
    if dns_template:
        settings["DnsTemplates"] = dns_template

    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        _atomic_write(path, json.dumps(settings, indent=4))
        return True, f"已导出到 {path}"
    except OSError as e:
        return False, f"导出失败：{e}"


def _parse_imported_features(features_obj):
    """Normalize the Features field from a config file.

    Accepts two formats:
      - New: {"KeyName": value, ...} — authoritative, round-trips multi-value policies.
      - Legacy: ["KeyName", ...] — pre-2026 exports; value is implicit.
    Returns (mapping, is_legacy). `mapping` is {key: value_or_None}; for the
    legacy format values are None, signalling "first matching row wins".
    """
    if isinstance(features_obj, dict):
        return dict(features_obj), False
    if isinstance(features_obj, list):
        return {k: None for k in features_obj}, True
    return {}, False


def import_settings(rows, path):
    """Import a SlimBrave Neo JSON config and update TUI row states."""
    try:
        config = read_json_file(path)
    except FileNotFoundError:
        return False, f"文件不存在：{path}"
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"JSON 无效：{e}"
    except OSError as e:
        return False, f"读取失败：{e}"

    features_map, is_legacy = _parse_imported_features(config.get("Features"))
    dns_mode = config.get("DnsMode", "")
    dns_template = config.get("DnsTemplates", "") or ""

    # Legacy array format can't distinguish value-1 vs value-2 for keys
    # with multiple rows (IncognitoModeAvailability). To avoid silently
    # picking the later entry — which historically force-incognitoed users
    # who imported the Parental Controls preset — only the first matching
    # row per key is checked in legacy mode.
    legacy_handled = set()

    for row in rows:
        if row["type"] == ROW_FEATURE:
            key = row["key"]
            if key not in features_map:
                row["checked"] = False
                continue
            expected = features_map[key]
            if is_legacy:
                if key in legacy_handled:
                    row["checked"] = False
                else:
                    row["checked"] = True
                    legacy_handled.add(key)
            else:
                row["checked"] = (expected == row["value"])
        elif row["type"] == ROW_DNS:
            if dns_mode and dns_mode in row["options"]:
                row["selected"] = row["options"].index(dns_mode)
            elif dns_mode == "secure":
                if "secure" in row["options"]:
                    row["selected"] = row["options"].index("secure")
        elif row["type"] == ROW_DNS_TEMPLATE:
            row["value"] = dns_template
            row["cursor"] = len(dns_template)
            row["scroll"] = 0

    return True, f"已从 {path} 导入"

# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

# Color pair IDs
CP_NORMAL = 1
CP_HEADER = 2
CP_CHECKED = 3
CP_CURSOR = 4
CP_BUTTON = 5
CP_BUTTON_ACTIVE = 6
CP_STATUS_OK = 7
CP_STATUS_ERR = 8
CP_TITLE = 9
CP_DIM = 10

BUTTONS = ["导入", "导出", "应用", "重置", "退出"]

# Focus zones
FOCUS_LIST = 0
FOCUS_BUTTONS = 1
FOCUS_PROMPT = 2   # status-line text input mode


def init_colors():
    """Initialize curses color pairs."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_HEADER, curses.COLOR_RED, -1)
    curses.init_pair(CP_CHECKED, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_CURSOR, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(CP_BUTTON, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_BUTTON_ACTIVE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_STATUS_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_STATUS_ERR, curses.COLOR_RED, -1)
    curses.init_pair(CP_TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(CP_DIM, curses.COLOR_WHITE, -1)


def selectable_indices(rows):
    """Return list of row indices that can receive cursor focus."""
    return [i for i, r in enumerate(rows)
            if r["type"] in (ROW_FEATURE, ROW_DNS, ROW_DNS_TEMPLATE)]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method="",
         prompt_label="", prompt_buf="", prompt_cur=0):
    """Render the full TUI screen."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1  # avoid writing to the last column

    # Title bar
    if install_method:
        title = f" SlimBrave Neo - Brave 精简加固工具 [{install_method}] "
    else:
        title = " SlimBrave Neo - Brave 精简加固工具 "
    pad = max(0, (usable_w - len(title)) // 2)
    try:
        stdscr.addnstr(0, 0, " " * usable_w, usable_w,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
        stdscr.addnstr(0, pad, title, usable_w - pad,
                        curses.color_pair(CP_TITLE) | curses.A_BOLD)
    except curses.error:
        pass

    # Key hints below title
    hint = " [Q/Esc] 退出  [Space/Enter] 切换  [Tab] 按钮 "
    try:
        stdscr.addnstr(1, 0, hint.center(usable_w), usable_w,
                        curses.color_pair(CP_NORMAL) | curses.A_DIM)
    except curses.error:
        pass

    # How many rows fit between title (line 1) and bottom area (3 lines)
    list_start_y = 2
    list_end_y = max_y - 4  # leave room for: blank, buttons, status
    visible_count = list_end_y - list_start_y
    if visible_count < 1:
        visible_count = 1

    # Current DNS mode (for dimming the template row)
    current_dns_mode = get_dns_mode(rows)

    # Draw the scrollable feature list
    for vi in range(visible_count):
        ri = vi + scroll_offset
        if ri >= len(rows):
            break
        row = rows[ri]
        y = list_start_y + vi
        if y >= max_y - 3:
            break

        is_cursor = (focus == FOCUS_LIST and ri == cursor_idx)

        line = ""
        attr = curses.color_pair(CP_NORMAL)

        if row["type"] == ROW_HEADER:
            attr = curses.color_pair(CP_HEADER) | curses.A_BOLD
            line = f"  {row['text']}"
        elif row["type"] == ROW_FEATURE:
            mark = "x" if row["checked"] else " "
            line = f"    [{mark}] {row['text']}"
            if row["checked"]:
                attr = curses.color_pair(CP_CHECKED)
            else:
                attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS:
            current = row["options"][row["selected"]]
            line = f"    < {current} >"
            attr = curses.color_pair(CP_NORMAL)
        elif row["type"] == ROW_DNS_TEMPLATE:
            tmpl_active = current_dns_mode in ("custom", "secure")
            val = row["value"] if row["value"] else ""
            if tmpl_active:
                # Show editable field
                field_w = max(10, usable_w - 22)
                scroll = row.get("scroll", 0)
                visible_text = val[scroll:scroll + field_w]
                line = f"    DoH Template: [{visible_text}]"
                attr = curses.color_pair(CP_NORMAL)
            else:
                line = "    DoH Template:（选择 custom/secure DNS 后可编辑）"
                attr = curses.color_pair(CP_DIM) | curses.A_DIM

        if is_cursor:
            attr = curses.color_pair(CP_CURSOR) | curses.A_BOLD

        try:
            stdscr.addnstr(y, 0, line.ljust(usable_w), usable_w, attr)
        except curses.error:
            pass

        # Draw text cursor for active template row
        if (is_cursor and row["type"] == ROW_DNS_TEMPLATE
                and current_dns_mode in ("custom", "secure")):
            tmpl_val = row["value"]
            field_start = len("    DoH Template: [")
            scroll = row.get("scroll", 0)
            cur_pos = row.get("cursor", 0)
            cur_screen_pos = field_start + cur_pos - scroll
            if 0 <= cur_screen_pos < usable_w:
                try:
                    ch = tmpl_val[cur_pos] if cur_pos < len(tmpl_val) else " "
                    stdscr.addnstr(y, cur_screen_pos, ch, 1,
                                   curses.color_pair(CP_BUTTON_ACTIVE))
                except curses.error:
                    pass

    # Scroll indicators
    if scroll_offset > 0:
        try:
            stdscr.addnstr(list_start_y - 1, usable_w - 5, " ^^^ ", 5,
                            curses.color_pair(CP_NORMAL) | curses.A_DIM)
        except curses.error:
            pass
    if scroll_offset + visible_count < len(rows):
        try:
            stdscr.addnstr(list_end_y, usable_w - 5, " vvv ", 5,
                            curses.color_pair(CP_NORMAL) | curses.A_DIM)
        except curses.error:
            pass

    # Bottom buttons
    btn_y = max_y - 2
    btn_x = 2
    for i, label in enumerate(BUTTONS):
        display = f" {label} "
        if focus == FOCUS_BUTTONS and i == btn_idx:
            attr = curses.color_pair(CP_BUTTON_ACTIVE) | curses.A_BOLD
        else:
            attr = curses.color_pair(CP_BUTTON)
        try:
            stdscr.addnstr(btn_y, btn_x, display, usable_w - btn_x, attr)
        except curses.error:
            pass
        btn_x += len(display) + 3

    # Status / prompt line
    status_y = max_y - 1
    if focus == FOCUS_PROMPT:
        # Show text input prompt
        prompt_text = f" {prompt_label}: {prompt_buf}"
        try:
            stdscr.addnstr(status_y, 0, prompt_text.ljust(usable_w),
                            usable_w, curses.color_pair(CP_TITLE))
            # Show cursor in the prompt
            cur_x = len(prompt_label) + 3 + prompt_cur
            if cur_x < usable_w:
                ch = prompt_buf[prompt_cur] if prompt_cur < len(prompt_buf) else " "
                stdscr.addnstr(status_y, cur_x, ch, 1,
                               curses.color_pair(CP_BUTTON_ACTIVE))
        except curses.error:
            pass
    elif status_msg:
        cp = CP_STATUS_OK if status_ok else CP_STATUS_ERR
        try:
            stdscr.addnstr(status_y, 2, status_msg[:usable_w - 3],
                            usable_w - 3, curses.color_pair(cp))
        except curses.error:
            pass

    stdscr.refresh()


def prompt_text_input(stdscr, rows, cursor_idx, scroll_offset, btn_idx,
                      install_method, label, default=""):
    """Show a status-line text prompt and return (ok, text) on Enter."""
    buf = list(default)
    cur = len(buf)

    while True:
        draw(stdscr, rows, cursor_idx, scroll_offset,
             FOCUS_PROMPT, btn_idx, "", True, install_method,
             prompt_label=label, prompt_buf="".join(buf), prompt_cur=cur)

        key = stdscr.getch()

        if key == 27:  # Escape - cancel
            return False, ""
        elif key in (curses.KEY_ENTER, 10, 13):
            return True, "".join(buf).strip()
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif key == curses.KEY_DC:  # Delete key
            if cur < len(buf):
                buf.pop(cur)
        elif key == curses.KEY_LEFT:
            if cur > 0:
                cur -= 1
        elif key == curses.KEY_RIGHT:
            if cur < len(buf):
                cur += 1
        elif key == curses.KEY_HOME:
            cur = 0
        elif key == curses.KEY_END:
            cur = len(buf)
        elif 32 <= key <= 126:  # printable ASCII
            buf.insert(cur, chr(key))
            cur += 1


def main(stdscr):
    """Main TUI event loop."""
    curses.curs_set(0)
    init_colors()
    stdscr.keypad(True)
    stdscr.timeout(-1)

    rows = build_rows()
    sel = selectable_indices(rows)
    if not sel:
        return

    # Detect Brave installation
    brave_info = detect_brave()
    install_method = brave_info["method"]

    # Load existing policy and pre-check matching features
    policy = load_existing_policy()
    sync_rows_with_policy(rows, policy)

    cursor_pos = 0          # index into sel[]
    cursor_idx = sel[0]     # index into rows[]
    scroll_offset = 0
    focus = FOCUS_LIST
    btn_idx = 0

    # Show detection warnings on startup, if any
    if brave_info["warnings"]:
        status_msg = brave_info["warnings"][0]
        status_ok = not brave_info["found"]
    else:
        status_msg = ""
        status_ok = True

    while True:
        # Compute scroll
        max_y, _ = stdscr.getmaxyx()
        list_start_y = 2
        list_end_y = max_y - 4
        visible_count = max(1, list_end_y - list_start_y)

        if cursor_idx < scroll_offset:
            scroll_offset = cursor_idx
        if cursor_idx >= scroll_offset + visible_count:
            scroll_offset = cursor_idx - visible_count + 1
        # Keep headers visible: if the row above cursor is a header, include it
        if cursor_idx > 0 and rows[cursor_idx - 1]["type"] == ROW_HEADER:
            if cursor_idx - 1 < scroll_offset:
                scroll_offset = cursor_idx - 1

        draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
             status_msg, status_ok, install_method)

        key = stdscr.getch()
        row = rows[cursor_idx]

        # --- Editing mode for DNS template row ---
        if (focus == FOCUS_LIST
                and row["type"] == ROW_DNS_TEMPLATE
                and get_dns_mode(rows) in ("custom", "secure")):
            # Typing into the template field
            if 32 <= key <= 126:
                val = row["value"]
                cur = row["cursor"]
                row["value"] = val[:cur] + chr(key) + val[cur:]
                row["cursor"] = cur + 1
                # Update horizontal scroll
                _, max_x = stdscr.getmaxyx()
                field_w = max(10, max_x - 1 - 22)
                if row["cursor"] - row["scroll"] >= field_w:
                    row["scroll"] = row["cursor"] - field_w + 1
                status_msg = ""
                continue
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if row["cursor"] > 0:
                    val = row["value"]
                    cur = row["cursor"]
                    row["value"] = val[:cur - 1] + val[cur:]
                    row["cursor"] = cur - 1
                    if row["scroll"] > 0:
                        row["scroll"] -= 1
                    status_msg = ""
                continue
            elif key == curses.KEY_DC:
                val = row["value"]
                cur = row["cursor"]
                if cur < len(val):
                    row["value"] = val[:cur] + val[cur + 1:]
                    status_msg = ""
                continue
            elif key == curses.KEY_LEFT:
                if row["cursor"] > 0:
                    row["cursor"] -= 1
                    if row["cursor"] < row["scroll"]:
                        row["scroll"] = row["cursor"]
                continue
            elif key == curses.KEY_RIGHT:
                if row["cursor"] < len(row["value"]):
                    row["cursor"] += 1
                    _, max_x = stdscr.getmaxyx()
                    field_w = max(10, max_x - 1 - 22)
                    if row["cursor"] - row["scroll"] >= field_w:
                        row["scroll"] = row["cursor"] - field_w + 1
                continue
            elif key == curses.KEY_HOME:
                row["cursor"] = 0
                row["scroll"] = 0
                continue
            elif key == curses.KEY_END:
                row["cursor"] = len(row["value"])
                _, max_x = stdscr.getmaxyx()
                field_w = max(10, max_x - 1 - 22)
                row["scroll"] = max(0, row["cursor"] - field_w + 1)
                continue
            # For other keys (arrows up/down, tab, etc.), fall through
            # to normal handling below

        # --- Global keys ---
        if key == ord("q") or key == 27:  # q or Escape
            break

        elif key == curses.KEY_UP:
            if focus == FOCUS_LIST:
                if cursor_pos > 0:
                    cursor_pos -= 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                focus = FOCUS_LIST
                cursor_pos = len(sel) - 1
                cursor_idx = sel[cursor_pos]
                status_msg = ""

        elif key == curses.KEY_DOWN:
            if focus == FOCUS_LIST:
                if cursor_pos < len(sel) - 1:
                    cursor_pos += 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
                else:
                    focus = FOCUS_BUTTONS
                    btn_idx = 0
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                pass

        elif key == ord("\t"):
            if focus == FOCUS_LIST:
                focus = FOCUS_BUTTONS
                btn_idx = 0
                status_msg = ""
            else:
                focus = FOCUS_LIST
                status_msg = ""

        elif key == curses.KEY_LEFT:
            if focus == FOCUS_BUTTONS:
                btn_idx = max(0, btn_idx - 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] - 1) % len(row["options"])
                    status_msg = ""

        elif key == curses.KEY_RIGHT:
            if focus == FOCUS_BUTTONS:
                btn_idx = min(len(BUTTONS) - 1, btn_idx + 1)
            elif focus == FOCUS_LIST:
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key == ord(" "):
            if focus == FOCUS_LIST:
                if row["type"] == ROW_FEATURE:
                    toggle_feature_row(rows, row)
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                btn_label = BUTTONS[btn_idx]

                if btn_label == "应用":
                    # Validate: custom DNS requires a template URL
                    dns_mode = get_dns_mode(rows)
                    dns_tmpl = get_dns_template(rows)
                    if dns_mode == "custom" and not dns_tmpl:
                        status_msg = "自定义 DNS 需要提供 DoH 模板 URL。"
                        status_ok = False
                    else:
                        status_ok, status_msg = apply_policy(rows)

                elif btn_label == "重置":
                    status_msg = "确认重置所有设置？按 Enter 确认，按任意键取消。"
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset,
                         focus, btn_idx, status_msg, status_ok,
                         install_method)
                    confirm = stdscr.getch()
                    if confirm in (curses.KEY_ENTER, 10, 13):
                        status_ok, status_msg = reset_policy(rows)
                    else:
                        status_msg = "已取消重置。"
                        status_ok = True

                elif btn_label == "导入":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "导入路径（Esc 取消）",
                        default="./Presets/")
                    if ok and path:
                        status_ok, status_msg = import_settings(rows, path)
                        # Rebuild selectable indices (unchanged, but safe)
                        sel = selectable_indices(rows)
                    else:
                        status_msg = "已取消导入。"
                        status_ok = True

                elif btn_label == "导出":
                    ok, path = prompt_text_input(
                        stdscr, rows, cursor_idx, scroll_offset,
                        btn_idx, install_method,
                        "导出路径（Esc 取消）",
                        default="./SlimBraveNeoSettings.json")
                    if ok and path:
                        status_ok, status_msg = export_settings(rows, path)
                    else:
                        status_msg = "已取消导出。"
                        status_ok = True

                elif btn_label == "退出":
                    break

            elif focus == FOCUS_LIST:
                # Enter on a list item acts like spacebar
                if row["type"] == ROW_FEATURE:
                    toggle_feature_row(rows, row)
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

# ---------------------------------------------------------------------------
# CLI (non-interactive)
# ---------------------------------------------------------------------------


def cli_import(path, doh_templates=""):
    """Non-interactive: import config and apply policies."""
    rows = build_rows()
    ok, msg = import_settings(rows, path)
    if not ok:
        print(f"错误：{msg}", file=sys.stderr)
        return 1
    print(msg)

    # Override DoH templates if provided via CLI flag
    if doh_templates:
        for row in rows:
            if row["type"] == ROW_DNS_TEMPLATE:
                row["value"] = doh_templates
                break

    ok, msg = apply_policy(rows)
    if not ok:
        print(f"错误：{msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_export(path):
    """Non-interactive: export current policy to a config file."""
    policy = load_existing_policy()
    if not policy:
        print("未找到现有策略。", file=sys.stderr)
        return 1

    rows = build_rows()
    sync_rows_with_policy(rows, policy)

    ok, msg = export_settings(rows, path)
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    print(msg)
    return 0


def cli_reset():
    """Non-interactive: delete the policy file."""
    try:
        if os.path.exists(POLICY_FILE):
            os.remove(POLICY_FILE)
            print(f"已删除 {POLICY_FILE}")
        else:
            print(f"未在 {POLICY_FILE} 找到策略文件")
        return 0
    except OSError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 1


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="slimbrave",
        description="SlimBrave Neo - Brave 精简加固工具（Linux）",
        epilog="不带参数运行将启动交互式 TUI。",
    )
    parser.add_argument(
        "--import", dest="import_path", metavar="PATH",
        help="导入 SlimBrave Neo JSON 配置并应用策略",
    )
    parser.add_argument(
        "--export", dest="export_path", metavar="PATH",
        help="将当前策略导出为 SlimBrave Neo JSON 配置",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="删除 SlimBrave Neo 托管策略文件",
    )
    parser.add_argument(
        "--policy-file", metavar="PATH",
        help=f"覆盖策略文件路径（默认：{POLICY_FILE}）",
    )
    parser.add_argument(
        "--doh-templates", metavar="URL",
        help="设置 DnsOverHttpsTemplates（用于 custom DNS 模式）",
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    args = parse_args()

    # Override policy file path if requested
    if args.policy_file:
        if not _is_within_allowed_policy_dir(args.policy_file):
            print(
                "--policy-file 必须解析到以下目录之一内："
                + ", ".join(ALLOWED_POLICY_DIRS)
            )
            sys.exit(2)
        POLICY_FILE = os.path.realpath(args.policy_file)
        POLICY_DIR = os.path.dirname(POLICY_FILE)

    is_cli = args.import_path or args.export_path or args.reset

    if os.geteuid() != 0:
        print("SlimBrave Neo 必须以 root 身份运行。")
        if is_cli:
            print("用法：sudo python3 slimbrave.py --import preset.json")
        else:
            print("用法：sudo python3 slimbrave.py")
        sys.exit(1)

    if is_cli:
        # Non-interactive CLI mode
        rc = 0
        if args.reset:
            rc = cli_reset()
        if args.import_path:
            rc = cli_import(args.import_path,
                            doh_templates=args.doh_templates or "")
        if args.export_path:
            rc = cli_export(args.export_path)
        sys.exit(rc)

    # Interactive TUI mode
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass  # Clean exit on Ctrl+C
