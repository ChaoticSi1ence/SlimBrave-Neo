#!/usr/bin/env python3
"""SlimBrave - Linux TUI for debloating and hardening Brave Browser.

Sets Chromium enterprise policies via JSON files at
/etc/brave/policies/managed/slimbrave.json. Requires root.
"""

import curses
import json
import os
import shutil
import subprocess
import sys

POLICY_DIR = "/etc/brave/policies/managed"
POLICY_FILE = os.path.join(POLICY_DIR, "slimbrave.json")

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
                "Snap confinement may prevent policies from taking effect. "
                "Native packages are recommended."
            ],
        }

    # Fallback — check PATH
    for name in ("brave-browser-stable", "brave-browser", "brave"):
        found = shutil.which(name)
        if found:
            return {"found": True, "method": "unknown", "path": found, "warnings": []}

    return {
        "found": False, "method": "not found", "path": "",
        "warnings": [
            "Brave browser not found. Policies will be written but may have no effect."
        ],
    }


# ---------------------------------------------------------------------------
# Feature definitions — mirrors the Windows SlimBrave.ps1 categories
# ---------------------------------------------------------------------------

CATEGORIES = [
    {
        "name": "Telemetry & Reporting",
        "features": [
            {"name": "Disable Metrics Reporting", "key": "MetricsReportingEnabled", "value": False},
            {"name": "Disable Safe Browsing Reporting", "key": "SafeBrowsingExtendedReportingEnabled", "value": False},
            {"name": "Disable URL Data Collection", "key": "UrlKeyedAnonymizedDataCollectionEnabled", "value": False},
            {"name": "Disable Feedback Surveys", "key": "FeedbackSurveysEnabled", "value": False},
        ],
    },
    {
        "name": "Privacy & Security",
        "features": [
            {"name": "Disable Safe Browsing", "key": "SafeBrowsingProtectionLevel", "value": 0},
            {"name": "Disable Autofill (Addresses)", "key": "AutofillAddressEnabled", "value": False},
            {"name": "Disable Autofill (Credit Cards)", "key": "AutofillCreditCardEnabled", "value": False},
            {"name": "Disable Password Manager", "key": "PasswordManagerEnabled", "value": False},
            {"name": "Disable Browser Sign-in", "key": "BrowserSignin", "value": 0},
            {"name": "Disable WebRTC IP Leak", "key": "WebRtcIPHandling", "value": "disable_non_proxied_udp"},
            {"name": "Disable QUIC Protocol", "key": "QuicAllowed", "value": False},
            {"name": "Block Third Party Cookies", "key": "BlockThirdPartyCookies", "value": True},
            {"name": "Enable Do Not Track", "key": "EnableDoNotTrack", "value": True},
            {"name": "Force Google SafeSearch", "key": "ForceGoogleSafeSearch", "value": True},
            {"name": "Disable IPFS", "key": "IPFSEnabled", "value": False},
            {"name": "Disable Incognito Mode", "key": "IncognitoModeAvailability", "value": 1},
            {"name": "Force Incognito Mode", "key": "IncognitoModeAvailability", "value": 2},
        ],
    },
    {
        "name": "Brave Features",
        "features": [
            {"name": "Disable Brave Rewards", "key": "BraveRewardsDisabled", "value": True},
            {"name": "Disable Brave Wallet", "key": "BraveWalletDisabled", "value": True},
            {"name": "Disable Brave VPN", "key": "BraveVPNDisabled", "value": True},
            {"name": "Disable Brave AI Chat", "key": "BraveAIChatEnabled", "value": False},
            {"name": "Disable Brave Shields", "key": "BraveShieldsDisabledForUrls", "value": ["https://*", "http://*"]},
            {"name": "Disable Tor", "key": "TorDisabled", "value": True},
            {"name": "Disable Sync", "key": "SyncDisabled", "value": True},
        ],
    },
    {
        "name": "Performance & Bloat",
        "features": [
            {"name": "Disable Background Mode", "key": "BackgroundModeEnabled", "value": False},
            {"name": "Disable Media Recommendations", "key": "MediaRecommendationsEnabled", "value": False},
            {"name": "Disable Shopping List", "key": "ShoppingListEnabled", "value": False},
            {"name": "Always Open PDF Externally", "key": "AlwaysOpenPdfExternally", "value": True},
            {"name": "Disable Translate", "key": "TranslateEnabled", "value": False},
            {"name": "Disable Spellcheck", "key": "SpellcheckEnabled", "value": False},
            {"name": "Disable Promotions", "key": "PromotionsEnabled", "value": False},
            {"name": "Disable Search Suggestions", "key": "SearchSuggestEnabled", "value": False},
            {"name": "Disable Printing", "key": "PrintingEnabled", "value": False},
            {"name": "Disable Default Browser Prompt", "key": "DefaultBrowserSettingEnabled", "value": False},
            {"name": "Disable Developer Tools", "key": "DeveloperToolsAvailability", "value": 2},
        ],
    },
]

DNS_MODES = ["automatic", "off", "custom"]

# ---------------------------------------------------------------------------
# Build a flat list of rows for the TUI (headers + toggleable items + DNS)
# ---------------------------------------------------------------------------

ROW_HEADER = 0
ROW_FEATURE = 1
ROW_DNS = 2


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
                "checked": False,
            })
    # DNS mode selector at the end
    rows.append({"type": ROW_HEADER, "text": "DNS Over HTTPS"})
    rows.append({
        "type": ROW_DNS,
        "text": "DNS Mode",
        "options": DNS_MODES,
        "selected": 0,  # index into DNS_MODES
    })
    return rows

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
    for row in rows:
        if row["type"] == ROW_FEATURE and row["checked"]:
            policy[row["key"]] = row["value"]
        elif row["type"] == ROW_DNS:
            policy["DnsOverHttpsMode"] = row["options"][row["selected"]]
    try:
        os.makedirs(POLICY_DIR, exist_ok=True)
        with open(POLICY_FILE, "w") as f:
            json.dump(policy, f, indent=4)
        return True, "Settings applied. Restart Brave to see changes."
    except PermissionError:
        return False, "Permission denied. Run as root."
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
        return True, "All settings reset. Restart Brave to see changes."
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
            if dns_val in row["options"]:
                row["selected"] = row["options"].index(dns_val)

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

BUTTONS = ["Apply", "Reset", "Cancel"]

# Focus zones
FOCUS_LIST = 0
FOCUS_BUTTONS = 1


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_NORMAL, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_HEADER, curses.COLOR_RED, -1)        # closest to LightSalmon
    curses.init_pair(CP_CHECKED, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_CURSOR, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(CP_BUTTON, curses.COLOR_WHITE, -1)
    curses.init_pair(CP_BUTTON_ACTIVE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_STATUS_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(CP_STATUS_ERR, curses.COLOR_RED, -1)
    curses.init_pair(CP_TITLE, curses.COLOR_CYAN, -1)


def selectable_indices(rows):
    """Return list of row indices that can receive cursor focus."""
    return [i for i, r in enumerate(rows) if r["type"] in (ROW_FEATURE, ROW_DNS)]


def draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
         status_msg, status_ok, install_method=""):
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    usable_w = max_x - 1  # avoid writing to the last column

    # Title bar
    if install_method:
        title = f" SlimBrave - Brave Browser Debloater [{install_method}] "
    else:
        title = " SlimBrave - Brave Browser Debloater "
    pad = max(0, (usable_w - len(title)) // 2)
    try:
        stdscr.addnstr(0, 0, " " * usable_w, usable_w, curses.color_pair(CP_TITLE) | curses.A_BOLD)
        stdscr.addnstr(0, pad, title, usable_w - pad, curses.color_pair(CP_TITLE) | curses.A_BOLD)
    except curses.error:
        pass

    # How many rows fit between title (line 1) and bottom area (3 lines)
    list_start_y = 2
    list_end_y = max_y - 4  # leave room for: blank, buttons, status
    visible_count = list_end_y - list_start_y
    if visible_count < 1:
        visible_count = 1

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

        if is_cursor:
            attr = curses.color_pair(CP_CURSOR) | curses.A_BOLD

        try:
            stdscr.addnstr(y, 0, line.ljust(usable_w), usable_w, attr)
        except curses.error:
            pass

    # Scroll indicators
    if scroll_offset > 0:
        try:
            stdscr.addnstr(list_start_y - 1, usable_w - 5, " ^^^ ", 5, curses.color_pair(CP_NORMAL) | curses.A_DIM)
        except curses.error:
            pass
    if scroll_offset + visible_count < len(rows):
        try:
            stdscr.addnstr(list_end_y, usable_w - 5, " vvv ", 5, curses.color_pair(CP_NORMAL) | curses.A_DIM)
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

    # Status message
    if status_msg:
        status_y = max_y - 1
        cp = CP_STATUS_OK if status_ok else CP_STATUS_ERR
        try:
            stdscr.addnstr(status_y, 2, status_msg[:usable_w - 3], usable_w - 3, curses.color_pair(cp))
        except curses.error:
            pass

    stdscr.refresh()


def main(stdscr):
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
        status_ok = not brave_info["found"]  # red if not found, green if found with warning
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

        if key == ord("q") or key == 27:  # q or Escape
            break

        elif key == curses.KEY_UP:
            if focus == FOCUS_LIST:
                if cursor_pos > 0:
                    cursor_pos -= 1
                    cursor_idx = sel[cursor_pos]
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                # Move back up to the list
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
                    # At the bottom of the list, move focus to buttons
                    focus = FOCUS_BUTTONS
                    btn_idx = 0
                    status_msg = ""
            elif focus == FOCUS_BUTTONS:
                pass  # already at bottom

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
                row = rows[cursor_idx]
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] - 1) % len(row["options"])
                    status_msg = ""

        elif key == curses.KEY_RIGHT:
            if focus == FOCUS_BUTTONS:
                btn_idx = min(len(BUTTONS) - 1, btn_idx + 1)
            elif focus == FOCUS_LIST:
                row = rows[cursor_idx]
                if row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key == ord(" "):
            if focus == FOCUS_LIST:
                row = rows[cursor_idx]
                if row["type"] == ROW_FEATURE:
                    row["checked"] = not row["checked"]
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""

        elif key in (curses.KEY_ENTER, 10, 13):
            if focus == FOCUS_BUTTONS:
                if BUTTONS[btn_idx] == "Apply":
                    status_ok, status_msg = apply_policy(rows)
                elif BUTTONS[btn_idx] == "Reset":
                    # Confirm reset
                    status_msg = "Reset all settings? Press Enter to confirm, any other key to cancel."
                    status_ok = True
                    draw(stdscr, rows, cursor_idx, scroll_offset, focus, btn_idx,
                         status_msg, status_ok, install_method)
                    confirm = stdscr.getch()
                    if confirm in (curses.KEY_ENTER, 10, 13):
                        status_ok, status_msg = reset_policy(rows)
                    else:
                        status_msg = "Reset cancelled."
                        status_ok = True
                elif BUTTONS[btn_idx] == "Cancel":
                    break
            elif focus == FOCUS_LIST:
                # Enter on a list item acts like spacebar
                row = rows[cursor_idx]
                if row["type"] == ROW_FEATURE:
                    row["checked"] = not row["checked"]
                    status_msg = ""
                elif row["type"] == ROW_DNS:
                    row["selected"] = (row["selected"] + 1) % len(row["options"])
                    status_msg = ""


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("SlimBrave must be run as root.")
        print("Usage: sudo python3 slimbrave.py")
        sys.exit(1)

    curses.wrapper(main)
