#!/usr/bin/env python3
"""Run the TUI in a real terminal, with the real curses, and read the screen.

Everything else in tests/ is pure over rows[] or renders through a fake
window. This is the one check that goes through ncurses: it starts the
script inside tmux - a real terminal emulator, 80x24 - sends keys, and
reads back what landed on screen. Twice per script: under a UTF-8 locale,
expecting the Unicode frames, and under the C locale with Python's UTF-8
mode off, expecting the ASCII fallback the scripts pick when the codec
cannot encode the box glyphs.

Needs tmux, passwordless sudo (the scripts refuse to run otherwise) and a
policy-file path inside the script's allowed directories. CI only; it
writes nothing - the TUI is quit without Apply.

    python3 tests/tui_smoke.py slimbrave-linux.py /etc/brave/policies/managed/smoke.json
"""
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLS, ROWS = 80, 24


def tmux(*args):
    return subprocess.run(["tmux", *args], check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout


def screen(session):
    rows = tmux("capture-pane", "-t", session, "-p").split("\n")
    rows = rows[:ROWS] + [""] * (ROWS - len(rows))
    return [r.rstrip() for r in rows]


def wait_for(session, needle, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = screen(session)
        if any(needle in r for r in rows):
            return rows
        time.sleep(0.25)
    raise SystemExit(f"timed out waiting for {needle!r}; the screen was:\n"
                     + "\n".join(screen(session)))


def press(session, key, settle=0.5):
    tmux("send-keys", "-t", session, key)
    time.sleep(settle)
    return screen(session)


def run(script, policy_file, env, label):
    session = f"slimbrave-smoke-{os.getpid()}-{label}"
    env_str = " ".join(f"{k}={v}" for k, v in env.items())
    # sudo keeps TERM, so curses sees tmux's own terminfo entry; the locale
    # is passed explicitly because sudo resets it.
    cmd = (f"sudo env {env_str} python3 {ROOT / script} --policy-file {policy_file}; "
           "echo EXIT=$?; sleep 60")
    tmux("new-session", "-d", "-s", session, "-x", str(COLS), "-y", str(ROWS), cmd)
    frames = {}
    try:
        frames["start"] = wait_for(session, "Settings")
        frames["down"] = press(session, "Down")
        frames["hidden"] = press(session, "d")
        frames["tab"] = press(session, "Tab")
        frames["button"] = press(session, "d")
        press(session, "q")
        frames["exit"] = wait_for(session, "EXIT=")
    finally:
        subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True)
    return frames


def pane_text(rows, tl, hz):
    """The text inside the Description box, or '' when there is none."""
    for i, r in enumerate(rows):
        if r.startswith(tl + hz + " Description "):
            body = []
            for line in rows[i + 1:]:
                if not line.startswith(("│", "|")):
                    break
                body.append(line.strip("│| "))
            return " ".join(body).strip()
    return ""


def check(frames, unicode):
    tl, hz, vt = ("┌", "─", "│") if unicode else ("+", "-", "|")
    f = frames["start"]
    problems = []

    def expect(cond, what):
        if not cond:
            problems.append(what)

    expect("SlimBrave Neo" in f[0], "title missing from row 0")
    expect(f[2].startswith(tl + hz + " Settings "), f"row 2 is not the Settings edge: {f[2]!r}")
    expect(sum(1 for r in f if r.startswith(tl + hz + " Description ")) == 1,
           "no single Description edge")
    buttons = [i for i, r in enumerate(f) if " Import " in r and " Quit " in r]
    expect(len(buttons) == 1 and f[buttons[0]].startswith(vt),
           "buttons row missing or not inside a frame")
    expect(all(len(r) <= COLS for r in f), "a row is wider than the terminal")
    expect(pane_text(f, tl, hz), "the pane is empty at start")
    expect(pane_text(frames["down"], tl, hz) != pane_text(f, tl, hz),
           "Down did not change what the pane describes")
    h = frames["hidden"]
    expect(not any(" Description " in r for r in h), "d did not hide the pane")
    expect(sum(1 for r in h if r.startswith(vt)) > sum(1 for r in f if r.startswith(vt)),
           "hiding the pane did not give the list more rows")
    expect("Load a settings file" in pane_text(frames["button"], tl, hz),
           "on the button row the pane does not describe Import")
    expect(any("EXIT=0" in r for r in frames["exit"]), "q did not exit cleanly")
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    script, policy_file = sys.argv[1], sys.argv[2]
    utf8 = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    passes = (
        ("utf8", {"LANG": utf8, "LC_ALL": utf8}, True),
        # LC_ALL set disables Python's C-locale coercion; PYTHONUTF8=0 keeps
        # UTF-8 mode off, so the preferred encoding really is ASCII.
        ("ascii", {"LC_ALL": "C", "PYTHONUTF8": "0"}, False),
    )
    failed = False
    for label, env, unicode in passes:
        frames = run(script, policy_file, env, label)
        problems = check(frames, unicode)
        print(f"=== {script} [{label}] {'ok' if not problems else 'FAILED'}")
        for p in problems:
            print(f"  - {p}")
        print("\n".join(frames["start"]))
        if problems:
            failed = True
            for name in ("down", "hidden", "button", "exit"):
                print(f"--- {name}")
                print("\n".join(frames[name]))
    sys.exit(1 if failed else 0)
