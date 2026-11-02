"""Thin adb wrapper. Set $ADB to the binary; on WSL `adb.exe` is found on PATH."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time

DUMP_PATH = "/sdcard/screenwarden_dump.xml"


class AdbError(RuntimeError):
    pass


def adb_binary() -> str:
    binary = os.environ.get("ADB") or shutil.which("adb") or shutil.which("adb.exe")
    if not binary:
        raise AdbError("adb not found: install platform-tools or set $ADB")
    return binary


class Device:
    def __init__(self, serial: str | None = None):
        self.base = [adb_binary()]
        serial = serial or os.environ.get("ANDROID_SERIAL")
        if serial:
            self.base += ["-s", serial]

    def run(self, *args: str, timeout: float = 60) -> bytes:
        done = subprocess.run([*self.base, *args], capture_output=True, timeout=timeout)
        if done.returncode:
            raise AdbError(f"adb {' '.join(args)}: {done.stderr.decode(errors='replace').strip()}")
        return done.stdout

    def shell(self, command: str, timeout: float = 60) -> str:
        return self.run("shell", command, timeout=timeout).decode(errors="replace")

    def dump_ui(self, retries: int = 4) -> str:
        """Return the current uiautomator XML, retrying while the UI is settling.

        --windows (Android 13+) includes every window, so overlays from other apps
        are visible; older devices reject it and fall back to the active window.
        """
        for attempt in range(retries):
            flag = "--windows " if attempt % 2 == 0 else ""
            self.shell(f"rm -f {DUMP_PATH}")
            out = self.shell(f"uiautomator dump {flag}{DUMP_PATH}")
            if "dumped to" in out:
                return self.run("exec-out", "cat", DUMP_PATH).decode("utf-8", errors="replace")
            time.sleep(2)
        raise AdbError("uiautomator dump failed")

    def screenshot(self) -> bytes:
        return self.run("exec-out", "screencap", "-p")

    def foreground(self) -> str:
        out = self.shell("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'")
        match = re.search(r"\b([a-zA-Z][\w.]+)/[\w.$]+", out)
        return match.group(1) if match else ""

    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {x} {y}")

    def type_text(self, text: str) -> None:
        escaped = re.sub(r"([\\%&|<>;()$`\"'])", r"\\\1", text).replace(" ", "%s")
        self.shell(f"input text {shlex.quote(escaped)}")

    def key(self, name: str) -> None:
        self.shell(f"input keyevent {name}")

    def swipe(self, x1: int, y1: int, x2: int, y2: int, ms: int = 300) -> None:
        self.shell(f"input swipe {x1} {y1} {x2} {y2} {ms}")

    def open_url(self, url: str) -> None:
        self.shell(f"am start -a android.intent.action.VIEW -d {shlex.quote(url)}")

    def open_app(self, package: str) -> None:
        self.shell(f"monkey -p {shlex.quote(package)} -c android.intent.category.LAUNCHER 1")

    def compose_sms(self, number: str, body: str) -> None:
        self.shell("am start -a android.intent.action.SENDTO "
                   f"-d {shlex.quote('smsto:' + number)} --es sms_body {shlex.quote(body)}")
