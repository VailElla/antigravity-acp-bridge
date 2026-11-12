#!/usr/bin/env python3
"""Report only the local source tuples owned by Google Antigravity's server."""

import ipaddress
import json
import os
import re
from contextlib import closing
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid

SERVER = os.environ.get("ACP_GUARD_SERVER", "/Applications/Antigravity.app/Contents/Resources/bin/language_server")
REPORT_INTERVAL = 3
SOCKET_SCAN_INTERVAL = 6
SSH_COMMAND = [
    "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
    os.environ.get("ACP_GUARD_ROUTER", ""), "/etc/openclash/custom/antigravity_port_feed.sh",
]
LOG_PATH = os.path.expanduser("~/Library/Logs/Antigravity/language_server.log")
SUMMARY_DB = os.path.expanduser("~/.gemini/antigravity/conversation_summaries.db")


def parse_source(line):
    """Parse an lsof -Fn TCP name without exporting its remote endpoint."""
    if not line.startswith("n") or "->" not in line:
        return None
    source = line[1:].split("->", 1)[0]
    try:
        if source.startswith("["):
            end = source.index("]")
            address, port = source[1:end].split("%", 1)[0], source[end + 2 :]
            if source[end + 1 : end + 2] != ":":
                return None
        else:
            address, port = source.rsplit(":", 1)
        address = ipaddress.ip_address(address)
        port = int(port)
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            return None
        if not 1 <= port <= 65535:
            return None
        return (str(address), port)
    except (ValueError, IndexError):
        return None


def source_tuples():
    result = subprocess.run(
        ["/usr/bin/pgrep", "-x", "language_server"],
        capture_output=True, text=True, timeout=4, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("pgrep failed")
    pairs = set()
    for pid in result.stdout.split():
        if not pid.isdigit():
            continue
        path = subprocess.run(
            ["/bin/ps", "-p", pid, "-o", "comm="],
            capture_output=True, text=True, timeout=4, check=False,
        )
        if path.returncode != 0 or path.stdout.strip() != SERVER:
            continue
        sockets = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", pid, "-iTCP",
             "-sTCP:ESTABLISHED", "-Fn"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if sockets.returncode not in (0, 1):
            raise RuntimeError("lsof failed")
        for line in sockets.stdout.splitlines():
            pair = parse_source(line)
            if pair is not None:
                pairs.add(pair)
    # Abnormal output must never expand the remote guard's scope.
    if len(pairs) > 256:
        raise RuntimeError("too many sockets")
    return sorted(pairs)


class RegionErrorWatch:
    """Share only whether a recent explicit Google location error appeared."""

    def __init__(self, path=LOG_PATH, clock=time.monotonic):
        self.path = path
        self.clock = clock
        self.inode = None
        self.offset = 0
        self.last_error = None
        self.partial = ""
        try:
            st = os.stat(path)
            self.inode, self.offset = st.st_ino, st.st_size
        except OSError:
            pass

    def recent(self):
        try:
            st = os.stat(self.path)
            if self.inode != st.st_ino or st.st_size < self.offset:
                self.inode, self.offset, self.partial = st.st_ino, 0, ""
            if st.st_size > self.offset:
                # Read only the end of an unexpectedly large burst.
                if st.st_size - self.offset > 262144:
                    self.offset = st.st_size - 262144
                    self.partial = ""
                with open(self.path, "rb") as f:
                    f.seek(self.offset)
                    data = f.read(st.st_size - self.offset)
                    self.offset = f.tell()
                lines = (self.partial + data.decode("utf-8", "replace")).split("\n")
                self.partial = lines.pop()[-4096:]
                for line in lines:
                    if ("Detected location: CN" in line and "PERMISSION_DENIED" in line) or (
                        "User location is not supported" in line and "FAILED_PRECONDITION" in line
                    ):
                        self.last_error = self.clock()
        except OSError:
            return False
        return self.last_error is not None and self.clock() - self.last_error <= 90


def all_tasks_idle(path=SUMMARY_DB):
    """Read only aggregate task state; unknown schemas/errors are not idle."""
    try:
        uri = 'file:' + urllib.parse.quote(path, safe='/') + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db:
            row = db.execute(
                "SELECT COUNT(*), SUM(CASE WHEN status = ? AND not_fully_idle = 0 "
                "THEN 0 ELSE 1 END) FROM conversation_summaries",
                ('CASCADE_RUN_STATUS_IDLE',),
            ).fetchone()
        return bool(row and row[0] > 0 and row[1] == 0)
    except (OSError, sqlite3.Error):
        return False


def main():
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", os.environ.get("ACP_GUARD_ROUTER", "")):
        raise SystemExit("Set ACP_GUARD_ROUTER to a trusted SSH alias or user@host")
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    child = None
    error_watch = RegionErrorWatch()
    reporter_id = uuid.uuid4().hex
    activity_epoch = 0
    last_idle = None
    idle_since = None
    next_scan = 0
    pairs = []
    while not stopping:
        try:
            if child is None or child.poll() is not None:
                child = subprocess.Popen(SSH_COMMAND, stdin=subprocess.PIPE,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, text=True)
            now = time.monotonic()
            if now >= next_scan:
                try:
                    pairs = source_tuples()
                except (OSError, subprocess.SubprocessError, RuntimeError):
                    # Invalidate the feed rather than publish a partial scan.
                    pairs = []
                next_scan = now + SOCKET_SCAN_INTERVAL
            idle = bool(pairs) and all_tasks_idle()
            if not idle:
                if last_idle is not False:
                    activity_epoch += 1
                idle_since = None
            elif last_idle is not True:
                idle_since = now
            last_idle = idle
            idle_for = int(now - idle_since) if idle and idle_since is not None else 0
            payload = json.dumps({"version": 2, "identities": pairs,
                                  "region_error": error_watch.recent(),
                                  "tasks_idle": idle, "idle_for": idle_for,
                                  "activity_epoch": activity_epoch,
                                  "reporter_id": reporter_id},
                                 separators=(",", ":")) + "\n"
            if len(payload.encode()) > 8192:
                payload = '{"version":2,"identities":[],"tasks_idle":false}\n'
            child.stdin.write(payload)
            child.stdin.flush()
        except (OSError, BrokenPipeError):
            if child is not None:
                child.terminate()
            child = None
        for _ in range(REPORT_INTERVAL):
            if stopping:
                break
            time.sleep(1)
    if child is not None:
        if child.stdin:
            child.stdin.close()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.terminate()


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        print("Antigravity source tuples:", len(source_tuples()))
        print("All conversations idle:", all_tasks_idle())
    else:
        main()
