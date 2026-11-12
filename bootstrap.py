#!/usr/bin/env python3
"""Create an isolated local configuration without overwriting an existing installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


def default_root() -> Path:
    if os.name == "nt":
        return Path(os.environ["LOCALAPPDATA"]) / "AntigravityAcpBridge"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AntigravityAcpBridge"
    return Path.home() / ".local" / "share" / "AntigravityAcpBridge"


def protect_directory(root: Path) -> None:
    if os.name != "nt":
        root.chmod(0o700)
        return
    # Use the current SID rather than a localized account name. Restrict this
    # newly created directory and its descendants to the user and LocalSystem.
    identity = subprocess.check_output(["whoami.exe", "/user", "/fo", "csv", "/nh"], timeout=10)
    match = re.search(rb"S-1-(?:\d+-)*\d+", identity)
    if match is None:
        raise RuntimeError("Cannot determine the current Windows user SID")
    subprocess.run(
        ["icacls.exe", str(root), "/inheritance:r", "/grant:r",
         "*" + match.group().decode("ascii") + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True, timeout=15,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agy", required=True, type=Path, help="Path to the verified agy executable")
    parser.add_argument("--sha512", required=True, help="Expected SHA-512 from a trusted source")
    parser.add_argument("--client-version", required=True, help="Version of the installed ACP client")
    parser.add_argument("--root", type=Path, default=default_root(), help="New private configuration directory")
    parser.add_argument("--port", type=int, default=18045)
    args = parser.parse_args()

    expected = args.sha512.lower()
    if not re.fullmatch(r"[0-9a-f]{128}", expected):
        parser.error("--sha512 must be a 128-character hexadecimal digest")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be in the range 1..65535")
    agy = args.agy.expanduser().resolve(strict=True)
    if not agy.is_file():
        parser.error("--agy must refer to a regular file")
    digest = hashlib.sha512()
    with agy.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        parser.error("The executable's SHA-512 does not match the supplied expected digest")

    root = args.root.expanduser().absolute()
    # Do not modify existing credentials or configurations, even when rerun.
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    protect_directory(root)
    token_file = root / "auth_token.txt"
    fd = os.open(str(token_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as token:
        token.write(secrets.token_urlsafe(48) + "\n")

    config = {
        "listen_host": "127.0.0.1",
        "listen_port": args.port,
        "agy_path": str(agy),
        "expected_sha512": expected,
        "client_version": args.client_version,
        "runtime_dir": str(root / "runtime"),
        "workspace_dir": str(root / "workspace"),
        "auth_token_file": str(token_file),
        "idle_timeout_sec": 1200,
        "turn_timeout_sec": 420,
        "watch_codex_ssh_daemon": False,
    }
    config_file = root / "bridge_config.json"
    fd = os.open(str(config_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(config, out, indent=2)
        out.write("\n")
    print("Created private configuration:", config_file)
    print("The bearer token is stored in a separate private file and was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
