#!/usr/bin/env python3
"""Register and switch the local Antigravity ACP provider in CC Switch.

Use local-status or status for live diagnostics. The optional SSH host for
status is read-only and uses ordinary SSH without forwarding.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any
import urllib.request
import uuid

PROVIDER_NAME_LOCAL = "Antigravity ACP (安全本地)"
DEFAULT_MODEL = "gemini-4-carbon"
LOCAL_BRIDGE_PORT = 18045
REMOTE_HELPERS = (
    '"$HOME/Library/Application Support/AntigravityAcpBridge/agy_ssh_lan.py"',
    '"$HOME/.local/share/AntigravityAcpBridge/agy_ssh_lan.py"',
)

BASE_INSTRUCTIONS = (
    "You are Codex, a coding agent. You and the user share the same workspace "
    "and collaborate to achieve the user's goals."
)

EFFORT_DESCRIPTIONS: dict[str, str] = {
    "low": "Fast responses with lighter reasoning",
    "medium": "Balances speed and reasoning depth for everyday tasks",
    "high": "Greater reasoning depth for complex problems",
}

GOOGLE_CATALOG_SPECS: list[dict[str, Any]] = [
    {
        "slug": "gemini-4-carbon",
        "display_name": "Gemini 4 Carbon (可调档位)",
        "levels": ["low", "medium", "high"],
        "default_level": "high",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-4-carbon-high",
        "display_name": "Gemini 4 Carbon (High)",
        "levels": ["high"],
        "default_level": "high",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-4-carbon-medium",
        "display_name": "Gemini 4 Carbon (Medium)",
        "levels": ["medium"],
        "default_level": "medium",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-4-carbon-low",
        "display_name": "Gemini 4 Carbon (Low)",
        "levels": ["low"],
        "default_level": "low",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-4-argon",
        "display_name": "Gemini 4 Argon (可调档位)",
        "levels": ["low", "medium", "high"],
        "default_level": "high",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-4-argon-high",
        "display_name": "Gemini 4 Argon (High)",
        "levels": ["high"],
        "default_level": "high",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-3.8-flash",
        "display_name": "Gemini 3.8 Flash (可调档位)",
        "levels": ["low", "medium", "high"],
        "default_level": "medium",
        "context_window": 1048576,
    },
    {
        "slug": "gemini-3.8-flash-high",
        "display_name": "Gemini 3.8 Flash (High)",
        "levels": ["high"],
        "default_level": "high",
        "context_window": 1048576,
    },
]


def default_bridge_root() -> Path:
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(local) / "AntigravityAcpBridge"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AntigravityAcpBridge"
    return Path.home() / ".local" / "share" / "AntigravityAcpBridge"


def build_ccswitch_catalog() -> list[dict[str, Any]]:
    models: list[dict[str, Any]] = []
    for spec in GOOGLE_CATALOG_SPECS:
        models.append(
            {
                "model": spec["slug"],
                "displayName": spec["display_name"],
                "contextWindow": spec["context_window"],
                "inputModalities": ["text", "image"],
                "reasoningLevels": list(spec["levels"]),
                "defaultReasoningLevel": spec["default_level"],
            }
        )
    return models


def build_codex_disk_catalog() -> dict[str, Any]:
    models: list[dict[str, Any]] = []
    for idx, spec in enumerate(GOOGLE_CATALOG_SPECS):
        cw = int(spec["context_window"])
        levels = [
            {"description": EFFORT_DESCRIPTIONS[lv], "effort": lv}
            for lv in spec["levels"]
        ]
        models.append(
            {
                "additional_speed_tiers": [],
                "auto_compact_token_limit": int(cw * 0.9),
                "availability_nux": None,
                "base_instructions": BASE_INSTRUCTIONS,
                "context_window": cw,
                "default_reasoning_level": spec["default_level"],
                "default_reasoning_summary": "none",
                "description": spec["display_name"],
                "display_name": spec["display_name"],
                "effective_context_window_percent": 95,
                "experimental_supported_tools": [],
                "input_modalities": ["text", "image"],
                "max_context_window": cw,
                "priority": 1000 + idx,
                "service_tiers": [],
                "shell_type": "shell_command",
                "slug": spec["slug"],
                "support_verbosity": False,
                "supported_in_api": True,
                "supported_reasoning_levels": levels,
                "supports_image_detail_original": False,
                "supports_parallel_tool_calls": False,
                "supports_reasoning_summaries": True,
                "supports_search_tool": False,
                "truncation_policy": {"limit": 10000, "mode": "bytes"},
                "upgrade": None,
                "visibility": "list",
            }
        )
    return {"models": models}


def _toml_path_literal(path: Path) -> str:
    s = str(path)
    if os.name == "nt":
        return "'" + s.replace("'", "''") + "'"
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_str(val: str) -> str:
    escaped = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def apply_provider_to_codex_config(
    existing_toml: str,
    *,
    model: str,
    effort: str,
    catalog_path: Path,
    base_url: str,
    bearer_token: str,
    provider_display_name: str = "Antigravity ACP",
) -> str:
    """Surgically update provider keys in `.codex/config.toml` while preserving MCP/projects/plugins/desktop."""
    lines = existing_toml.splitlines()
    first_table_idx = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("#"):
            first_table_idx = i
            break

    preamble = lines[:first_table_idx]
    rest = lines[first_table_idx:]

    managed_keys = {
        "model",
        "model_provider",
        "model_reasoning_effort",
        "model_catalog_json",
        "disable_response_storage",
    }
    kept_preamble: list[str] = []
    for line in preamble:
        m = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", line)
        if m and m.group(1) in managed_keys:
            continue
        kept_preamble.append(line)

    while kept_preamble and not kept_preamble[-1].strip():
        kept_preamble.pop()

    injected_preamble = [
        f"model_provider = {_toml_str('custom')}",
        f"model = {_toml_str(model)}",
        f"model_reasoning_effort = {_toml_str(effort)}",
        f"model_catalog_json = {_toml_path_literal(catalog_path)}",
        "disable_response_storage = true",
    ]
    new_preamble = kept_preamble + ([""] if kept_preamble else []) + injected_preamble + [""]

    # Remove existing `[model_providers.custom]` table block from `rest`, keep everything else
    filtered_rest: list[str] = []
    skipping_custom = False
    for line in rest:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("#"):
            if stripped == "[model_providers.custom]":
                skipping_custom = True
                continue
            skipping_custom = False
        if not skipping_custom:
            filtered_rest.append(line)

    custom_block = [
        "[model_providers.custom]",
        f"name = {_toml_str(provider_display_name)}",
        f"base_url = {_toml_str(base_url)}",
        'wire_api = "responses"',
        "requires_openai_auth = false",
        f"experimental_bearer_token = {_toml_str(bearer_token)}",
        "supports_websockets = false",
        "",
    ]

    combined = new_preamble + custom_block + filtered_rest
    return "\n".join(combined).rstrip() + "\n"


def _write_private_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    tmp.write_bytes(data)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _digest_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _row_digest(rows: list[Any]) -> str:
    return hashlib.sha256(json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _set_current_provider(settings_path: Path, provider_id: str | None) -> None:
    settings = json.loads(settings_path.read_text(encoding="utf-8-sig")) if settings_path.is_file() else {}
    if provider_id is None:
        settings.pop("currentProviderCodex", None)
    else:
        settings["currentProviderCodex"] = provider_id
    _write_private_file(settings_path, (json.dumps(settings, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def refresh_idle_ssh_codex_daemon() -> list[int] | None:
    """Reload configuration using Codex's daemon manager once SSH clients have disconnected."""
    if os.name == "nt":
        return []
    import fcntl

    codex_dir = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    local_cli = Path.home() / ".local" / "bin" / "codex"
    codex = str(local_cli) if local_cli.is_file() else shutil.which("codex")
    if not codex:
        return []
    control = codex_dir / "app-server-control"
    control.mkdir(parents=True, exist_ok=True)
    stamp = control / "agy-config-digest"
    with (control / "agy-refresh.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return None
        result = subprocess.run(
            ["ps", "-x", "-ww", "-o", "pid=,ppid=,command="],
            capture_output=True, text=True, check=True, timeout=5,
        )
        processes = []
        for line in result.stdout.splitlines():
            fields = line.split(None, 2)
            if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
                processes.append((int(fields[0]), int(fields[1]), fields[2]))

        codex_process = re.compile(r"^(?:[^\s]+/)?codex\s+(?:.*\s)?app-server\s+")
        servers: list[int] = []
        for pid, _, command in processes:
            match = codex_process.match(command)
            if match is None:
                continue
            arguments = command[match.end():].split()
            if arguments[:1] == ["proxy"]:
                return None
            if any(flag == "--listen" and address == "unix://" for flag, address in zip(arguments, arguments[1:])):
                servers.append(pid)
        if any(parent in servers and "mcp" not in command.lower() for _, parent, command in processes):
            return None

        digest = _row_digest([_digest_file(codex_dir / name) for name in ("config.toml", "cc-switch-model-catalog.json")])
        if servers and stamp.is_file() and stamp.read_text(encoding="ascii").strip() == digest:
            return []
        action = "restart" if servers else "start"
        subprocess.run(
            [codex, "-c", "features.code_mode_host=true", "app-server", "daemon", action],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=35,
        )
        if not (control / "app-server-control.sock").is_socket():
            raise RuntimeError("Codex daemon manager did not publish a control socket")
        _write_private_file(stamp, (digest + "\n").encode("ascii"))
        return servers


def register_or_update_ccswitch_provider(
    *,
    token: str,
    port: int = LOCAL_BRIDGE_PORT,
    provider_name: str = PROVIDER_NAME_LOCAL,
    default_model: str = DEFAULT_MODEL,
    activate: bool = False,
) -> dict[str, Any]:
    home = Path.home()
    db_path = home / ".cc-switch" / "cc-switch.db"
    codex_dir = home / ".codex"
    auth_path = codex_dir / "auth.json"
    cfg_path = codex_dir / "config.toml"
    cat_path = codex_dir / "cc-switch-model-catalog.json"
    state_path = home / ".cc-switch" / "agy-ssh-state.json"
    settings_path = db_path.with_name("settings.json")

    if not db_path.is_file():
        raise RuntimeError(f"CC Switch database not found at {db_path}")

    auth_before = _digest_file(auth_path)
    cfg_before = _digest_file(cfg_path)

    base_url = f"http://127.0.0.1:{port}/v1"
    cc_config_toml = (
        'model_provider = "custom"\n'
        f'model = "{default_model}"\n'
        'model_reasoning_effort = "high"\n'
        "disable_response_storage = true\n\n"
        "[model_providers.custom]\n"
        'name = "Antigravity ACP"\n'
        f'base_url = "{base_url}"\n'
        'wire_api = "responses"\n'
        "requires_openai_auth = true\n"
        "supports_websockets = false\n"
    )
    settings_obj = {
        "auth": {"OPENAI_API_KEY": token},
        "config": cc_config_toml,
        "modelCatalog": {"models": build_ccswitch_catalog()},
    }
    meta_obj = {
        "commonConfigEnabled": False,
        "endpointAutoSelect": False,
        "apiFormat": "openai_responses",
    }
    notes = (
        f"官方 Google 签名 agy ACP 本地安全网关 (127.0.0.1:{port})；"
        "零 OAuth 提取、禁用遥测、支持并行请求；默认 Gemini 4 Carbon。"
    )

    with sqlite3.connect(str(db_path), timeout=10, isolation_level=None) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        existing_row = conn.execute(
            "SELECT id, is_current FROM providers WHERE app_type='codex' AND name=?",
            (provider_name,),
        ).fetchone()
        provider_id = existing_row[0] if existing_row else f"agy-acp-{uuid.uuid4().hex[:12]}"

        other_before = conn.execute(
            "SELECT * FROM providers WHERE NOT (app_type='codex' AND id=?) ORDER BY app_type, id",
            (provider_id,),
        ).fetchall()
        cur_rows = conn.execute(
            "SELECT id, name FROM providers WHERE app_type='codex' AND is_current=1"
        ).fetchall()

        if existing_row:
            conn.execute(
                """UPDATE providers
                   SET settings_config=?, website_url=?, notes=?, meta=?
                   WHERE app_type='codex' AND id=?""",
                (
                    json.dumps(settings_obj, ensure_ascii=False, separators=(",", ":")),
                    "https://antigravity.google",
                    notes,
                    json.dumps(meta_obj, separators=(",", ":")),
                    provider_id,
                ),
            )
        else:
            rank = conn.execute("SELECT MAX(sort_index), COUNT(*) FROM providers WHERE app_type='codex'").fetchone()
            sort_idx = max(rank[0] if rank and rank[0] is not None else 0, rank[1] if rank else 0) + 1
            conn.execute(
                """INSERT INTO providers
                   (id, app_type, name, settings_config, website_url, category, created_at,
                    sort_index, notes, icon, icon_color, meta, is_current, in_failover_queue)
                   VALUES (?, 'codex', ?, ?, 'https://antigravity.google', NULL, ?,
                           ?, ?, NULL, NULL, ?, 0, 0)""",
                (
                    provider_id,
                    provider_name,
                    json.dumps(settings_obj, ensure_ascii=False, separators=(",", ":")),
                    int(time.time() * 1000),
                    sort_idx,
                    notes,
                    json.dumps(meta_obj, separators=(",", ":")),
                ),
            )

        if not activate:
            other_after = conn.execute(
                "SELECT * FROM providers WHERE NOT (app_type='codex' AND id=?) ORDER BY app_type, id",
                (provider_id,),
            ).fetchall()
            if _row_digest(other_before) != _row_digest(other_after):
                conn.execute("ROLLBACK")
                raise RuntimeError("Unexpected change in other provider rows; rolled back.")
        else:
            # Save prior state if we are transitioning from a non-Antigravity-ACP provider
            prev_non_agy = [r for r in cur_rows if r[0] != provider_id]
            if prev_non_agy or not state_path.is_file():
                settings = json.loads(settings_path.read_text(encoding="utf-8-sig")) if settings_path.is_file() else {}
                saved_state = {
                    "saved_at": int(time.time()),
                    "previous_provider_id": prev_non_agy[0][0] if prev_non_agy else (cur_rows[0][0] if cur_rows else None),
                    "previous_provider_name": prev_non_agy[0][1] if prev_non_agy else (cur_rows[0][1] if cur_rows else None),
                    "previous_settings_provider": settings.get("currentProviderCodex"),
                    "config_toml_b64": base64.b64encode(cfg_path.read_bytes()).decode("ascii") if cfg_path.is_file() else None,
                    "catalog_json_b64": base64.b64encode(cat_path.read_bytes()).decode("ascii") if cat_path.is_file() else None,
                    "auth_json_b64": base64.b64encode(auth_path.read_bytes()).decode("ascii") if auth_path.is_file() else None,
                }
                _write_private_file(state_path, json.dumps(saved_state, ensure_ascii=False, indent=2).encode("utf-8"))

            conn.execute("UPDATE providers SET is_current=0 WHERE app_type='codex'")
            conn.execute("UPDATE providers SET is_current=1 WHERE app_type='codex' AND id=?", (provider_id,))

        if activate:
            existing_toml = cfg_path.read_text(encoding="utf-8-sig") if cfg_path.is_file() else ""
            updated_toml = apply_provider_to_codex_config(
                existing_toml, model=default_model, effort="high", catalog_path=cat_path,
                base_url=base_url, bearer_token=token,
            )
            originals = {p: p.read_bytes() if p.is_file() else None for p in (cat_path, cfg_path, settings_path)}
            written: list[Path] = []
            try:
                for path, data in (
                    (cat_path, json.dumps(build_codex_disk_catalog(), ensure_ascii=False, indent=2).encode("utf-8")),
                    (cfg_path, updated_toml.encode("utf-8")),
                ):
                    _write_private_file(path, data)
                    written.append(path)
                _set_current_provider(settings_path, provider_id)
                written.append(settings_path)
                if _digest_file(auth_path) != auth_before:
                    raise RuntimeError("Codex auth.json changed during provider activation")
                conn.execute("COMMIT")
            except Exception:
                for path in reversed(written):
                    if originals[path] is None:
                        path.unlink(missing_ok=True)
                    else:
                        _write_private_file(path, originals[path])
                raise
        else:
            conn.execute("COMMIT")

    with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as ro:
        qc = ro.execute("PRAGMA quick_check").fetchone()[0]
        if qc != "ok":
            raise RuntimeError(f"SQLite quick_check failed: {qc}")

    reloaded_pids: list[int] | None = []
    if activate:
        reloaded_pids = refresh_idle_ssh_codex_daemon()
    else:
        if _digest_file(cfg_path) != cfg_before:
            raise RuntimeError("Live config.toml unexpectedly changed while activate=False")

    if _digest_file(auth_path) != auth_before:
        raise RuntimeError("~/.codex/auth.json digest changed unexpectedly!")

    return {
        "status": "activated" if activate else "registered",
        "provider_id": provider_id,
        "provider_name": provider_name,
        "port": port,
        "default_model": default_model,
        "db_quick_check": "ok",
        "auth_json_preserved": True,
        "reloaded_ssh_app_server_pids": reloaded_pids or [],
        "ssh_app_server_refresh_deferred": reloaded_pids is None,
    }


def local_disable() -> dict[str, Any]:
    home = Path.home()
    db_path = home / ".cc-switch" / "cc-switch.db"
    codex_dir = home / ".codex"
    auth_path = codex_dir / "auth.json"
    cfg_path = codex_dir / "config.toml"
    cat_path = codex_dir / "cc-switch-model-catalog.json"
    state_path = home / ".cc-switch" / "agy-ssh-state.json"

    if not state_path.is_file():
        return {"status": "noop", "reason": "no_saved_state"}

    state = json.loads(state_path.read_text(encoding="utf-8"))
    prev_id = state.get("previous_provider_id")
    prev_name = state.get("previous_provider_name")

    if state.get("config_toml_b64") is not None:
        _write_private_file(cfg_path, base64.b64decode(state["config_toml_b64"]))
    if state.get("catalog_json_b64") is not None:
        _write_private_file(cat_path, base64.b64decode(state["catalog_json_b64"]))
    elif cat_path.is_file():
        cat_path.unlink()
    if not auth_path.is_file() and state.get("auth_json_b64") is not None:
        _write_private_file(auth_path, base64.b64decode(state["auth_json_b64"]))

    if db_path.is_file() and prev_id:
        with sqlite3.connect(str(db_path), timeout=10, isolation_level=None) as conn:
            conn.execute("BEGIN IMMEDIATE")
            exists = conn.execute(
                "SELECT 1 FROM providers WHERE app_type='codex' AND id=?",
                (prev_id,),
            ).fetchone()
            if exists:
                conn.execute("UPDATE providers SET is_current=0 WHERE app_type='codex'")
                conn.execute("UPDATE providers SET is_current=1 WHERE app_type='codex' AND id=?", (prev_id,))
                _set_current_provider(db_path.with_name("settings.json"), state.get("previous_settings_provider", prev_id))
            conn.execute("COMMIT")

    reloaded_pids = refresh_idle_ssh_codex_daemon()
    return {
        "status": "restored",
        "restored_provider_id": prev_id,
        "restored_provider_name": prev_name,
        "auth_json_exists": auth_path.is_file(),
        "reloaded_ssh_app_server_pids": reloaded_pids or [],
        "ssh_app_server_refresh_deferred": reloaded_pids is None,
    }


def local_status() -> dict[str, Any]:
    home = Path.home()
    codex_dir = home / ".codex"
    cfg_path = codex_dir / "config.toml"
    auth_path = codex_dir / "auth.json"
    db_path = home / ".cc-switch" / "cc-switch.db"

    cur_provider = None
    if db_path.is_file():
        try:
            with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5) as ro:
                row = ro.execute("SELECT id, name FROM providers WHERE app_type='codex' AND is_current=1").fetchone()
                if row:
                    cur_provider = {"id": row[0], "name": row[1]}
        except Exception:
            pass

    cfg_model = None
    cfg_provider = None
    cfg_base_url = None
    if cfg_path.is_file():
        txt = cfg_path.read_text(encoding="utf-8", errors="replace")
        m_mod = re.search(r'^\s*model\s*=\s*"([^"]+)"', txt, re.MULTILINE)
        m_prv = re.search(r'^\s*model_provider\s*=\s*"([^"]+)"', txt, re.MULTILINE)
        m_url = re.search(r'^\s*base_url\s*=\s*"([^"]+)"', txt, re.MULTILINE)
        cfg_model = m_mod.group(1) if m_mod else None
        cfg_provider = m_prv.group(1) if m_prv else None
        cfg_base_url = m_url.group(1) if m_url else None

    health: dict[str, Any] | None = None
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{LOCAL_BRIDGE_PORT}/health", timeout=1.5) as resp:
            health = {"port": LOCAL_BRIDGE_PORT, **json.loads(resp.read().decode("utf-8"))}
    except (OSError, ValueError):
        pass

    return {
        "hostname": os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "windows"),
        "cc_switch_current": cur_provider,
        "codex_model": cfg_model,
        "codex_model_provider": cfg_provider,
        "codex_base_url": cfg_base_url,
        "auth_json_exists": auth_path.is_file(),
        "bridge_health": health,
    }


def remote_status(ssh_host: str) -> dict[str, Any]:
    """Read the target host's local status without enabling forwarding."""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", ssh_host):
        raise ValueError("Expected an SSH alias or user@hostname")
    ssh = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ClearAllForwardings=yes", ssh_host]
    run_options = {"capture_output": True, "timeout": 20, "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    installed = " ".join(
        f"if [ -f {path} ]; then exec /usr/bin/python3 -I -B {path} local-status; fi;"
        for path in REMOTE_HELPERS
    )
    res = subprocess.run([*ssh, installed + " exit 44"], input=b"", **run_options)
    if res.returncode == 44:
        res = subprocess.run([*ssh, "python3 -I -B - local-status"], input=Path(__file__).read_bytes(), **run_options)
    out = res.stdout.decode("utf-8", "replace").strip()
    if res.returncode != 0:
        err = res.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"SSH status for '{ssh_host}' failed (rc={res.returncode}): {err or out}")
    if not out:
        raise RuntimeError(f"SSH helper on '{ssh_host}' returned no status")
    return json.loads(out.splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Antigravity ACP local CC Switch helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_reg = sub.add_parser("register-ccswitch", help="Register/update Antigravity ACP provider in local CC Switch")
    p_reg.add_argument("--token-file", default=str(default_bridge_root() / "auth_token.txt"))
    p_reg.add_argument("--port", type=int, default=LOCAL_BRIDGE_PORT)
    p_reg.add_argument("--model", default=DEFAULT_MODEL)
    p_reg.add_argument("--activate", action="store_true")

    p_le = sub.add_parser("local-enable", help="Activate local Antigravity ACP provider safely")
    p_le.add_argument("--token-file", default=str(default_bridge_root() / "auth_token.txt"))
    p_le.add_argument("--port", type=int, default=LOCAL_BRIDGE_PORT)
    p_le.add_argument("--model", default=DEFAULT_MODEL)

    sub.add_parser("local-disable", help="Restore this host's prior CC Switch provider")
    sub.add_parser("local-status", help="Show local Codex, CC Switch and bridge status")
    sub.add_parser("refresh-ssh", help="Reload this host's SSH app-server when idle")

    p_st = sub.add_parser("status", help="Show local status and optional LAN SSH host status")
    p_st.add_argument("host", nargs="?")

    args = parser.parse_args()

    if args.cmd == "register-ccswitch":
        tok = Path(args.token_file).read_text(encoding="utf-8").strip()
        out = register_or_update_ccswitch_provider(
            token=tok,
            port=args.port,
            default_model=args.model,
            activate=args.activate,
        )
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if args.cmd == "local-enable":
        tok = Path(args.token_file).read_text(encoding="utf-8").strip()
        out = register_or_update_ccswitch_provider(
            token=tok,
            port=args.port,
            default_model=args.model,
            activate=True,
        )
        print(json.dumps(out, ensure_ascii=False))
        return 0

    if args.cmd == "local-disable":
        print(json.dumps(local_disable(), ensure_ascii=False))
        return 0

    if args.cmd == "local-status":
        print(json.dumps(local_status(), ensure_ascii=False))
        return 0

    if args.cmd == "refresh-ssh":
        return 3 if refresh_idle_ssh_codex_daemon() is None else 0

    if args.cmd == "status":
        result: dict[str, Any] = {"local": local_status()}
        if args.host:
            result["remote"] = remote_status(args.host)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
