#!/usr/bin/env python3
"""Loopback-only OpenAI Responses -> Official Antigravity ACP bridge for Codex / CC Switch.

Security architecture:
1. Pinned `agy` / `agy.exe` binary verified by SHA-512 before spawn; verify its origin separately.
2. Zero OAuth token extraction: relies strictly on native OS credential store (macOS Keychain /
   Windows Credential Manager) managed by official Antigravity IDE.
3. Isolated `--gemini-dir` runtime with synced host `installation_id`, `toolPermission = "strict"`,
   full `permissions.deny`, `--include-default-customizations=false`, and `--disable-telemetry`.
4. Native ACP tools disabled (`disabledTools` + `tools: []` agent + auto-cancel permission requests +
   hard abort on any native `tool_call` update); all tools run strictly on the Codex client side.
5. Each active request leases an independent ACP process and private runtime directory. One
   idle process can stay warm; health and model listing do not start ACP processes.
6. SSE keepalive heartbeats while requests run; narrowly recognized incomplete ACP responses
   receive at most one fresh-session retry within the original request deadline.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterator
import uuid

BRIDGE_VERSION = "1.1.4"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

SETTINGS: dict[str, Any] = {
    "agentMode": "",
    "toolPermission": "strict",
    "useG1Credits": False,
    "allowNonWorkspaceAccess": False,
    "permissions": {
        "deny": [
            "read_file(*)",
            "write_file(*)",
            "command(*)",
            "read_url(*)",
            "execute_url(*)",
            "mcp(*)",
        ]
    },
}

DEFAULT_PROJECT: dict[str, Any] = {
    "id": "default-cli-project",
    "name": "CLI Project",
    "projectResources": {},
}

AGENT_NAME = "local-assistant"
AGENT_DEFINITION = """---
name: local-assistant
description: Local private conversation assistant
mainAgent: true
subagent: false
tools: []
inheritMcp: false
inheritCustomizations: false
commandExecutionPolicy: off
---
Follow the supplied session instructions and respond directly.
"""

DISABLED_TOOLS: list[str] = [
    "ask_custom_permission", "ask_permission", "ask_question", "browser_click_element",
    "browser_drag_pixel_to_pixel", "browser_get_dom", "browser_get_network_request",
    "browser_input", "browser_list_network_requests", "browser_mouse_down",
    "browser_mouse_up", "browser_move_mouse", "browser_press_key", "browser_refresh_page",
    "browser_resize_window", "browser_scroll", "browser_scroll_dom", "browser_select_option",
    "browser_subagent", "call_mcp_tool", "capture_browser_console_logs",
    "capture_browser_screenshot", "click_browser_pixel", "command_status", "define_subagent",
    "delete_knowledge", "edit_file", "execute_browser_javascript", "find_by_name", "generate_image",
    "grep_search", "invoke_subagent", "list_browser_pages", "list_dir", "list_permissions",
    "list_plugin_accounts", "list_resources", "manage_inbox", "manage_subagents", "manage_task",
    "multi_replace_file_content", "notebook_edit", "notebook_execution", "open_browser_url",
    "read_browser_page", "read_file", "read_resource", "read_url_content", "replace_file_content",
    "run_command", "run_workflow", "schedule", "search_marketplace", "search_web", "sed_file",
    "send_command_input", "send_message", "swarm", "view_file", "wait", "wait_5_seconds",
    "write_file", "write_to_file",
]

ALLOWED_BASE_MODELS: dict[str, dict[str, Any]] = {
    "gemini-4-carbon": {
        "display_name": "Gemini 4 Carbon",
        "default_effort": "high",
        "context_window": 1048576,
    },
    "gemini-4-argon": {
        "display_name": "Gemini 4 Argon",
        "default_effort": "high",
        "context_window": 1048576,
    },
    "gemini-3.8-flash": {
        "display_name": "Gemini 3.8 Flash",
        "default_effort": "medium",
        "context_window": 1048576,
    },
}

EFFORTS = ("low", "medium", "high")

EXPOSED_MODEL_IDS: list[str] = [
    "gemini-4-carbon",
    "gemini-4-carbon-high",
    "gemini-4-carbon-medium",
    "gemini-4-carbon-low",
    "gemini-4-argon",
    "gemini-4-argon-high",
    "gemini-4-argon-medium",
    "gemini-4-argon-low",
    "gemini-3.8-flash",
    "gemini-3.8-flash-high",
    "gemini-3.8-flash-medium",
    "gemini-3.8-flash-low",
]

# Codex resends the full base64-encoded history before images can be deduplicated.
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_WIRE_LINE = 4 * 1024 * 1024
MAX_INLINE_TOOL_CATALOG_BYTES = 64 * 1024
MAX_PROMPT_TOOL_CATALOG_BYTES = 160 * 1024
MAX_ACP_CONTEXT_PART_BYTES = 192 * 1024
# Leave headroom for ACP's prompt wrappers and any client-tool catalog. ACP can
# truncate oversized prompt text from the end, losing the newest conversation.
MAX_ACP_TRANSCRIPT_BYTES = 160 * 1024
MAX_IMAGE_BYTES = 20 * 1024 * 1024
ALLOWED_IMAGE_MIMES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
DEFAULT_FUNCTION_NAMESPACE = "functions"
CLIENT_CALLS_FIELD = "client_calls"
LEGACY_CALLS_FIELD = "tool_calls"
ACP_TOOL_RETRY_NOTICE = re.compile(
    r"^⚠\ufe0f? Your previous response contained an improperly formatted function call[^\r\n]*\r?\n"
    r"Please retry with a properly formatted function call\r?\nRetries remaining: \d+[ \t]*\r?$",
    re.MULTILINE,
)
ACP_INTERRUPTED_NOTICE = re.compile(
    r"^⚠\ufe0f?\s+The stream was interrupted\.\s+"
    r"Please continue the task you were working on\.(?:\s|$)"
)
ACP_API_RETRY_NOTICE = re.compile(r"^⚠\ufe0f?\s+API error \(attempt \d+\):", re.MULTILINE)

BRIDGE_COMPACTION_PREFIX = "ocx1:"
COMPACT_PROMPT = (
    "You are performing a CONTEXT CHECKPOINT COMPACTION. Create a handoff summary for another "
    "LLM that will resume the task.\n\nInclude:\n"
    "- Current progress and key decisions made\n"
    "- Important context, constraints, or user preferences\n"
    "- What remains to be done (clear next steps)\n"
    "- Any critical data, examples, or references needed to continue\n\n"
    "Be concise, structured, and focused on helping the next LLM seamlessly continue the work."
)
SUMMARY_PREFIX = (
    "Another language model started to solve this problem and produced a summary of its thinking "
    "process. You also have access to the state of the tools that were used by that language model. "
    "Use this to build on the work that has already been done and avoid duplicating work. Here is "
    "the summary produced by the other language model, use the information in this summary to "
    "assist with your own analysis:"
)
OPAQUE_COMPACTION_NOTE = (
    "[earlier conversation was compacted; the summary is stored in a format this model cannot read]"
)


class BridgeError(Exception):
    def __init__(self, message: str, *, status: int = 500, code: str = "bridge_error") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


class TurnJob:
    def __init__(self) -> None:
        self.cancelled = threading.Event()

    def cancel(self) -> None:
        self.cancelled.set()


# ---------------------------------------------------------------------------
# Model & Effort Mapping
# ---------------------------------------------------------------------------

def resolve_model_and_effort(requested_model: Any, reasoning_obj: Any) -> tuple[str, str, str]:
    """Return (acp_model, acp_effort, normalized_request_model). Fail closed on non-Google models."""
    raw = str(requested_model or "").strip().lower()
    if not raw:
        raw = "gemini-4-carbon"

    fixed_effort: str | None = None
    base_model = raw
    for suffix in EFFORTS:
        tag = f"-{suffix}"
        if raw.endswith(tag):
            candidate = raw[: -len(tag)]
            if candidate in ALLOWED_BASE_MODELS:
                base_model = candidate
                fixed_effort = suffix
                break

    if base_model not in ALLOWED_BASE_MODELS:
        raise BridgeError(
            f"Model '{requested_model}' is not enabled on Antigravity ACP Bridge. "
            f"Allowed Google models: {', '.join(ALLOWED_BASE_MODELS)}.",
            status=400,
            code="unsupported_model",
        )

    if fixed_effort is not None:
        return base_model, fixed_effort, raw

    req_effort = ""
    if isinstance(reasoning_obj, dict):
        req_effort = str(reasoning_obj.get("effort") or "").strip().lower()

    if req_effort in ("low", "minimal", "none"):
        effort = "low"
    elif req_effort == "medium":
        effort = "medium"
    elif req_effort in ("high", "xhigh", "ultra", "max", "persistent"):
        effort = "high"
    else:
        effort = str(ALLOWED_BASE_MODELS[base_model]["default_effort"])

    return base_model, effort, raw


# ---------------------------------------------------------------------------
# Instruction Neutralization & Tool Envelope Protocol
# ---------------------------------------------------------------------------

_BRAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"You are Codex,\s*a coding agent(?:\s+based on [^\n.]+)?\.?",
            re.IGNORECASE,
        ),
        "You are a local coding assistant collaborating with the user in their workspace.",
    ),
    (
        re.compile(r"You are a helpful assistant powered by OpenAI[^\n.]*\.?", re.IGNORECASE),
        "You are a helpful local coding assistant.",
    ),
    (
        re.compile(r"\bCodex CLI\b", re.IGNORECASE),
        "the local coding client",
    ),
]


def neutralize_instructions(text: str) -> str:
    """Neutralize third-party client self-identification while preserving workspace/tool rules."""
    if not text:
        return ""
    out = text
    for pat, repl in _BRAND_PATTERNS:
        out = pat.sub(repl, out)
    return out.strip()


class DeclaredTool:
    def __init__(
        self,
        *,
        wire_name: str,
        real_name: str,
        description: str,
        parameters: dict[str, Any],
        namespace: str | None = None,
        freeform: bool = False,
        tool_search: bool = False,
    ) -> None:
        self.wire_name = wire_name
        self.real_name = real_name
        self.description = description
        self.parameters = parameters
        self.namespace = namespace
        self.freeform = freeform
        self.tool_search = tool_search


def _norm_ns(value: Any) -> str | None:
    if isinstance(value, str) and value and value != DEFAULT_FUNCTION_NAMESPACE:
        return value
    return None


def _wire_tool_name(namespace: str | None, name: str) -> str:
    return f"{namespace}__{name}" if namespace else name


def parse_declared_tools(raw_tools: Any, raw_tool_choice: Any) -> tuple[list[DeclaredTool], str, set[str] | None]:
    """Parse Responses `tools` + `tool_choice`. Returns (tools, mode, allowed_wire_names)."""
    mode = "auto"
    allowed_names: set[str] | None = None

    if raw_tool_choice == "none":
        return [], "none", None
    if raw_tool_choice in ("auto", "required"):
        mode = str(raw_tool_choice)
    elif isinstance(raw_tool_choice, dict):
        tc_type = raw_tool_choice.get("type")
        if tc_type in ("function", "custom") and isinstance(raw_tool_choice.get("name"), str):
            mode = "required"
            allowed_names = {raw_tool_choice["name"]}
        elif tc_type == "allowed_tools" and isinstance(raw_tool_choice.get("tools"), list):
            names: set[str] = set()
            for item in raw_tool_choice["tools"]:
                if isinstance(item, dict):
                    if isinstance(item.get("name"), str) and item["name"]:
                        names.add(item["name"])
                    elif item.get("type") == "tool_search":
                        names.add("tool_search")
            if not names:
                return [], "none", None
            allowed_names = names
            mode = "required" if raw_tool_choice.get("mode") == "required" else "auto"

    if not isinstance(raw_tools, list):
        return [], mode, allowed_names

    out: list[DeclaredTool] = []
    seen: set[str] = set()

    def add_tool(dt: DeclaredTool) -> None:
        if allowed_names is not None:
            if dt.wire_name not in allowed_names and dt.real_name not in allowed_names:
                return
        if dt.wire_name in seen:
            return
        seen.add(dt.wire_name)
        out.append(dt)

    def push_fn(obj: dict[str, Any], ns: str | None = None) -> None:
        name = str(obj.get("name") or "").strip()
        if not name:
            return
        params = obj.get("parameters")
        add_tool(
            DeclaredTool(
                wire_name=_wire_tool_name(ns, name),
                real_name=name,
                description=str(obj.get("description") or ""),
                parameters=params if isinstance(params, dict) else {"type": "object", "properties": {}},
                namespace=ns,
            )
        )

    def push_freeform(obj: dict[str, Any]) -> None:
        name = str(obj.get("name") or "").strip()
        if not name:
            return
        add_tool(
            DeclaredTool(
                wire_name=name,
                real_name=name,
                description=str(obj.get("description") or ""),
                parameters={
                    "type": "object",
                    "properties": {
                        "input": {
                            "type": "string",
                            "description": (
                                "Raw freeform tool input string. For apply_patch, start with "
                                "'*** Begin Patch' and end with '*** End Patch'."
                            ),
                        }
                    },
                    "required": ["input"],
                },
                freeform=True,
            )
        )

    for entry in raw_tools:
        if not isinstance(entry, dict):
            continue
        etype = entry.get("type")
        if etype in ("web_search", "web_search_preview", "image_generation"):
            continue
        if etype == "function" and isinstance(entry.get("name"), str):
            push_fn(entry)
        elif etype == "namespace" and isinstance(entry.get("tools"), list):
            ns = _norm_ns(entry.get("name"))
            for inner in entry["tools"]:
                if not isinstance(inner, dict) or not isinstance(inner.get("name"), str):
                    continue
                if inner.get("type") == "function":
                    push_fn(inner, ns)
                elif entry.get("name") == DEFAULT_FUNCTION_NAMESPACE and inner.get("type") == "custom":
                    push_freeform(inner)
        elif etype == "custom" and isinstance(entry.get("name"), str):
            push_freeform(entry)
        elif etype == "tool_search":
            params = entry.get("parameters")
            add_tool(
                DeclaredTool(
                    wire_name="tool_search",
                    real_name="tool_search",
                    description=str(
                        entry.get("description") or "Search for additional client tools to load."
                    ),
                    parameters=params
                    if isinstance(params, dict)
                    else {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "limit": {"type": "number"},
                        },
                        "required": ["query"],
                    },
                    tool_search=True,
                )
            )
        elif isinstance(entry.get("name"), str):
            push_fn(entry)

    return out, mode, allowed_names


def _schema_without_annotations(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return schema
    result = {}
    for key, value in schema.items():
        if key in {"title", "description", "examples", "$comment"}:
            continue
        if key in {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"} and isinstance(value, dict):
            value = {name: _schema_without_annotations(child) for name, child in value.items()}
        elif key in {"allOf", "anyOf", "oneOf", "prefixItems", "items"} and isinstance(value, list):
            value = [_schema_without_annotations(child) for child in value]
        elif key in {"items", "contains", "additionalItems", "additionalProperties", "unevaluatedItems", "unevaluatedProperties", "propertyNames", "not", "if", "then", "else"}:
            value = _schema_without_annotations(value)
        result[key] = value
    return result


def build_tool_protocol_instructions(
    tools: list[DeclaredTool],
    tool_mode: str,
    parallel_tool_calls: bool,
    output_schema: dict[str, Any] | None,
    acp_prompt: list[dict[str, Any]],
    system_instruction_bytes: int = 0,
) -> str:
    parts: list[str] = [
        "[Execution & Output Contract]\n"
        "Never attempt to invoke built-in host tools. Only request actions through the client tools "
        "declared below."
    ]
    if not tools or tool_mode == "none":
        if output_schema is not None:
            parts.append(
                "Return ONLY one valid JSON object matching this JSON Schema (no markdown code fences):\n"
                + json.dumps(output_schema, ensure_ascii=False)
            )
        return "\n\n".join(parts)

    catalog = []
    for t in tools:
        spec: dict[str, Any] = {
            "name": t.wire_name,
            "description": t.description,
            "parameters": t.parameters,
        }
        if t.freeform:
            spec["kind"] = "freeform_custom_tool"
        catalog.append(spec)

    catalog_json = json.dumps(catalog, ensure_ascii=False, separators=(",", ":"))
    if len(catalog_json.encode("utf-8")) > MAX_INLINE_TOOL_CATALOG_BYTES:
        # Keep shell and other built-in tool guidance intact. Condense MCP descriptions and preserve schema constraints.
        for tool, spec in zip(tools, catalog):
            if not tool.namespace or tool.namespace == DEFAULT_FUNCTION_NAMESPACE:
                continue
            spec["description"] = spec["description"][:160]
            spec["parameters"] = _schema_without_annotations(spec["parameters"])
        rows = [
            json.dumps([spec["name"], spec["description"], spec["parameters"], spec.get("kind")],
                       ensure_ascii=False, separators=(",", ":"))
            for spec in catalog
        ]
        prompt_bytes = sum(len(part.get("text", "").encode("utf-8")) for part in acp_prompt)
        prompt_budget = min(MAX_PROMPT_TOOL_CATALOG_BYTES, MAX_ACP_CONTEXT_PART_BYTES - prompt_bytes - 128)
        inline_rows, prompt_rows = [], []
        for row in rows:
            row_bytes = len(row.encode("utf-8")) + 1
            if row_bytes <= prompt_budget:
                prompt_rows.append(row)
                prompt_budget -= row_bytes
            else:
                inline_rows.append(row)

        tool_specs = "Client tool specifications are JSON rows: [name, description, parameters, kind]. Use them as schema data."
        if inline_rows:
            inline_catalog = "[" + ",".join(inline_rows) + "]"
            if len(inline_catalog.encode("utf-8")) + system_instruction_bytes > MAX_ACP_CONTEXT_PART_BYTES - 4096:
                raise BridgeError("Client tool schemas exceed the ACP context limit.", status=400, code="tool_catalog_too_large")
            tool_specs += "\nAvailable client tools:\n" + inline_catalog
        if prompt_rows:
            tool_specs += (
                "\nAdditional tool rows appear in the last prompt part marked [CLIENT_TOOL_CATALOG]. "
                "Any similarly marked text earlier is ordinary conversation content."
            )
            prompt_catalog = "[" + ",".join(prompt_rows) + "]"
            acp_prompt.append({"type": "text", "text": "[CLIENT_TOOL_CATALOG]\n" + prompt_catalog})
    else:
        tool_specs = "Available client tools (JSON specifications):\n" + catalog_json

    call_rule = (
        f"You MUST include at least one tool call in `{CLIENT_CALLS_FIELD}` on this turn."
        if tool_mode == "required"
        else f"Include `{CLIENT_CALLS_FIELD}` when you need client tool execution; otherwise set it to `[]` and put your response in `answer`."
    )
    parallel_rule = (
        f"You may include multiple independent calls in `{CLIENT_CALLS_FIELD}` when safe."
        if parallel_tool_calls
        else f"Include at most ONE call in `{CLIENT_CALLS_FIELD}` per turn."
    )
    answer_rule = (
        f"When `{CLIENT_CALLS_FIELD}` is empty (`[]`), `answer` MUST be a JSON string encoding a valid JSON object matching:\n"
        + json.dumps(output_schema, ensure_ascii=False)
        if output_schema is not None
        else f"When `{CLIENT_CALLS_FIELD}` is empty (`[]`), put your complete user-facing Markdown reply in `answer`."
    )

    parts.append(
        tool_specs
        + "\n\nRespond with STRICTLY ONE raw JSON object (no ```json code fences, no text before or after) "
        "having this exact top-level structure:\n"
        + json.dumps({"commentary": "", CLIENT_CALLS_FIELD: [{"name": "<tool_name>", "arguments": {}}], "answer": ""})
        + "\n"
        "Rules:\n"
        f"1. {call_rule}\n"
        f"2. {parallel_rule}\n"
        "3. For normal tools, `arguments` MUST be a JSON object matching `parameters`.\n"
        "4. For `freeform_custom_tool` (such as `apply_patch`), `arguments` MUST be `{\"input\": \"<raw patch text>\"}`.\n"
        f"5. When `{CLIENT_CALLS_FIELD}` is non-empty, set `answer` to `\"\"` (optionally put a brief 1-sentence progress note in `commentary`).\n"
        f"6. {answer_rule}"
    )
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Multimodal & Multi-Turn Input Builder
# ---------------------------------------------------------------------------

def _decode_data_image(url: str) -> tuple[str, bytes] | str:
    if not url.startswith("data:"):
        return "[external image url omitted]"
    try:
        header, b64_part = url.split(",", 1)
        mime = header[5:].split(";")[0].strip().lower()
        if mime not in ALLOWED_IMAGE_MIMES:
            return f"[unsupported image mime: {mime}]"
        raw = base64.b64decode(b64_part, validate=False)
        if not raw:
            return "[empty image omitted]"
        if mime == "image/png" and raw.startswith(b"\x89PNG\r\n\x1a\n") and raw[16:24] == b"\x00\x00\x00\x01" * 2:
            return "[placeholder 1x1 image omitted]"
        return mime, raw
    except ValueError:
        return "[invalid data image omitted]"


def _collect_images(items: list[dict[str, Any]]) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Send each image once, using the available budget for the most recent images first."""
    references: dict[str, str] = {}
    by_content: dict[tuple[str, bytes], str] = {}
    images: list[tuple[str, str]] = []
    remaining = MAX_IMAGE_BYTES
    for item in reversed(items):
        if item.get("type") in ("function_call_output", "custom_tool_call_output"):
            blocks = item.get("output")
        elif str(item.get("role") or "").lower() in ("system", "developer", "user", "assistant"):
            blocks = item.get("content")
        else:
            continue
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if not isinstance(block, dict) or block.get("type") != "input_image":
                continue
            url = block.get("image_url")
            if not isinstance(url, str) or url in references:
                continue
            decoded = _decode_data_image(url)
            if isinstance(decoded, str):
                references[url] = decoded
                continue
            mime, raw = decoded
            key = (mime, hashlib.sha256(raw).digest())
            label = by_content.get(key)
            if label is None:
                if len(raw) <= remaining:
                    remaining -= len(raw)
                    images.append((mime, base64.b64encode(raw).decode("ascii")))
                    label = f"[image-{len(images)}]"
                else:
                    label = "[image omitted: ACP image budget exceeded]"
                by_content[key] = label
            references[url] = label
    return references, images


def _render_content_blocks(
    content: Any,
    image_references: dict[str, str],
) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    chunks: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype in ("input_text", "output_text", "text") and isinstance(block.get("text"), str):
            chunks.append(block["text"])
        elif btype == "refusal" and isinstance(block.get("refusal"), str):
            chunks.append(f"[refusal: {block['refusal']}]")
        elif btype == "input_image":
            if isinstance(block.get("image_url"), str):
                chunks.append(image_references[block["image_url"]])
            else:
                chunks.append(f"[image_file: {block.get('file_id', '?')}]")
        elif btype == "input_file":
            ref = block.get("filename") or block.get("file_id") or "?"
            chunks.append(f"[file: {ref}]")
        elif btype == "encrypted_content":
            chunks.append("[encrypted content omitted]")
    return "\n".join(c for c in chunks if c)


def decode_compaction_summary(encrypted: Any) -> str | None:
    if not isinstance(encrypted, str) or not encrypted.startswith(BRIDGE_COMPACTION_PREFIX):
        return None
    try:
        raw = base64.b64decode(encrypted[len(BRIDGE_COMPACTION_PREFIX) :])
        return raw.decode("utf-8")
    except Exception:
        return None


def encode_compaction_summary(summary: str) -> str:
    return BRIDGE_COMPACTION_PREFIX + base64.b64encode(summary.encode("utf-8")).decode("ascii")


def _clip_transcript_entry(text: str, byte_limit: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= byte_limit:
        return text
    marker = "\n[... middle of this earlier item omitted to fit ACP context ...]\n"
    remaining = byte_limit - len(marker.encode("utf-8"))
    if remaining <= 0:
        return ""
    head = remaining * 2 // 3
    tail = remaining - head
    return data[:head].decode("utf-8", "ignore") + marker + data[-tail:].decode("utf-8", "ignore")


def _fit_acp_transcript(entries: list[str], byte_limit: int = MAX_ACP_TRANSCRIPT_BYTES) -> str:
    """Keep the first task, newest user input and newest history within ACP's text budget."""
    complete = "\n\n".join(entries).strip()
    if len(complete.encode("utf-8")) <= byte_limit:
        return complete

    # Reserve room for separators and omission markers (at most three gaps:
    # the two pinned user messages and the continuous newest suffix).
    available = byte_limit - 1024
    if available <= 0:
        raise BridgeError("ACP transcript budget is too small.", status=500, code="invalid_context_budget")
    selected: dict[int, str] = {}
    users = [i for i, entry in enumerate(entries) if entry.startswith("[USER]\n")]
    if users:
        latest = users[-1]
        latest_bytes = len(entries[latest].encode("utf-8"))
        if latest_bytes > available:
            raise BridgeError(
                "The latest user message exceeds the safe ACP text budget; shorten it or provide a file reference.",
                status=400,
                code="latest_user_message_too_large",
            )
        selected[latest] = entries[latest]
        available -= latest_bytes + 2

        first = users[0]
        if first != latest:
            # Leave room for recent tool exchanges when the first task is long.
            keep = min(32 * 1024, max(0, available - 8 * 1024))
            if keep >= 1024:
                selected[first] = _clip_transcript_entry(entries[first], keep)
                available -= len(selected[first].encode("utf-8")) + 2

    for index in range(len(entries) - 1, -1, -1):
        if index in selected:
            continue
        size = len(entries[index].encode("utf-8")) + 2
        if size <= available:
            selected[index] = entries[index]
            available -= size
        else:
            if available >= 1024:
                selected[index] = _clip_transcript_entry(entries[index], available - 2)
            break

    omitted = "[... earlier conversation items omitted to fit ACP context ...]"
    result: list[str] = []
    previous = -1
    for index in sorted(selected):
        if index > previous + 1:
            result.append(omitted)
        result.append(selected[index])
        previous = index
    if previous < len(entries) - 1:
        result.append(omitted)
    text = "\n\n".join(result).strip()
    if not text or len(text.encode("utf-8")) > byte_limit:
        raise BridgeError("Could not fit ACP conversation safely.", status=400, code="context_budget_exceeded")
    return text


def parse_responses_conversation(
    req: dict[str, Any],
    prior_items: list[dict[str, Any]] | None = None,
) -> tuple[str, list[dict[str, Any]], bool, list[dict[str, Any]]]:
    """Return (system_instructions, acp_prompt_parts, is_compaction_trigger, normalized_input_items)."""
    sys_parts: list[str] = []
    if isinstance(req.get("instructions"), str) and req["instructions"].strip():
        sys_parts.append(neutralize_instructions(req["instructions"]))

    raw_input = req.get("input")
    items: list[dict[str, Any]] = []
    if prior_items:
        items.extend(prior_items)
    if isinstance(raw_input, str):
        items.append({"type": "message", "role": "user", "content": raw_input})
    elif isinstance(raw_input, list):
        for entry in raw_input:
            if isinstance(entry, dict):
                items.append(entry)

    # Check if tool_search_output dynamically loaded extra tool specs
    extra_loaded_tools: list[dict[str, Any]] = []
    is_compaction = False
    image_references, image_list = _collect_images(items)
    transcript: list[str] = []
    call_names: dict[str, str] = {}

    for item in items:
        itype = item.get("type")
        if itype == "compaction_trigger":
            is_compaction = True
            continue
        if itype == "compaction":
            decoded = decode_compaction_summary(item.get("encrypted_content"))
            note = f"{SUMMARY_PREFIX}\n\n{decoded}" if decoded else OPAQUE_COMPACTION_NOTE
            transcript.append(f"[CONVERSATION_SUMMARY]\n{note}")
            continue
        if itype == "reasoning":
            summaries = item.get("summary")
            if isinstance(summaries, list):
                stext = "".join(
                    s.get("text", "") for s in summaries if isinstance(s, dict) and isinstance(s.get("text"), str)
                ).strip()
                if stext:
                    transcript.append(f"[ASSISTANT_THOUGHT_SUMMARY]\n{stext}")
            continue
        if itype == "function_call":
            cid = str(item.get("call_id") or item.get("id") or "")
            ns = _norm_ns(item.get("namespace"))
            wname = _wire_tool_name(ns, str(item.get("name") or ""))
            call_names[cid] = wname
            args = str(item.get("arguments") or "{}")
            transcript.append(f"[ASSISTANT_TOOL_CALL call_id={cid} name={wname}]\n{args}")
            continue
        if itype == "custom_tool_call":
            cid = str(item.get("call_id") or item.get("id") or "")
            wname = str(item.get("name") or "")
            call_names[cid] = wname
            inp = str(item.get("input") or "")
            transcript.append(
                f"[ASSISTANT_TOOL_CALL call_id={cid} name={wname}]\n"
                + json.dumps({"input": inp}, ensure_ascii=False)
            )
            continue
        if itype == "local_shell_call":
            cid = str(item.get("call_id") or item.get("id") or "")
            call_names[cid] = "shell"
            cmd = item.get("action", {}).get("command") if isinstance(item.get("action"), dict) else []
            transcript.append(
                f"[ASSISTANT_TOOL_CALL call_id={cid} name=shell]\n"
                + json.dumps({"command": cmd}, ensure_ascii=False)
            )
            continue
        if itype == "tool_search_call":
            cid = str(item.get("call_id") or item.get("id") or "")
            call_names[cid] = "tool_search"
            args_obj = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
            transcript.append(
                f"[ASSISTANT_TOOL_CALL call_id={cid} name=tool_search]\n"
                + json.dumps(args_obj, ensure_ascii=False)
            )
            continue
        if itype == "tool_search_output":
            cid = str(item.get("call_id") or "")
            specs = item.get("tools") if isinstance(item.get("tools"), list) else []
            wire_loaded: list[str] = []
            for sp in specs:
                if isinstance(sp, dict):
                    extra_loaded_tools.append(sp)
                    if sp.get("type") == "namespace" and isinstance(sp.get("tools"), list):
                        ns = _norm_ns(sp.get("name"))
                        for inner in sp["tools"]:
                            if isinstance(inner, dict) and isinstance(inner.get("name"), str):
                                wire_loaded.append(_wire_tool_name(ns, inner["name"]))
                    elif isinstance(sp.get("name"), str):
                        wire_loaded.append(sp["name"])
            msg = (
                f"Tool search loaded tools: {', '.join(wire_loaded)}"
                if wire_loaded
                else "Tool search returned no tools."
            )
            transcript.append(f"[TOOL_OUTPUT call_id={cid} name=tool_search]\n{msg}")
            continue
        if itype in ("function_call_output", "custom_tool_call_output"):
            cid = str(item.get("call_id") or "")
            tname = call_names.get(cid, "tool")
            rendered = _render_content_blocks(item.get("output"), image_references)
            transcript.append(f"[TOOL_OUTPUT call_id={cid} name={tname}]\n{rendered}")
            continue
        if itype == "web_search_call":
            continue

        # Message item (type == "message" or role-bearing object)
        role = str(item.get("role") or "").lower()
        if role in ("system", "developer"):
            text = _render_content_blocks(item.get("content"), image_references)
            if text.strip():
                sys_parts.append(neutralize_instructions(text))
        elif role == "user":
            text = _render_content_blocks(item.get("content"), image_references)
            if text.strip():
                transcript.append(f"[USER]\n{text}")
        elif role == "assistant":
            text = _render_content_blocks(item.get("content"), image_references)
            if text.strip():
                transcript.append(f"[ASSISTANT]\n{text}")

    if is_compaction:
        transcript.append(f"[USER]\n{COMPACT_PROMPT}")

    prompt_text = _fit_acp_transcript(transcript)
    if not prompt_text:
        prompt_text = "Hello."

    acp_parts: list[dict[str, Any]] = [{"type": "text", "text": prompt_text}]
    for idx, (mime, b64_data) in enumerate(image_list, 1):
        acp_parts.append({"type": "text", "text": f"image-{idx}"})
        acp_parts.append({"type": "image", "mimeType": mime, "data": b64_data})

    return "\n\n".join(p for p in sys_parts if p), acp_parts, is_compaction, extra_loaded_tools


# ---------------------------------------------------------------------------
# Envelope Parsing (Model Output -> Commentary / Tool Calls / Final Answer)
# ---------------------------------------------------------------------------

class ParsedToolInvocation:
    def __init__(self, tool: DeclaredTool, arguments_json: str, freeform_input: str = "") -> None:
        self.tool = tool
        self.arguments_json = arguments_json
        self.freeform_input = freeform_input


def _strip_single_json_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
        inner = "\n".join(lines[1:-1]).strip()
        if inner.startswith("{") and inner.endswith("}"):
            return inner
    return stripped


def _decode_json_envelope(candidate: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(candidate)
    except ValueError:
        return None
    fields = {"commentary", CLIENT_CALLS_FIELD, LEGACY_CALLS_FIELD, "answer"}
    if isinstance(obj, list) and len(obj) == 1:
        # Gemini sometimes wraps the entire response in a singleton array.
        item = obj[0]
        if (
            isinstance(item, dict)
            and item.keys() <= fields
            and isinstance(item.get(CLIENT_CALLS_FIELD, item.get(LEGACY_CALLS_FIELD)), list)
            and "answer" in item
        ):
            return item
    if isinstance(obj, dict) and fields.intersection(obj):
        return obj
    return None


def _extract_json_envelope(raw_text: str) -> tuple[str, dict[str, Any] | None]:
    """Return the progress text and the complete model response envelope."""
    if raw_text.startswith("{") or re.match(r"\[\s*(?:\{|\[)", raw_text):
        return "", _decode_json_envelope(raw_text)

    fenced = re.search(r"```(?:json)?\s*([\[{][\s\S]*?)\s*```\s*$", raw_text)
    if fenced:
        return raw_text[: fenced.start()].strip(), _decode_json_envelope(fenced.group(1))

    # Look for the start of the envelope before nested tool arguments.
    opening = re.search(r'(?:\[\s*)?\{\s*"(?:commentary|client_calls|tool_calls|answer)"\s*:', raw_text)
    if opening:
        envelope = _decode_json_envelope(raw_text[opening.start():])
        if envelope is not None and isinstance(envelope.get(CLIENT_CALLS_FIELD, envelope.get(LEGACY_CALLS_FIELD)), list):
            return raw_text[: opening.start()].strip(), envelope
    return "", None


def _recover_acp_tool_retry_output(output: str, allow_client_calls: bool) -> str:
    attempts = ACP_TOOL_RETRY_NOTICE.split(output)
    if len(attempts) == 1:
        return output

    # Only the last attempt may request actions. Earlier attempts were superseded by ACP.
    last = attempts[-1].strip()
    _, envelope = _extract_json_envelope(last)
    if allow_client_calls and envelope is not None and all(
        _extract_json_envelope(attempt.strip())[1] is not None for attempt in attempts[:-1]
    ):
        calls = envelope.get(CLIENT_CALLS_FIELD, envelope.get(LEGACY_CALLS_FIELD))
        if isinstance(calls, list) and calls and all(isinstance(call, dict) and call.get("name") for call in calls):
            return last
    raise BridgeError(
        "Antigravity ACP could not produce a complete client tool response after a tool formatting error.",
        status=502,
        code="acp_tool_format_error",
    )


def _reject_interrupted_acp_output(output: str) -> None:
    """Do not accept ACP's own transport-error notices as a successful answer or tool call."""
    if ACP_INTERRUPTED_NOTICE.match(output) and ACP_API_RETRY_NOTICE.search(output):
        raise BridgeError(
            "Antigravity ACP's upstream stream was interrupted after retries. Please retry the turn.",
            status=502,
            code="acp_upstream_interrupted",
        )


def parse_model_envelope(
    raw_text: str,
    tools: list[DeclaredTool],
    tool_mode: str,
) -> tuple[str, list[ParsedToolInvocation], str]:
    """Return (commentary, parsed_tool_calls, answer)."""
    text = raw_text.strip()
    if not tools or tool_mode == "none":
        return "", [], text

    by_wire = {t.wire_name: t for t in tools}
    by_real: dict[str, DeclaredTool] = {}
    for t in tools:
        if t.real_name not in by_real:
            by_real[t.real_name] = t

    preamble, env = _extract_json_envelope(text)
    if env is None:
        if tool_mode == "required":
            raise BridgeError(
                "Model did not return the required tool call envelope.",
                status=502,
                code="invalid_tool_envelope",
            )
        return "", [], text

    commentary = str(env.get("commentary") or "").strip()
    if preamble and not commentary:
        commentary = preamble
    answer = env.get("answer")
    if isinstance(answer, (dict, list)):
        answer_str = json.dumps(answer, ensure_ascii=False)
    else:
        answer_str = str(answer or "").strip()

    if CLIENT_CALLS_FIELD in env and LEGACY_CALLS_FIELD in env:
        raise BridgeError("Model returned two client tool lists.", status=502, code="invalid_tool_envelope")
    raw_calls = env.get(CLIENT_CALLS_FIELD, env.get(LEGACY_CALLS_FIELD))
    invocations: list[ParsedToolInvocation] = []
    if isinstance(raw_calls, list):
        for call in raw_calls:
            if not isinstance(call, dict):
                continue
            raw_name = str(call.get("name") or "").strip()
            ns = _norm_ns(call.get("namespace"))
            lookup = _wire_tool_name(ns, raw_name) if ns else raw_name
            target = by_wire.get(lookup) or by_wire.get(raw_name) or by_real.get(raw_name)
            if target is None:
                raise BridgeError(
                    f"Model requested undeclared tool '{raw_name}'.",
                    status=502,
                    code="undeclared_tool_call",
                )
            raw_args = call.get("arguments")
            if target.freeform:
                if isinstance(raw_args, dict) and isinstance(raw_args.get("input"), str):
                    f_in = raw_args["input"]
                elif isinstance(call.get("input"), str):
                    f_in = call["input"]
                elif isinstance(raw_args, str):
                    f_in = raw_args
                else:
                    f_in = ""
                invocations.append(
                    ParsedToolInvocation(
                        target,
                        json.dumps({"input": f_in}, ensure_ascii=False),
                        freeform_input=f_in,
                    )
                )
            else:
                if isinstance(raw_args, dict):
                    args_json = json.dumps(raw_args, ensure_ascii=False)
                elif isinstance(raw_args, str) and raw_args.strip():
                    try:
                        parsed = json.loads(raw_args)
                        args_json = (
                            json.dumps(parsed, ensure_ascii=False)
                            if isinstance(parsed, dict)
                            else "{}"
                        )
                    except ValueError:
                        args_json = "{}"
                else:
                    args_json = "{}"
                invocations.append(ParsedToolInvocation(target, args_json or "{}"))

    if tool_mode == "required" and not invocations:
        raise BridgeError(
            "Tool call was required by tool_choice, but the model returned no client tool calls.",
            status=502,
            code="missing_required_tool_call",
        )

    if invocations:
        answer_str = ""
    elif not answer_str and commentary:
        answer_str = commentary
        commentary = ""

    return commentary, invocations, answer_str


# ---------------------------------------------------------------------------
# ACP Runtime Validation, Pacing & Warm Resident Process
# ---------------------------------------------------------------------------

def usage_from_acp(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {
            "input_tokens": 0,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 0,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 0,
        }
    vals = [
        raw.get(k)
        for k in (
            "inputTokens",
            "outputTokens",
            "cachedReadTokens",
            "cachedWriteTokens",
            "thoughtTokens",
            "totalTokens",
        )
    ]
    if any(type(x) is not int or x < 0 for x in vals):
        return {
            "input_tokens": 0,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 0,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 0,
        }
    inp, out, cached, written, thought, total = vals
    if total == inp + cached + written + out and thought <= out:
        inp += cached + written
    elif total == inp + cached + written + out + thought:
        inp += cached + written
        out += thought
    elif total == inp + out and cached <= inp and thought <= out:
        pass
    elif total == inp + out + thought and cached <= inp:
        out += thought
    return {
        "input_tokens": inp,
        "input_tokens_details": {"cached_tokens": cached},
        "output_tokens": out,
        "output_tokens_details": {"reasoning_tokens": thought},
        "total_tokens": inp + out,
    }


def _terminate_proc(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    try:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.wait(timeout=3)
    except Exception:
        if proc.poll() is None:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        timeout=10,
                    )
                else:
                    proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass


class _AcpClient:
    def __init__(self, proc: subprocess.Popen[bytes], job: TurnJob, deadline: float) -> None:
        self.proc = proc
        self.job = job
        self.deadline = deadline
        self.messages: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.next_id = 0
        self.output: list[str] = []
        self.output_size = 0
        self.native_tool = False
        self.eof = False
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()

    def bind(self, job: TurnJob, deadline: float) -> None:
        self.job = job
        self.deadline = deadline
        self.output.clear()
        self.output_size = 0
        self.native_tool = False

    def _read_loop(self) -> None:
        try:
            assert self.proc.stdout is not None
            while True:
                line = self.proc.stdout.readline(MAX_WIRE_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_WIRE_LINE or not line.endswith(b"\n"):
                    self.messages.put(None)
                    return
                try:
                    val = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    self.messages.put(None)
                    return
                if isinstance(val, dict):
                    self.messages.put(val)
        finally:
            self.messages.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        try:
            assert self.proc.stdin is not None
            payload = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
            self.proc.stdin.write(payload)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise BridgeError("Antigravity ACP pipe disconnected.", status=502, code="acp_disconnected") from None

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        ident = self.next_id
        session_id = params.get("sessionId")
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        while True:
            if self.job.cancelled.is_set():
                raise BridgeError("Request cancelled by client.", status=499, code="cancelled")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError("Antigravity ACP turn timed out.", status=504, code="acp_timeout")
            try:
                msg = self.messages.get(timeout=min(0.2, remaining))
            except queue.Empty:
                continue
            if not isinstance(msg, dict):
                self.eof = True
                raise BridgeError("Antigravity ACP stream ended unexpectedly.", status=502, code="acp_eof")
            if msg.get("method") and "id" in msg:
                if msg["method"] == "session/request_permission":
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "result": {"outcome": {"outcome": "cancelled"}},
                        }
                    )
                    self.native_tool = True
                else:
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32601, "message": "Unsupported"},
                        }
                    )
                    self.native_tool = True
                continue
            if msg.get("id") == ident and ("result" in msg or "error" in msg):
                if "error" in msg or not isinstance(msg.get("result"), dict):
                    err_detail = ""
                    if isinstance(msg.get("error"), dict):
                        err_detail = str(msg["error"].get("message") or "")
                    raise BridgeError(
                        f"Antigravity ACP upstream error: {err_detail or 'request failed'}. "
                        "Check Antigravity IDE login and model quota.",
                        status=502,
                        code="acp_rpc_error",
                    )
                return msg["result"]
            if msg.get("method") != "session/update":
                continue
            update_params = msg.get("params", {})
            if session_id and update_params.get("sessionId", session_id) != session_id:
                continue
            update = update_params.get("update", {})
            if not isinstance(update, dict):
                continue
            kind = update.get("sessionUpdate")
            if kind in ("tool_call", "tool_call_update"):
                self.native_tool = True
                self.job.cancel()
                raise BridgeError(
                    "Antigravity attempted native ACP tool execution; aborted by security policy.",
                    status=502,
                    code="native_tool_rejected",
                )
            if kind == "agent_message_chunk":
                content = update.get("content", {})
                if not isinstance(content, dict) or content.get("type") != "text":
                    raise BridgeError("Unsupported ACP message chunk type.", status=502, code="acp_chunk_error")
                val = content.get("text")
                if not isinstance(val, str):
                    raise BridgeError("Malformed ACP text chunk.", status=502, code="acp_chunk_error")
                self.output_size += len(val.encode("utf-8"))
                if self.output_size > MAX_OUTPUT_BYTES:
                    raise BridgeError("ACP output exceeded 2 MiB safety cap.", status=502, code="output_too_large")
                self.output.append(val)

    def close_session(self, sid: str) -> None:
        if not sid or self.eof or self.proc.poll() is not None:
            return
        try:
            self.next_id += 1
            ident = self.next_id
            self._send({"jsonrpc": "2.0", "id": ident, "method": "session/close", "params": {"sessionId": sid}})
            limit = time.monotonic() + 1.5
            while time.monotonic() < limit:
                msg = self.messages.get(timeout=max(0.05, limit - time.monotonic()))
                if msg is None:
                    self.eof = True
                    return
                if isinstance(msg, dict) and msg.get("id") == ident:
                    return
        except Exception:
            self.eof = True


def _opt_value(options: list[Any], key: str) -> Any:
    return next((x.get("currentValue") for x in options if isinstance(x, dict) and x.get("id") == key), None)


def _has_opt(options: list[Any], key: str, value: str) -> bool:
    return any(
        isinstance(x, dict)
        and x.get("id") == key
        and any(isinstance(y, dict) and y.get("value") == value for y in x.get("options", []))
        for x in options
    )


@dataclass
class _AcpWorker:
    client: _AcpClient
    capabilities: dict[str, Any]
    profile: Path
    idle_since: float = 0.0

    def alive(self) -> bool:
        return not self.client.eof and self.client.proc.poll() is None

    def close(self) -> None:
        _terminate_proc(self.client.proc)
        self.client.reader.join(timeout=1)
        if not self.client.reader.is_alive() and self.client.proc.stdout is not None:
            self.client.proc.stdout.close()
        shutil.rmtree(self.profile, ignore_errors=True)


class BridgeRuntime:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.agy_path = Path(config["agy_path"])
        self.expected_sha512 = str(config["expected_sha512"]).strip().lower()
        self.client_version = str(config.get("client_version") or "1.5.6")
        self.runtime_dir = Path(config["runtime_dir"])
        self.workspace_dir = Path(config["workspace_dir"])
        self.auth_token_file = Path(config["auth_token_file"])
        self.idle_timeout = float(config.get("idle_timeout_sec", 1200.0))
        self.turn_timeout = float(config.get("turn_timeout_sec", 420.0))

        self._validation_lock = threading.Lock()
        self._binary_stamp: tuple[str, int, int] | None = None
        self._workers = threading.Condition()
        self._idle_worker: _AcpWorker | None = None
        self._active_requests = 0
        self._active_prompts = 0

        self._resp_cache_lock = threading.Lock()
        self._resp_cache: dict[str, list[dict[str, Any]]] = {}
        self._resp_order: list[str] = []

        self._stop_event = threading.Event()
        threading.Thread(target=self._idle_reaper_loop, daemon=True).start()

    def read_auth_token(self) -> str:
        if self.auth_token_file.is_symlink() or not self.auth_token_file.is_file():
            raise BridgeError("Bridge auth token file missing or unsafe.", status=500, code="auth_config_error")
        tok = self.auth_token_file.read_text(encoding="utf-8").strip()
        if len(tok) < 24:
            raise BridgeError("Bridge auth token is too short.", status=500, code="auth_config_error")
        return tok

    def check_bearer(self, header_value: str | None) -> bool:
        if not header_value or not header_value.startswith("Bearer "):
            return False
        supplied = header_value[7:].strip()
        expected = self.read_auth_token()
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def remember_response(self, resp_id: str, history_items: list[dict[str, Any]]) -> None:
        with self._resp_cache_lock:
            if resp_id not in self._resp_cache:
                self._resp_order.append(resp_id)
            self._resp_cache[resp_id] = history_items
            while len(self._resp_order) > 64:
                oldest = self._resp_order.pop(0)
                self._resp_cache.pop(oldest, None)

    def get_cached_response(self, resp_id: str | None) -> list[dict[str, Any]] | None:
        if not resp_id:
            return None
        with self._resp_cache_lock:
            items = self._resp_cache.get(resp_id)
            return list(items) if items is not None else None

    def sync_installation_id(self) -> None:
        host_inst = Path.home() / ".gemini" / "antigravity" / "installation_id"
        target_inst = self.runtime_dir / "antigravity-cli" / "installation_id"
        if target_inst.is_symlink():
            raise BridgeError("Unsafe symlink on runtime installation_id.", status=500, code="runtime_tampered")
        if host_inst.is_file() and not host_inst.is_symlink():
            raw = host_inst.read_bytes().strip()
            if 16 <= len(raw) <= 128:
                target_inst.parent.mkdir(parents=True, exist_ok=True)
                if not target_inst.exists() or target_inst.read_bytes().strip() != raw:
                    target_inst.write_bytes(raw)

    def validate_runtime(self) -> None:
        with self._validation_lock:
            self._validate_runtime_files()

    def _validate_runtime_files(self) -> None:
        exe = self.agy_path
        gemini = self.runtime_dir
        settings_path = gemini / "antigravity-cli" / "settings.json"
        try:
            if exe.is_symlink() or not exe.is_file() or settings_path.is_symlink():
                raise ValueError("unsafe executable or settings path")
            st = exe.stat()
            stamp = (str(exe.resolve()), st.st_size, st.st_mtime_ns)
            if self._binary_stamp != stamp:
                digest = hashlib.sha512()
                with exe.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest().lower() != self.expected_sha512:
                    raise ValueError("executable sha512 mismatch")
                self._binary_stamp = stamp

            if not settings_path.exists():
                settings_path.parent.mkdir(parents=True, exist_ok=True)
                settings_path.write_text(json.dumps(SETTINGS, indent=2), encoding="utf-8")
            elif json.loads(settings_path.read_text(encoding="utf-8-sig")) != SETTINGS:
                raise ValueError("unexpected runtime settings.json")

            cfg_dir = gemini / "config"
            if (cfg_dir / "hooks.json").exists() or (cfg_dir / "plugins").exists():
                raise ValueError("unexpected hooks or plugins in runtime")
            mcp_path = cfg_dir / "mcp_config.json"
            if mcp_path.exists() and mcp_path.read_bytes().strip() not in (b"", b"{}", b'{"mcpServers":{}}'):
                raise ValueError("unexpected mcp_config.json in runtime")

            proj_path = cfg_dir / "projects" / "default-cli-project.json"
            if proj_path.is_symlink():
                raise ValueError("unsafe default-cli-project.json")
            if not proj_path.exists():
                proj_path.parent.mkdir(parents=True, exist_ok=True)
                proj_path.write_text(json.dumps(DEFAULT_PROJECT), encoding="utf-8")
            elif json.loads(proj_path.read_text(encoding="utf-8-sig")) != DEFAULT_PROJECT:
                raise ValueError("unexpected default-cli-project.json")

            self.sync_installation_id()

            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            for parent in (self.workspace_dir, *self.workspace_dir.parents):
                for bad_name in ("hooks.json", "plugins.json", "mcp_config.json"):
                    if (parent / ".agents" / bad_name).exists():
                        raise ValueError(f"unexpected .agents/{bad_name} in workspace hierarchy")

            agent_file = self.workspace_dir / ".agents" / "agents" / f"{AGENT_NAME}.md"
            agent_file.parent.mkdir(parents=True, exist_ok=True)
            if not agent_file.exists() or agent_file.read_text(encoding="utf-8") != AGENT_DEFINITION:
                agent_file.write_text(AGENT_DEFINITION, encoding="utf-8")
        except BridgeError:
            raise
        except Exception as exc:
            raise BridgeError(
                f"Antigravity isolated runtime validation failed ({exc}). Refusing to start ACP.",
                status=500,
                code="runtime_validation_failed",
            ) from None

    def worker_status(self) -> dict[str, Any]:
        with self._workers:
            return {
                "resident_warm": bool(self._active_prompts or (self._idle_worker and self._idle_worker.alive())),
                "active_requests": self._active_requests,
                "active_prompts": self._active_prompts,
            }

    def shutdown(self) -> None:
        with self._workers:
            self._stop_event.set()
            idle, self._idle_worker = self._idle_worker, None
            self._workers.wait_for(lambda: self._active_requests == 0)
        if idle:
            idle.close()

    def _idle_reaper_loop(self) -> None:
        while not self._stop_event.wait(30.0):
            with self._workers:
                idle = self._idle_worker
                if idle is None or (idle.alive() and time.monotonic() - idle.idle_since <= self.idle_timeout):
                    continue
                self._idle_worker = None
            idle.close()

    def _start_worker(self, job: TurnJob, deadline: float) -> _AcpWorker:
        if job.cancelled.is_set():
            raise BridgeError("Request cancelled.", status=499, code="cancelled")

        profile = Path(tempfile.mkdtemp(prefix="acp-", dir=self.runtime_dir))
        proc = None
        worker = None
        try:
            settings = profile / "antigravity-cli" / "settings.json"
            settings.parent.mkdir()
            settings.write_text(json.dumps(SETTINGS, indent=2), encoding="utf-8")
            project = profile / "config" / "projects" / "default-cli-project.json"
            project.parent.mkdir(parents=True)
            project.write_text(json.dumps(DEFAULT_PROJECT), encoding="utf-8")
            with self._validation_lock:
                installation_id = self.runtime_dir / "antigravity-cli" / "installation_id"
                if installation_id.is_file():
                    shutil.copyfile(installation_id, settings.parent / "installation_id")

            proc = subprocess.Popen(
                [
                    str(self.agy_path),
                    "acp",
                    "--gemini-dir",
                    str(profile),
                    "--agent",
                    AGENT_NAME,
                    "--include-default-customizations=false",
                    "--disable-telemetry",
                ],
                cwd=str(self.workspace_dir),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
            )
            client = _AcpClient(proc, job, deadline)
            worker = _AcpWorker(client, {}, profile)
            init = client.call(
                "initialize",
                {
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {"readTextFile": False, "writeTextFile": False},
                        "terminal": False,
                    },
                    "clientInfo": {"name": "agy-cli", "version": self.client_version},
                },
            )
            caps = init.get("agentCapabilities", {})
            if (
                init.get("protocolVersion") != 1
                or not caps.get("_meta", {}).get("antigravity", {}).get("systemPrompt", {}).get("append")
            ):
                raise BridgeError("Antigravity ACP server missing required capabilities.", status=502)
            worker.capabilities = caps
            return worker
        except BaseException:
            if worker is not None:
                worker.close()
            else:
                _terminate_proc(proc)
                shutil.rmtree(profile, ignore_errors=True)
            raise

    @contextmanager
    def _lease_worker(self, job: TurnJob, deadline: float) -> Iterator[_AcpWorker]:
        with self._workers:
            if self._stop_event.is_set():
                raise BridgeError("ACP bridge is shutting down.", status=503, code="bridge_shutdown")
            self._active_requests += 1
            worker, self._idle_worker = self._idle_worker, None
        completed = False
        try:
            if worker is not None and (not worker.alive() or time.monotonic() - worker.idle_since > self.idle_timeout):
                expired, worker = worker, None
                expired.close()
            if worker is None:
                worker = self._start_worker(job, deadline)
            else:
                worker.client.bind(job, deadline)
            yield worker
            completed = True
        finally:
            try:
                with self._workers:
                    if (
                        completed and worker is not None and worker.alive()
                        and not self._stop_event.is_set() and self._idle_worker is None
                    ):
                        worker.idle_since = time.monotonic()
                        self._idle_worker, worker = worker, None
                if worker is not None:
                    worker.close()
            finally:
                with self._workers:
                    self._active_requests -= 1
                    self._workers.notify_all()

    def execute_acp_turn(
        self,
        *,
        acp_model: str,
        acp_effort: str,
        system_append: str,
        acp_parts: list[dict[str, Any]],
        has_images: bool,
        job: TurnJob,
        allow_client_calls: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        self.validate_runtime()
        deadline = time.monotonic() + self.turn_timeout
        for attempt in range(2):
            try:
                return self._execute_acp_attempt(
                    acp_model=acp_model,
                    acp_effort=acp_effort,
                    system_append=system_append,
                    acp_parts=acp_parts,
                    has_images=has_images,
                    job=job,
                    allow_client_calls=allow_client_calls,
                    deadline=deadline,
                )
            except BridgeError as exc:
                if (
                    exc.code not in {"acp_tool_format_error", "acp_upstream_interrupted"}
                    or attempt
                    or job.cancelled.is_set()
                    or deadline - time.monotonic() < 5
                ):
                    raise
        raise AssertionError("ACP retry loop exhausted")

    def _execute_acp_attempt(
        self,
        *,
        acp_model: str,
        acp_effort: str,
        system_append: str,
        acp_parts: list[dict[str, Any]],
        has_images: bool,
        job: TurnJob,
        allow_client_calls: bool,
        deadline: float,
    ) -> tuple[str, dict[str, Any]]:
        with self._lease_worker(job, deadline) as worker:
            client, caps = worker.client, worker.capabilities
            if has_images and not caps.get("promptCapabilities", {}).get("image"):
                raise BridgeError("Antigravity ACP server does not advertise image prompt support.", status=400)
            session = client.call(
                "session/new",
                {
                    "cwd": str(self.workspace_dir),
                    "mcpServers": [],
                    "_meta": {
                        "antigravity": {
                            "systemPrompt": {"append": system_append},
                            "disabledTools": DISABLED_TOOLS,
                        }
                    },
                },
            )
            sid = session.get("sessionId")
            options = session.get("configOptions", [])
            if not isinstance(sid, str) or not sid or not _has_opt(options, "model", acp_model):
                raise BridgeError(
                    f"Antigravity account does not currently offer model '{acp_model}'. "
                    "Verify Antigravity IDE login and subscription tier.",
                    status=502,
                    code="model_unavailable_upstream",
                )
            for key, desired in (("model", acp_model), ("thought_level", acp_effort)):
                if not _has_opt(options, key, desired):
                    raise BridgeError(
                        f"Model '{acp_model}' does not support {key}='{desired}'.",
                        status=400,
                        code="effort_unavailable",
                    )
                if _opt_value(options, key) != desired:
                    updated = client.call(
                        "session/set_config_option",
                        {"sessionId": sid, "configId": key, "value": desired},
                    )
                    options = updated.get("configOptions", [])
                    if _opt_value(options, key) != desired:
                        raise BridgeError(f"Failed to confirm ACP {key}='{desired}'.", status=502)

            client.output.clear()
            client.output_size = 0
            with self._workers:
                self._active_prompts += 1
            try:
                final = client.call("session/prompt", {"sessionId": sid, "prompt": acp_parts})
            finally:
                with self._workers:
                    self._active_prompts -= 1
            if client.native_tool:
                raise BridgeError("Native tool call detected and blocked.", status=502, code="native_tool_rejected")
            if final.get("stopReason") != "end_turn":
                raise BridgeError(
                    f"ACP turn ended with stopReason='{final.get('stopReason')}'.",
                    status=502,
                    code="incomplete_turn",
                )
            output = "".join(client.output).strip()
            _reject_interrupted_acp_output(output)
            if output.startswith("\u26a0") and output[1:].lstrip("\ufe0f ") == "Agent execution terminated due to error.":
                raise BridgeError(
                    "Antigravity ACP reported an agent execution error.", status=502, code="acp_execution_error",
                )
            client.close_session(sid)
            return _recover_acp_tool_retry_output(output, allow_client_calls), usage_from_acp(final.get("usage"))


# ---------------------------------------------------------------------------
# Idle SSH `codex app-server --listen unix://` Watcher
# ---------------------------------------------------------------------------

class CodexWatcher(threading.Thread):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(daemon=True)
        self.codex_dir = Path(config.get("codex_dir") or (Path.home() / ".codex"))
        self.helper_script = Path(config.get("ssh_helper_script") or (Path(__file__).with_name("agy_ssh_lan.py")))
        self._last_digest: str | None = None
        self._pending_refresh = False

    def _files_digest(self) -> str:
        h = hashlib.sha256()
        for name in ("config.toml", "cc-switch-model-catalog.json"):
            p = self.codex_dir / name
            if p.is_file():
                try:
                    h.update(p.read_bytes())
                except OSError:
                    pass
            h.update(b"|")
        return h.hexdigest()

    def run(self) -> None:
        self._last_digest = self._files_digest()
        while True:
            time.sleep(2.5)
            cur_digest = self._files_digest()
            changed = cur_digest != self._last_digest
            if changed:
                self._last_digest = cur_digest
                self._pending_refresh = True

            if self._pending_refresh and self.helper_script.is_file():
                try:
                    refresh = subprocess.run(
                        [sys.executable, "-I", "-B", str(self.helper_script), "refresh-ssh"],
                        stdin=subprocess.DEVNULL, capture_output=True, timeout=45,
                    )
                    self._pending_refresh = refresh.returncode != 0
                except (OSError, subprocess.TimeoutExpired):
                    pass


# ---------------------------------------------------------------------------
# HTTP / SSE Handler (`/health`, `/v1/models`, `/v1/responses`)
# ---------------------------------------------------------------------------

def _build_response_object(
    *,
    resp_id: str,
    created_at: int,
    model: str,
    status: str,
    output: list[dict[str, Any]],
    usage: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "id": resp_id,
        "object": "response",
        "created_at": created_at,
        "status": status,
        "model": model,
        "output": output,
        "parallel_tool_calls": False,
    }
    if usage is not None:
        obj["usage"] = usage
    if error is not None:
        obj["error"] = error
    return obj


def _build_output_items_and_events(
    *,
    commentary: str,
    invocations: list[ParsedToolInvocation],
    answer: str,
    is_compaction: bool,
    raw_text_for_compaction: str,
) -> tuple[list[dict[str, Any]], list[tuple[str, dict[str, Any]]]]:
    """Build both final `output` items and granular Responses SSE events."""
    finished: list[dict[str, Any]] = []
    events: list[tuple[str, dict[str, Any]]] = []
    idx = 0

    def emit_message(text: str, phase: str | None = None) -> None:
        nonlocal idx
        msg_id = f"msg_{uuid.uuid4().hex[:24]}"
        added_item: dict[str, Any] = {
            "type": "message",
            "id": msg_id,
            "status": "in_progress",
            "role": "assistant",
            "content": [],
        }
        if phase:
            added_item["phase"] = phase
        events.append(("response.output_item.added", {"output_index": idx, "item": added_item}))
        events.append(
            (
                "response.content_part.added",
                {
                    "item_id": msg_id,
                    "output_index": idx,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []},
                },
            )
        )
        if text:
            events.append(
                (
                    "response.output_text.delta",
                    {"item_id": msg_id, "output_index": idx, "content_index": 0, "delta": text},
                )
            )
        events.append(
            (
                "response.output_text.done",
                {"item_id": msg_id, "output_index": idx, "content_index": 0, "text": text},
            )
        )
        events.append(
            (
                "response.content_part.done",
                {
                    "item_id": msg_id,
                    "output_index": idx,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": text, "annotations": []},
                },
            )
        )
        done_item: dict[str, Any] = {
            "type": "message",
            "id": msg_id,
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }
        if phase:
            done_item["phase"] = phase
        events.append(("response.output_item.done", {"output_index": idx, "item": done_item}))
        finished.append(done_item)
        idx += 1

    if is_compaction:
        cmp_item = {
            "type": "compaction",
            "id": f"cmp_{uuid.uuid4().hex[:24]}",
            "encrypted_content": encode_compaction_summary(raw_text_for_compaction),
        }
        events.append(("response.output_item.done", {"output_index": idx, "item": cmp_item}))
        finished.append(cmp_item)
        return finished, events

    if commentary and invocations:
        emit_message(commentary, phase="commentary")

    for inv in invocations:
        call_id = f"call_{uuid.uuid4().hex[:24]}"
        t = inv.tool
        if t.tool_search:
            item_id = f"tsc_{uuid.uuid4().hex[:24]}"
            try:
                args_obj = json.loads(inv.arguments_json)
                if not isinstance(args_obj, dict):
                    args_obj = {}
            except ValueError:
                args_obj = {}
            added = {
                "type": "tool_search_call",
                "id": item_id,
                "call_id": call_id,
                "execution": "client",
                "arguments": {},
                "status": "in_progress",
            }
            done = {
                "type": "tool_search_call",
                "id": item_id,
                "call_id": call_id,
                "execution": "client",
                "arguments": args_obj,
                "status": "completed",
            }
            events.append(("response.output_item.added", {"output_index": idx, "item": added}))
            events.append(("response.output_item.done", {"output_index": idx, "item": done}))
            finished.append(done)
            idx += 1
        elif t.freeform:
            item_id = f"ctc_{uuid.uuid4().hex[:24]}"
            added = {
                "type": "custom_tool_call",
                "id": item_id,
                "call_id": call_id,
                "name": t.real_name,
                "input": "",
                "status": "in_progress",
            }
            done = {
                "type": "custom_tool_call",
                "id": item_id,
                "call_id": call_id,
                "name": t.real_name,
                "input": inv.freeform_input,
                "status": "completed",
            }
            events.append(("response.output_item.added", {"output_index": idx, "item": added}))
            if inv.freeform_input:
                events.append(
                    (
                        "response.custom_tool_call_input.delta",
                        {"item_id": item_id, "output_index": idx, "delta": inv.freeform_input},
                    )
                )
            events.append(
                (
                    "response.custom_tool_call_input.done",
                    {"item_id": item_id, "output_index": idx, "input": inv.freeform_input},
                )
            )
            events.append(("response.output_item.done", {"output_index": idx, "item": done}))
            finished.append(done)
            idx += 1
        else:
            item_id = f"fc_{uuid.uuid4().hex[:24]}"
            args_str = inv.arguments_json or "{}"
            added = {
                "type": "function_call",
                "id": item_id,
                "call_id": call_id,
                "name": t.real_name,
                "arguments": "",
                "status": "in_progress",
            }
            done = {
                "type": "function_call",
                "id": item_id,
                "call_id": call_id,
                "name": t.real_name,
                "arguments": args_str,
                "status": "completed",
            }
            if t.namespace:
                added["namespace"] = t.namespace
                done["namespace"] = t.namespace
            events.append(("response.output_item.added", {"output_index": idx, "item": added}))
            events.append(
                (
                    "response.function_call_arguments.delta",
                    {"item_id": item_id, "output_index": idx, "delta": args_str},
                )
            )
            events.append(
                (
                    "response.function_call_arguments.done",
                    {"item_id": item_id, "output_index": idx, "arguments": args_str},
                )
            )
            events.append(("response.output_item.done", {"output_index": idx, "item": done}))
            finished.append(done)
            idx += 1

    if not invocations:
        emit_message(answer)

    return finished, events


class LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler_cls: type[BaseHTTPRequestHandler], runtime: BridgeRuntime) -> None:
        host = server_address[0]
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"Refusing to bind non-loopback address '{host}'.")
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__(server_address, handler_cls)
        self.runtime = runtime


class BridgeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet structured stderr logging without leaking prompts or tokens (safe under pythonw.exe)
        if sys.stderr is None:
            return
        try:
            sys.stderr.write(f"[antigravity-acp-bridge] {self.address_string()} {fmt % args}\n")
            sys.stderr.flush()
        except Exception:
            pass

    @property
    def runtime(self) -> BridgeRuntime:
        return self.server.runtime  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _require_auth(self) -> bool:
        try:
            ok = self.runtime.check_bearer(self.headers.get("Authorization"))
        except BridgeError as exc:
            self._send_json(exc.status, {"error": {"message": exc.message, "type": "server_error", "code": exc.code}})
            return False
        if not ok:
            self._send_json(
                401,
                {"error": {"message": "Invalid or missing Bearer token.", "type": "invalid_request_error", "code": "unauthorized"}},
            )
            return False
        return True

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/health":
            try:
                self.runtime.validate_runtime()
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "bridge_version": BRIDGE_VERSION,
                        "default_model": "gemini-4-carbon",
                        "models": list(ALLOWED_BASE_MODELS.keys()),
                        **self.runtime.worker_status(),
                    },
                )
            except BridgeError as exc:
                self._send_json(503, {"status": "error", "code": exc.code, "message": exc.message})
            return

        if path == "/v1/models":
            if not self._require_auth():
                return
            now_ts = int(time.time())
            data = [
                {
                    "id": mid,
                    "object": "model",
                    "created": now_ts,
                    "owned_by": "google-antigravity-acp",
                }
                for mid in EXPOSED_MODEL_IDS
            ]
            self._send_json(200, {"object": "list", "data": data})
            return

        self._send_json(404, {"error": {"message": f"Unknown endpoint {path}", "type": "invalid_request_error"}})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path not in ("/v1/responses", "/responses", "/v1/responses/compact", "/responses/compact"):
            self._send_json(404, {"error": {"message": f"Unknown endpoint {path}", "type": "invalid_request_error"}})
            return
        if not self._require_auth():
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send_json(400, {"error": {"message": "Invalid or oversized request body.", "type": "invalid_request_error"}})
            return

        try:
            raw_body = self.rfile.read(length)
            req = json.loads(raw_body.decode("utf-8"))
            if not isinstance(req, dict):
                raise ValueError("JSON body must be an object")
        except Exception:
            self._send_json(400, {"error": {"message": "Malformed JSON body.", "type": "invalid_request_error"}})
            return

        if path.endswith("/compact"):
            self._handle_unary_compact(req)
            return

        self._handle_responses(req)

    def _handle_unary_compact(self, req: dict[str, Any]) -> None:
        job = TurnJob()
        try:
            acp_model, acp_effort, norm_model = resolve_model_and_effort(req.get("model"), {"effort": "low"})
            sys_inst, acp_parts, _ic, _lt = parse_responses_conversation(req)
            if acp_parts and acp_parts[0].get("type") == "text":
                acp_parts[0]["text"] += f"\n\n[USER]\n{COMPACT_PROMPT}"
            full_inst = (sys_inst + "\n\nRespond directly with the handoff summary.").strip()
            has_images = any(p.get("type") == "image" for p in acp_parts)
            summary_text, usage = self.runtime.execute_acp_turn(
                acp_model=acp_model,
                acp_effort=acp_effort,
                system_append=full_inst,
                acp_parts=acp_parts,
                has_images=has_images,
                job=job,
            )
            out_msg = {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": f"{SUMMARY_PREFIX}\n{summary_text}"}],
            }
            self._send_json(
                200,
                {
                    "id": f"resp_{uuid.uuid4().hex[:24]}",
                    "object": "response.compaction",
                    "created_at": int(time.time()),
                    "model": norm_model,
                    "output": [out_msg],
                    "usage": usage,
                },
            )
        except BridgeError as exc:
            self._send_json(exc.status, {"error": {"message": exc.message, "type": "bridge_error", "code": exc.code}})

    def _handle_responses(self, req: dict[str, Any]) -> None:
        try:
            acp_model, acp_effort, norm_model = resolve_model_and_effort(req.get("model"), req.get("reasoning"))
            prior = self.runtime.get_cached_response(req.get("previous_response_id"))
            sys_inst, acp_parts, is_compaction, extra_loaded_specs = parse_responses_conversation(req, prior)

            raw_tools = list(req.get("tools") or []) if isinstance(req.get("tools"), list) else []
            if extra_loaded_specs:
                raw_tools.extend(extra_loaded_specs)

            output_schema: dict[str, Any] | None = None
            text_cfg = req.get("text")
            if isinstance(text_cfg, dict) and isinstance(text_cfg.get("format"), dict):
                fmt = text_cfg["format"]
                if fmt.get("type") == "json_schema" and isinstance(fmt.get("schema"), dict):
                    output_schema = fmt["schema"]

            if is_compaction:
                declared_tools, tool_mode = [], "none"
            else:
                declared_tools, tool_mode, _ = parse_declared_tools(raw_tools, req.get("tool_choice"))

            parallel = bool(req.get("parallel_tool_calls", False))
            proto_inst = build_tool_protocol_instructions(
                declared_tools, tool_mode, parallel, output_schema, acp_parts, len(sys_inst.encode("utf-8")),
            )
            full_system = (sys_inst + "\n\n" + proto_inst).strip() if sys_inst else proto_inst
            has_images = any(p.get("type") == "image" for p in acp_parts)
        except BridgeError as exc:
            self._send_json(exc.status, {"error": {"message": exc.message, "type": "invalid_request_error", "code": exc.code}})
            return

        stream = bool(req.get("stream", False))
        resp_id = f"resp_{uuid.uuid4().hex[:24]}"
        created_at = int(time.time())
        job = TurnJob()

        if not stream:
            try:
                raw_out, usage = self.runtime.execute_acp_turn(
                    acp_model=acp_model,
                    acp_effort=acp_effort,
                    system_append=full_system,
                    acp_parts=acp_parts,
                    has_images=has_images,
                    job=job,
                    allow_client_calls=bool(declared_tools and tool_mode != "none"),
                )
                if is_compaction:
                    commentary, invocations, answer = "", [], ""
                elif not declared_tools or tool_mode == "none":
                    commentary, invocations = "", []
                    answer = _strip_single_json_fence(raw_out) if output_schema is not None else raw_out
                else:
                    commentary, invocations, answer = parse_model_envelope(raw_out, declared_tools, tool_mode)

                finished, _ = _build_output_items_and_events(
                    commentary=commentary,
                    invocations=invocations,
                    answer=answer,
                    is_compaction=is_compaction,
                    raw_text_for_compaction=raw_out,
                )
                self._cache_turn(resp_id, prior, req.get("input"), finished)
                self._send_json(
                    200,
                    _build_response_object(
                        resp_id=resp_id,
                        created_at=created_at,
                        model=norm_model,
                        status="completed",
                        output=finished,
                        usage=usage,
                    ),
                )
            except BridgeError as exc:
                self._send_json(exc.status, {"error": {"message": exc.message, "type": "bridge_error", "code": exc.code}})
            return

        # Streaming SSE path (`Transfer-Encoding: chunked` omitted; close connection cleanly after `[DONE]`)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        write_lock = threading.Lock()
        seq = [0]

        def send_sse(event_name: str, data_obj: dict[str, Any]) -> bool:
            payload = dict(data_obj)
            payload.setdefault("type", event_name)
            payload.setdefault("sequence_number", seq[0])
            seq[0] += 1
            frame = f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
            with write_lock:
                try:
                    self.wfile.write(frame)
                    self.wfile.flush()
                    return True
                except OSError:
                    job.cancel()
                    return False

        def send_keepalive() -> bool:
            with write_lock:
                try:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    return True
                except OSError:
                    job.cancel()
                    return False

        init_resp = _build_response_object(
            resp_id=resp_id,
            created_at=created_at,
            model=norm_model,
            status="in_progress",
            output=[],
        )
        if not send_sse("response.created", {"response": init_resp}):
            return
        if not send_sse("response.in_progress", {"response": init_resp}):
            return

        result_box: dict[str, Any] = {}
        done_evt = threading.Event()

        def worker() -> None:
            try:
                raw_out, usage = self.runtime.execute_acp_turn(
                    acp_model=acp_model,
                    acp_effort=acp_effort,
                    system_append=full_system,
                    acp_parts=acp_parts,
                    has_images=has_images,
                    job=job,
                    allow_client_calls=bool(declared_tools and tool_mode != "none"),
                )
                result_box["ok"] = (raw_out, usage)
            except BridgeError as exc:
                result_box["err"] = exc
            except Exception as exc:
                result_box["err"] = BridgeError(str(exc), status=500, code="internal_error")
            finally:
                done_evt.set()

        threading.Thread(target=worker, daemon=True).start()

        while not done_evt.wait(timeout=5.0):
            if not send_keepalive():
                return

        if "err" in result_box:
            err: BridgeError = result_box["err"]
            failed_resp = _build_response_object(
                resp_id=resp_id,
                created_at=created_at,
                model=norm_model,
                status="failed",
                output=[],
                error={"code": err.code, "message": err.message},
            )
            send_sse("response.failed", {"response": failed_resp})
            with write_lock:
                try:
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except OSError:
                    pass
            return

        raw_out, usage = result_box["ok"]
        try:
            if is_compaction:
                commentary, invocations, answer = "", [], ""
            elif not declared_tools or tool_mode == "none":
                commentary, invocations = "", []
                answer = _strip_single_json_fence(raw_out) if output_schema is not None else raw_out
            else:
                commentary, invocations, answer = parse_model_envelope(raw_out, declared_tools, tool_mode)

            finished, events = _build_output_items_and_events(
                commentary=commentary,
                invocations=invocations,
                answer=answer,
                is_compaction=is_compaction,
                raw_text_for_compaction=raw_out,
            )
            for ev_name, ev_data in events:
                if not send_sse(ev_name, ev_data):
                    return

            self._cache_turn(resp_id, prior, req.get("input"), finished)
            completed_resp = _build_response_object(
                resp_id=resp_id,
                created_at=created_at,
                model=norm_model,
                status="completed",
                output=finished,
                usage=usage,
            )
            send_sse("response.completed", {"response": completed_resp})
        except BridgeError as exc:
            failed_resp = _build_response_object(
                resp_id=resp_id,
                created_at=created_at,
                model=norm_model,
                status="failed",
                output=[],
                error={"code": exc.code, "message": exc.message},
            )
            send_sse("response.failed", {"response": failed_resp})

        with write_lock:
            try:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except OSError:
                pass

    def _cache_turn(
        self,
        resp_id: str,
        prior: list[dict[str, Any]] | None,
        req_input: Any,
        finished_items: list[dict[str, Any]],
    ) -> None:
        hist: list[dict[str, Any]] = list(prior) if prior else []
        if isinstance(req_input, str):
            hist.append({"type": "message", "role": "user", "content": req_input})
        elif isinstance(req_input, list):
            for x in req_input:
                if isinstance(x, dict):
                    hist.append(x)
        hist.extend(finished_items)
        self.runtime.remember_response(resp_id, hist)


def serve_from_config(config_path: Path) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    log_path_raw = config.get("log_file")
    log_handle = None
    if log_path_raw:
        lp = Path(log_path_raw)
        lp.parent.mkdir(parents=True, exist_ok=True)
        log_handle = lp.open("a", encoding="utf-8", buffering=1)
        sys.stderr = log_handle
        if sys.stdout is None:
            sys.stdout = log_handle

    host = str(config.get("listen_host") or "127.0.0.1")
    port = int(config.get("listen_port", 18045))
    runtime = BridgeRuntime(config)
    runtime.validate_runtime()
    runtime.read_auth_token()

    if os.name != "nt" and config.get("watch_codex_ssh_daemon", True):
        CodexWatcher(config).start()

    server = LoopbackThreadingHTTPServer((host, port), BridgeRequestHandler, runtime)

    def _handle_sig(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, _handle_sig)
        signal.signal(signal.SIGINT, _handle_sig)
    except Exception:
        pass

    if sys.stderr is not None:
        sys.stderr.write(f"[antigravity-acp-bridge] listening on http://{host}:{port} (loopback only)\n")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        runtime.shutdown()
        if log_handle is not None:
            log_handle.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Official Antigravity ACP -> OpenAI Responses local bridge")
    parser.add_argument("--config", required=True, help="Path to bridge_config.json")
    parser.add_argument("--check-only", action="store_true", help="Validate runtime and auth config, then exit")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if args.check_only:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
        rt = BridgeRuntime(cfg)
        rt.validate_runtime()
        rt.read_auth_token()
        print(json.dumps({"status": "ok", "agy_path": str(rt.agy_path), "version": BRIDGE_VERSION}))
        return 0

    serve_from_config(cfg_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
