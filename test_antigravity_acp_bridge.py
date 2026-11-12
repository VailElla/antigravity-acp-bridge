#!/usr/bin/env python3
"""Unit and mock-ACP integration tests for antigravity_acp_bridge.py and agy_ssh_lan.py."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agy_ssh_lan as ssh_lan
import antigravity_acp_bridge as bridge


MOCK_AGY_SCRIPT = """#!/usr/bin/env python3
import json, sys, time
from pathlib import Path

while True:
    line = sys.stdin.readline()
    if not line:
        break
    msg = json.loads(line)
    ident = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})
    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": ident,
            "result": {
                "protocolVersion": 1,
                "agentInfo": {"name": "Mock ACP", "version": "1.5.6"},
                "agentCapabilities": {
                    "promptCapabilities": {"image": True},
                    "_meta": {"antigravity": {"systemPrompt": {"append": True}}},
                },
            },
        }
        sys.stdout.write(json.dumps(resp) + "\\n")
        sys.stdout.flush()
    elif method == "session/new":
        opts = [
            {
                "id": "model",
                "currentValue": "gemini-4-carbon",
                "options": [
                    {"value": "gemini-4-carbon"},
                    {"value": "gemini-4-argon"},
                    {"value": "gemini-3.8-flash"},
                ],
            },
            {
                "id": "thought_level",
                "currentValue": "medium",
                "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
            },
        ]
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": ident, "result": {"sessionId": "s1", "configOptions": opts}}) + "\\n")
        sys.stdout.flush()
    elif method == "session/set_config_option":
        cid = params["configId"]
        val = params["value"]
        opts = [
            {
                "id": "model",
                "currentValue": val if cid == "model" else "gemini-4-carbon",
                "options": [
                    {"value": "gemini-4-carbon"},
                    {"value": "gemini-4-argon"},
                    {"value": "gemini-3.8-flash"},
                ],
            },
            {
                "id": "thought_level",
                "currentValue": val if cid == "thought_level" else "high",
                "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
            },
        ]
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": ident, "result": {"configOptions": opts}}) + "\\n")
        sys.stdout.flush()
    elif method == "session/prompt":
        prompt_text = params["prompt"][0]["text"]
        overlap = next((m for m in ("OVERLAP_A", "OVERLAP_B", "OVERLAP_C") if m in prompt_text), None)
        if overlap:
            Path(overlap).touch()
            until = time.monotonic() + 8
            while not Path("release-parallel-test").exists() and time.monotonic() < until:
                time.sleep(0.02)
            upd = {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": params["sessionId"], "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": overlap}}}}
            sys.stdout.write(json.dumps(upd) + "\\n")
            sys.stdout.flush()
        elif "TRIGGER_NATIVE_TOOL" in prompt_text:
            upd = {"jsonrpc": "2.0", "method": "session/update", "params": {"update": {"sessionUpdate": "tool_call"}}}
            sys.stdout.write(json.dumps(upd) + "\\n")
            sys.stdout.flush()
        elif "CALL_PATCH" in prompt_text:
            body = json.dumps({
                "commentary": "Applying patch",
                "tool_calls": [{"name": "apply_patch", "arguments": {"input": "*** Begin Patch\\n*** End Patch"}}],
                "answer": "",
            })
            upd = {"jsonrpc": "2.0", "method": "session/update", "params": {"update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": body}}}}
            sys.stdout.write(json.dumps(upd) + "\\n")
            sys.stdout.flush()
        else:
            if "CALL_HEAD_WRAPPED" in prompt_text:
                body = json.dumps([{
                    "commentary": "Checking the script",
                    "tool_calls": [{"name": "exec_command", "arguments": {"cmd": "head -n 65 trial.py", "login": False}}],
                    "answer": "",
                }])
            elif "ACP_RETRY_ONCE" in prompt_text or "ACP_RETRY_NEVER" in prompt_text:
                attempted = Path("acp-retry-attempted")
                call = {"name": "exec_command", "arguments": {"cmd": "pwd", "login": False}}
                if "ACP_RETRY_ONCE" in prompt_text and attempted.exists():
                    body = json.dumps({"commentary": "", "client_calls": [call], "answer": ""})
                else:
                    attempted.touch()
                    call["arguments"]["cmd"] = "superseded attempt"
                    body = (
                        json.dumps({"commentary": "", "tool_calls": [call], "answer": ""})
                        + "\\n⚠ Your previous response contained an improperly formatted function call: Malformed call."
                        + "\\nPlease retry with a properly formatted function call\\nRetries remaining: 3\\n"
                        + json.dumps({"commentary": "", "tool_calls": [], "answer": "Unable to invoke the tool."})
                    )
            elif "ACP_UPSTREAM_INTERRUPT_ONCE" in prompt_text or "ACP_UPSTREAM_INTERRUPT_NEVER" in prompt_text:
                attempted = Path("acp-upstream-interruption-attempted")
                if "ACP_UPSTREAM_INTERRUPT_ONCE" in prompt_text and attempted.exists():
                    body = json.dumps({"commentary": "", "client_calls": [{"name": "exec_command", "arguments": {"cmd": "pwd"}}], "answer": ""})
                else:
                    attempted.touch()
                    body = (
                        "⚠ The stream was interrupted. Please continue the task you were working on.\\n\\n"
                        "⚠ API error (attempt 2): request failed: upstream EOF\\n"
                        + json.dumps([{" commentary": "", "client_calls": [{"name": "exec_command", "arguments": {"cmd": "superseded"}}], "answer": ""}])
                    )
            elif "ACP_EXECUTION_ERROR" in prompt_text:
                body = "\u26a0 Agent execution terminated due to error."
            else:
                body = json.dumps({"commentary": "", "tool_calls": [], "answer": "CARBON_MOCK_OK"})
            upd = {"jsonrpc": "2.0", "method": "session/update", "params": {"update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": body}}}}
            sys.stdout.write(json.dumps(upd) + "\\n")
            sys.stdout.flush()
        done = {
            "jsonrpc": "2.0",
            "id": ident,
            "result": {
                "stopReason": "end_turn",
                "usage": {
                    "inputTokens": 100,
                    "outputTokens": 25,
                    "cachedReadTokens": 10,
                    "cachedWriteTokens": 0,
                    "thoughtTokens": 5,
                    "totalTokens": 135,
                },
            },
        }
        sys.stdout.write(json.dumps(done) + "\\n")
        sys.stdout.flush()
    elif method == "session/close":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": ident, "result": {}}) + "\\n")
        sys.stdout.flush()
"""


class BridgeUnitTests(unittest.TestCase):
    def test_model_and_effort_mapping(self) -> None:
        self.assertEqual(
            bridge.resolve_model_and_effort("gemini-4-carbon", {"effort": "xhigh"}),
            ("gemini-4-carbon", "high", "gemini-4-carbon"),
        )
        self.assertEqual(
            bridge.resolve_model_and_effort("gemini-4-carbon-low", {"effort": "high"}),
            ("gemini-4-carbon", "low", "gemini-4-carbon-low"),
        )
        self.assertEqual(
            bridge.resolve_model_and_effort("gemini-3.8-flash", None),
            ("gemini-3.8-flash", "medium", "gemini-3.8-flash"),
        )
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.resolve_model_and_effort("claude-opus-5-5-high", None)
        self.assertEqual(ctx.exception.status, 400)

    def test_instruction_neutralization(self) -> None:
        raw = "You are Codex, a coding agent based on GPT-5. Keep /home/example/project/AGENTS.md intact."
        cleaned = bridge.neutralize_instructions(raw)
        self.assertNotIn("You are Codex", cleaned)
        self.assertIn("/home/example/project/AGENTS.md", cleaned)

    def test_declared_tools_and_envelope(self) -> None:
        raw_tools = [
            {"type": "function", "name": "shell_command", "parameters": {"type": "object"}},
            {"type": "custom", "name": "apply_patch", "description": "Patch files"},
            {
                "type": "namespace",
                "name": "mcp_demo",
                "tools": [{"type": "function", "name": "ping", "parameters": {"type": "object"}}],
            },
            {"type": "web_search"},
        ]
        tools, mode, _ = bridge.parse_declared_tools(raw_tools, "auto")
        self.assertEqual(mode, "auto")
        self.assertEqual([t.wire_name for t in tools], ["shell_command", "apply_patch", "mcp_demo__ping"])

        fenced = '```json\n{"commentary":"checking","tool_calls":[{"name":"mcp_demo__ping","arguments":{}}],"answer":""}\n```'
        comm, invs, ans = bridge.parse_model_envelope(fenced, tools, mode)
        self.assertEqual(comm, "checking")
        self.assertEqual(ans, "")
        self.assertEqual(len(invs), 1)
        self.assertEqual(invs[0].tool.real_name, "ping")
        self.assertEqual(invs[0].tool.namespace, "mcp_demo")
        self.assertEqual(invs[0].arguments_json, "{}")

    def test_tool_envelope_wrappers_preserve_call_arguments(self) -> None:
        tools, mode, _ = bridge.parse_declared_tools([
            {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
        ], "auto")
        args = {"cmd": "head -n 65 trial.py", "login": False}
        envelope = {"commentary": "", "tool_calls": [{"name": "exec_command", "arguments": args}], "answer": ""}
        raw_object = json.dumps(envelope)
        raw_array = json.dumps([envelope])
        for text, expected_note in (
            (raw_array, ""),
            ("Checking the script." + raw_object, "Checking the script."),
            ("[Progress] Checking the script.\n" + raw_array, "[Progress] Checking the script."),
            ("Checking the script.\n```json\n" + raw_array + "\n```", "Checking the script."),
        ):
            with self.subTest(text=text):
                note, calls, answer = bridge.parse_model_envelope(text, tools, mode)
                self.assertEqual(note, expected_note)
                self.assertEqual(answer, "")
                self.assertEqual([call.tool.real_name for call in calls], ["exec_command"])
                self.assertEqual(json.loads(calls[0].arguments_json), args)

        for text in (
            json.dumps([envelope, envelope]),
            json.dumps([{"tool_calls": ["an example"], "answer": "a label", "other": True}]),
            raw_array[:-1],
        ):
            with self.subTest(text=text):
                self.assertEqual(bridge.parse_model_envelope(text, tools, mode), ("", [], text))
        self.assertEqual(bridge.parse_model_envelope(raw_array, tools, "none"), ("", [], raw_array))

        envelope["tool_calls"][0]["name"] = "undeclared_command"
        with self.assertRaises(bridge.BridgeError) as error:
            bridge.parse_model_envelope(json.dumps([envelope]), tools, mode)
        self.assertEqual(error.exception.code, "undeclared_tool_call")

    def test_only_last_complete_acp_retry_attempt_can_request_tools(self) -> None:
        tools, mode, _ = bridge.parse_declared_tools([
            {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
        ], "auto")
        first = json.dumps({"tool_calls": [{"name": "exec_command", "arguments": {"cmd": "superseded"}}], "answer": ""})
        last = json.dumps({"client_calls": [{"name": "exec_command", "arguments": {"cmd": "pwd"}}], "answer": ""})
        notice = (
            "\n⚠ Your previous response contained an improperly formatted function call\n"
            "Please retry with a properly formatted function call\nRetries remaining: 3\n"
        )
        recovered = bridge._recover_acp_tool_retry_output(first + notice + last, True)
        _, calls, answer = bridge.parse_model_envelope(recovered, tools, mode)
        self.assertEqual([json.loads(call.arguments_json) for call in calls], [{"cmd": "pwd"}])
        self.assertEqual(answer, "")
        for terminal, allowed in ((last, False), (last[:-1], True), ('{"tool_calls":[],"answer":"failed"}', True)):
            with self.subTest(terminal=terminal, allowed=allowed):
                with self.assertRaises(bridge.BridgeError) as error:
                    bridge._recover_acp_tool_retry_output(first + notice + terminal, allowed)
                self.assertEqual(error.exception.code, "acp_tool_format_error")

    def test_interrupted_upstream_output_is_not_an_answer_or_a_tool_call(self) -> None:
        incomplete = (
            "⚠ The stream was interrupted. Please continue the task you were working on.\n\n"
            "⚠ API error (attempt 2): request failed: upstream EOF\n"
            '[{" commentary":"","client_calls":[{"name":"exec_command",'
            '"arguments":{"cmd":"superseded"}}],"answer":""}]'
        )
        with self.assertRaises(bridge.BridgeError) as error:
            bridge._reject_interrupted_acp_output(incomplete)
        self.assertEqual(error.exception.code, "acp_upstream_interrupted")
        # Quoted diagnostics inside a valid model answer are ordinary content.
        bridge._reject_interrupted_acp_output(json.dumps({"answer": incomplete}, ensure_ascii=False))

    def test_oversized_history_keeps_original_task_latest_user_and_tool_result(self) -> None:
        entries = [
            "[USER]\nOriginal task and constraints.",
            "[ASSISTANT]\n" + "较旧的历史资料。" * 30000,
            "[USER]\nLatest instruction: use the result below.",
            '[ASSISTANT_TOOL_CALL call_id=call_last name=exec_command]\n{"cmd":"pwd"}',
            "[TOOL_OUTPUT call_id=call_last name=exec_command]\nRECENT_RESULT",
        ]
        fitted = bridge._fit_acp_transcript(entries)
        self.assertLessEqual(len(fitted.encode("utf-8")), bridge.MAX_ACP_TRANSCRIPT_BYTES)
        for expected in ("Original task and constraints", "Latest instruction", "call_last", "RECENT_RESULT"):
            self.assertIn(expected, fitted)
        self.assertIn("omitted to fit ACP context", fitted)

        parsed = bridge.parse_responses_conversation({"input": [
            {"role": "user", "content": "Original task and constraints."},
            {"role": "assistant", "content": "历史资料" * 60000},
            {"role": "user", "content": "Latest instruction."},
        ]})[1][0]["text"]
        self.assertLessEqual(len(parsed.encode("utf-8")), bridge.MAX_ACP_TRANSCRIPT_BYTES)
        self.assertIn("Original task", parsed)
        self.assertIn("Latest instruction", parsed)

    def test_oversized_latest_message_is_rejected_instead_of_silently_cut(self) -> None:
        entries = ["[USER]\nOriginal task", "[ASSISTANT]\nEarlier result", "[USER]\n" + "x" * 180000]
        with self.assertRaises(bridge.BridgeError) as error:
            bridge._fit_acp_transcript(entries)
        self.assertEqual(error.exception.code, "latest_user_message_too_large")
        small = ["[USER]\nOriginal task", "[ASSISTANT]\nResult"]
        self.assertEqual(bridge._fit_acp_transcript(small), "\n\n".join(small))

    def test_large_tool_catalog_keeps_schemas_out_of_system_prompt(self) -> None:
        schema = {"type": "object", "properties": {"folder": {"type": "string"}}, "required": ["folder"]}
        description = "Describe the requested folder. " * 2400
        raw = [{"type": "namespace", "name": "mcp_demo", "tools": [
            {"type": "function", "name": "list_folder", "description": description, "parameters": schema},
        ]}]
        tools, mode, _ = bridge.parse_declared_tools(raw, "required")
        prompt = [{"type": "text", "text": "[USER]\nList this folder."}]
        system = bridge.build_tool_protocol_instructions(tools, mode, False, None, prompt)

        self.assertNotIn(description, system)
        self.assertIn("MUST include at least one tool call", system)
        self.assertIn('"client_calls"', system)
        self.assertNotIn('"tool_calls"', system)
        marker, catalog = prompt[1]["text"].split("\n", 1)
        self.assertEqual(marker, "[CLIENT_TOOL_CATALOG]")
        self.assertEqual(json.loads(catalog), [["mcp_demo__list_folder", description[:160], schema, None]])
        self.assertEqual(prompt[0]["text"], "[USER]\nList this folder.")

    def test_multimodal_extraction_and_1x1_skip(self) -> None:
        # 2x2 valid PNG header (width=2, height=2)
        png_2x2 = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + (2).to_bytes(4, "big")
            + (2).to_bytes(4, "big")
            + b"\x08\x02\x00\x00\x00\xfd\xd4\x9as"
        )
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + (1).to_bytes(4, "big")
            + (1).to_bytes(4, "big")
            + b"\x08\x02\x00\x00\x00\x90wS\xde"
        )
        url_2x2 = "data:image/png;base64," + base64.b64encode(png_2x2).decode("ascii")
        url_1x1 = "data:image/png;base64," + base64.b64encode(png_1x1).decode("ascii")

        req = {
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "Inspect"},
                        {"type": "input_image", "image_url": url_1x1},
                    ],
                },
                {"type": "function_call", "call_id": "c1", "name": "view_image", "arguments": "{}"},
                {
                    "type": "function_call_output",
                    "call_id": "c1",
                    "output": [{"type": "input_image", "image_url": url_2x2}],
                },
            ]
        }
        _sys, parts, _ic, _lt = bridge.parse_responses_conversation(req)
        self.assertNotIn("base64", parts[0]["text"])
        self.assertIn("[placeholder 1x1 image omitted]", parts[0]["text"])
        self.assertIn("[image-1]", parts[0]["text"])
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[2]["type"], "image")
        self.assertEqual(parts[2]["mimeType"], "image/png")

    def test_image_history_deduplicates_and_prefers_recent_inputs(self) -> None:
        def image(raw: bytes) -> dict:
            return {"type": "input_image", "image_url": "data:image/jpeg;base64," + base64.b64encode(raw).decode()}

        def result(call_id: str, *blocks: dict) -> dict:
            return {"type": "function_call_output", "call_id": call_id, "output": list(blocks)}

        old = image(b"older")
        reused = image(b"reused")
        latest = image(b"newest")
        prior = [result("old", old), result("prior", reused)]
        with mock.patch.object(bridge, "MAX_IMAGE_BYTES", 12):
            _, parts, _, _ = bridge.parse_responses_conversation({"input": [result("current", reused, latest)]}, prior)
        attached = [base64.b64decode(part["data"]) for part in parts if part["type"] == "image"]
        self.assertEqual(attached, [b"reused", b"newest"])
        text = parts[0]["text"]
        self.assertIn("call_id=old name=tool]\n[image omitted: ACP image budget exceeded]", text)
        self.assertIn("call_id=prior name=tool]\n[image-1]", text)
        self.assertIn("call_id=current name=tool]\n[image-1]\n[image-2]", text)

    def test_codex_toml_and_ssh_config_helpers(self) -> None:
        sample_toml = (
            'notify = ["cmd", "turn-ended"]\n'
            'model = "gpt-6-astra"\n'
            'sandbox_mode = "danger-full-access"\n\n'
            '[model_providers.custom]\n'
            'name = "Old"\n'
            'base_url = "http://127.0.0.1:8045/v1"\n\n'
            '[mcp_servers.blender]\n'
            'command = "blender-mcp"\n'
        )
        updated = ssh_lan.apply_provider_to_codex_config(
            sample_toml,
            model="gemini-4-carbon",
            effort="high",
            catalog_path=Path("/home/example/.codex/cc-switch-model-catalog.json"),
            base_url="http://127.0.0.1:18045/v1",
            bearer_token="TEST_ONLY_" + "x" * 32,
        )
        self.assertIn('model = "gemini-4-carbon"', updated)
        self.assertIn('base_url = "http://127.0.0.1:18045/v1"', updated)
        self.assertNotIn(":8045", updated)
        self.assertIn('[mcp_servers.blender]', updated)
        self.assertIn('sandbox_mode = "danger-full-access"', updated)

    def test_ssh_status_is_read_only_and_legacy_remote_switches_are_rejected(self) -> None:
        for args in (["enable", "example-host"], ["disable", "example-host"], ["setup-ssh-config", "example-host"], ["local-enable-tunnel"]):
            with self.subTest(args=args), mock.patch.object(sys, "argv", ["agy-ssh", *args]), redirect_stderr(StringIO()):
                with mock.patch.object(ssh_lan.subprocess, "run") as run:
                    with self.assertRaises(SystemExit) as rejected:
                        ssh_lan.main()
                    self.assertEqual(rejected.exception.code, 2)
                    run.assert_not_called()

        with mock.patch.object(ssh_lan.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b'{"hostname":"example-host"}', stderr=b"")
            self.assertEqual(ssh_lan.remote_status("example-host"), {"hostname": "example-host"})
            command = run.call_args.args[0]
            self.assertIn("ClearAllForwardings=yes", command)
            self.assertIn("local-status", command[-1])

    def test_http_sse_and_security_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            if os.name == "nt":
                mock_py = root / "mock_agy.py"
                mock_py.write_text(MOCK_AGY_SCRIPT, encoding="utf-8")
                agy = root / "agy.cmd"
                agy.write_text(f'@echo off\r\n"{sys.executable}" -I -B "{mock_py}"\r\n', encoding="utf-8")
            else:
                agy = root / "agy"
                agy.write_text(MOCK_AGY_SCRIPT, encoding="utf-8")
                agy.chmod(agy.stat().st_mode | stat.S_IEXEC)
            sha = hashlib.sha512(agy.read_bytes()).hexdigest()

            tok_file = root / "auth_token.txt"
            tok = "TEST_ONLY_" + "x" * 32
            tok_file.write_text(tok, encoding="utf-8")

            cfg = {
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "agy_path": str(agy),
                "expected_sha512": sha,
                "client_version": "1.5.6",
                "runtime_dir": str(root / "runtime"),
                "workspace_dir": str(root / "ws"),
                "auth_token_file": str(tok_file),
                # Old installations can still carry these settings during upgrade.
                "pace_min_interval_range": [60, 60],
                "pace_max_rpm": 1,
                "watch_codex_ssh_daemon": False,
            }
            rt = bridge.BridgeRuntime(cfg)
            rt.validate_runtime()
            srv = bridge.LoopbackThreadingHTTPServer(("127.0.0.1", 0), bridge.BridgeRequestHandler, rt)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                # 1. /health works without spawning resident ACP
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as r:
                    h = json.loads(r.read().decode())
                self.assertEqual(h["status"], "ok")
                self.assertFalse(h["resident_warm"])

                # 2. Unauthenticated /v1/models -> 401
                with self.assertRaises(urllib.error.HTTPError) as e401:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models", timeout=3)
                self.assertEqual(e401.exception.code, 401)

                # 3. Streaming custom_tool_call (`apply_patch`)
                req_patch = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/responses",
                    data=json.dumps(
                        {
                            "model": "gemini-4-carbon",
                            "stream": True,
                            "tools": [{"type": "custom", "name": "apply_patch"}],
                            "input": "CALL_PATCH",
                        }
                    ).encode("utf-8"),
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req_patch, timeout=10) as r:
                    sse_raw = r.read().decode("utf-8")
                self.assertIn("event: response.custom_tool_call_input.done", sse_raw)
                self.assertIn('"type": "custom_tool_call"', sse_raw)
                self.assertIn("event: response.completed", sse_raw)
                self.assertIn("data: [DONE]", sse_raw)

                for stream in (True, False):
                    with self.subTest(stream=stream):
                        request = urllib.request.Request(
                            f"http://127.0.0.1:{port}/v1/responses",
                            data=json.dumps({
                                "model": "gemini-4-carbon",
                                "stream": stream,
                                "input": "CALL_HEAD_WRAPPED",
                                "tools": [{"type": "function", "name": "exec_command", "parameters": {"type": "object"}}],
                            }).encode(),
                            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                        )
                        with urllib.request.urlopen(request, timeout=10) as response:
                            body = response.read().decode()
                        if stream:
                            self.assertIn("event: response.function_call_arguments.done", body)
                            completed = next(line for line in body.splitlines() if line.startswith("data: ") and
                                             json.loads(line[6:]).get("type") == "response.completed")
                            result = json.loads(completed[6:])["response"]
                        else:
                            result = json.loads(body)
                        self.assertEqual([item["type"] for item in result["output"]], ["message", "function_call"])
                        call = result["output"][1]
                        self.assertEqual(call["name"], "exec_command")
                        self.assertEqual(json.loads(call["arguments"]), {"cmd": "head -n 65 trial.py", "login": False})

                def request_retry(marker):
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/v1/responses",
                        data=json.dumps({
                            "model": "gemini-4-carbon", "input": marker,
                            "tools": [{"type": "function", "name": "exec_command", "parameters": {"type": "object"}}],
                        }).encode(),
                        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:
                        return json.load(response)

                recovered = request_retry("ACP_RETRY_ONCE")
                calls = [item for item in recovered["output"] if item["type"] == "function_call"]
                self.assertEqual([json.loads(call["arguments"]) for call in calls], [{"cmd": "pwd", "login": False}])
                self.assertNotIn("superseded attempt", json.dumps(recovered))
                with self.assertRaises(urllib.error.HTTPError) as error:
                    request_retry("ACP_RETRY_NEVER")
                self.assertEqual(error.exception.code, 502)
                self.assertEqual(json.load(error.exception)["error"]["code"], "acp_tool_format_error")

                recovered = request_retry("ACP_UPSTREAM_INTERRUPT_ONCE")
                calls = [item for item in recovered["output"] if item["type"] == "function_call"]
                self.assertEqual([json.loads(call["arguments"]) for call in calls], [{"cmd": "pwd"}])
                self.assertNotIn("superseded", json.dumps(recovered))
                with self.assertRaises(urllib.error.HTTPError) as error:
                    request_retry("ACP_UPSTREAM_INTERRUPT_NEVER")
                self.assertEqual(error.exception.code, 502)
                self.assertEqual(json.load(error.exception)["error"]["code"], "acp_upstream_interrupted")

                req_interrupted = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/responses",
                    data=json.dumps({
                        "model": "gemini-4-carbon", "stream": True, "input": "ACP_UPSTREAM_INTERRUPT_NEVER",
                        "tools": [{"type": "function", "name": "exec_command", "parameters": {"type": "object"}}],
                    }).encode(),
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req_interrupted, timeout=10) as r:
                    sse_interrupted = r.read().decode("utf-8")
                self.assertIn("event: response.failed", sse_interrupted)
                self.assertIn("acp_upstream_interrupted", sse_interrupted)
                self.assertNotIn("event: response.completed", sse_interrupted)
                self.assertNotIn("superseded", sse_interrupted)

                # 4. Native ACP tool rejection -> response.failed
                req_native = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/responses",
                    data=json.dumps(
                        {
                            "model": "gemini-4-carbon",
                            "stream": True,
                            "input": "TRIGGER_NATIVE_TOOL",
                        }
                    ).encode("utf-8"),
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req_native, timeout=10) as r:
                    sse_fail = r.read().decode("utf-8")
                self.assertIn("event: response.failed", sse_fail)
                self.assertIn("native_tool_rejected", sse_fail)

                req_error = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/responses",
                    data=json.dumps({"model": "gemini-4-carbon", "stream": True, "input": "ACP_EXECUTION_ERROR"}).encode(),
                    headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req_error, timeout=10) as r:
                    sse_error = r.read().decode("utf-8")
                self.assertIn("event: response.failed", sse_error)
                self.assertIn("acp_execution_error", sse_error)

                def request_text(marker):
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/v1/responses",
                        data=json.dumps({"model": "gemini-4-carbon", "input": marker}).encode(),
                        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=12) as response:
                        return json.load(response)["output"][0]["content"][0]["text"]

                markers = ("OVERLAP_A", "OVERLAP_B", "OVERLAP_C")
                with ThreadPoolExecutor(max_workers=len(markers)) as pool:
                    turns = [pool.submit(request_text, marker) for marker in markers]
                    try:
                        deadline = time.monotonic() + 6
                        while time.monotonic() < deadline and not all((rt.workspace_dir / m).exists() for m in markers):
                            time.sleep(0.02)
                        self.assertTrue(all((rt.workspace_dir / marker).exists() for marker in markers))
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as response:
                            self.assertEqual(json.load(response)["active_prompts"], len(markers))
                    finally:
                        (rt.workspace_dir / "release-parallel-test").touch()
                    self.assertEqual([turn.result(timeout=12) for turn in turns], list(markers))
            finally:
                srv.shutdown()
                srv.server_close()
                rt.shutdown()


if __name__ == "__main__":
    unittest.main()
