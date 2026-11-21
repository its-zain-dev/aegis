#!/usr/bin/env python3
"""End-to-end smoke test for the compiled `aegis` binary.

Verifies:
1. CLI check & test-redact commands
2. Live `aegis serve --stdio` multiplexing a real child Stdio MCP server
   - initialize, tools/list (hiding denied tools), tools/call allowed + secret redaction,
     BLAKE3 cache hit on 2nd call, tools/call blocked (-32001)
3. Live `aegis serve --http` Streamable HTTP (2025-03-26) gateway
   - POST /mcp, GET /health, GET /metrics, live `aegis status --json` over IPC
4. Binary WAL trace inspection:
   - `aegis export --format jsonl`
   - `aegis export --format otel`
   - `aegis replay --mode diff`
   - `aegis replay --mode serve-stdio`
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request


MOCK_SERVER_CODE = textwrap.dedent(
    """\
    import json, sys

    call_count = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if "id" not in msg:
            continue
        req_id = msg["id"]
        method = msg.get("method", "")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "py-mock", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "list_issues",
                        "description": "List open issues",
                        "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}}},
                    },
                    {
                        "name": "delete_repo",
                        "description": "Delete repository",
                        "inputSchema": {"type": "object"},
                    },
                ]
            }
        elif method == "tools/call":
            call_count += 1
            name = msg.get("params", {}).get("name", "")
            result = {
                "content": [{
                    "type": "text",
                    "text": f"call#{call_count} tool={name} pat=ghp_abcdefghijklmnopqrstuvwxyz012345 aws=AKIAIOSFODNN7EXAMPLE",
                }],
                "isError": False,
            }
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\\n")
        sys.stdout.flush()
    """
)


def run_cmd(args, input_text=None):
    res = subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        check=True,
    )
    return res.stdout, res.stderr


def send_stdio_rpc(proc, payload):
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    assert line, f"EOF waiting for response to {payload}"
    return json.loads(line)


def http_json_post(url, payload, headers=None):
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8")), dict(resp.headers)


def main():
    if len(sys.argv) < 2:
        print("Usage: e2e_smoke.py <path-to-aegis-binary>", file=sys.stderr)
        sys.exit(2)
    aegis = os.path.abspath(sys.argv[1])
    assert os.path.exists(aegis), f"binary not found: {aegis}"

    with tempfile.TemporaryDirectory() as tmp:
        mock_py = os.path.join(tmp, "mock_mcp.py")
        with open(mock_py, "w", encoding="utf-8") as f:
            f.write(MOCK_SERVER_CODE)

        wal_path = os.path.join(tmp, "trace.wal")
        cache_dir = os.path.join(tmp, "cache")
        ipc_sock = os.path.join(tmp, "aegis.sock")
        cfg_path = os.path.join(tmp, "aegis.toml")

        cfg = textwrap.dedent(
            f"""\
            [gateway]
            name = "aegis-e2e"
            hide_denied_tools = true

            [ipc]
            enabled = true
            path = '{ipc_sock}'

            [policy]
            default = "allow"
            deny = ["*__delete_*"]

            [profiles.readonly]
            default = "deny"
            allow = ["*__list_*"]

            [cache]
            enabled = true
            dir = '{cache_dir}'
            allow = ["*__list_*"]

            [trace]
            enabled = true
            path = '{wal_path}'
            compress = true

            [servers.github]
            transport = "stdio"
            command = '{sys.executable}'
            args = ['{mock_py}']
            """
        )
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg)

        # 1. Version, Check, Test-Redact
        out, _ = run_cmd([aegis, "--version"])
        assert "0.9.0" in out, out

        out, _ = run_cmd([aegis, "check", "--config", cfg_path, "--test-tool", "github__delete_repo"])
        assert "DENY" in out, out

        out, _ = run_cmd([
            aegis,
            "test-redact",
            "--config",
            cfg_path,
            "--text",
            "gh=ghp_abcdefghijklmnopqrstuvwxyz012345 db=postgres://u:secretpass@host/db",
        ])
        assert "[REDACTED:github_token]" in out, out
        assert "[REDACTED:database_url]" in out, out
        assert "secretpass" not in out, out
        print("[PASS] version, check, test-redact")

        # 2. Live Stdio Mode round-trip
        stdio_proc = subprocess.Popen(
            [aegis, "serve", "--stdio", "--config", cfg_path, "--no-ipc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            init_resp = send_stdio_rpc(
                stdio_proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "e2e-client", "version": "1.0"},
                    },
                },
            )
            assert init_resp["result"]["serverInfo"]["name"] == "aegis-e2e"

            list_resp = send_stdio_rpc(
                stdio_proc,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            tool_names = [t["name"] for t in list_resp["result"]["tools"]]
            assert tool_names == ["github__list_issues"], tool_names

            # Blocked call -> -32001
            blocked_resp = send_stdio_rpc(
                stdio_proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "github__delete_repo", "arguments": {}},
                },
            )
            assert blocked_resp["error"]["code"] == -32001, blocked_resp

            # First allowed call -> redacted secrets, call#1
            ok1 = send_stdio_rpc(
                stdio_proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "github__list_issues", "arguments": {"repo": "aegis"}},
                },
            )
            text1 = ok1["result"]["content"][0]["text"]
            assert "call#1" in text1, text1
            assert "[REDACTED:github_token]" in text1, text1
            assert "[REDACTED:aws_access_key]" in text1, text1
            assert "ghp_" not in text1 and "AKIA" not in text1

            # Second identical call -> BLAKE3 cache hit (still call#1!)
            ok2 = send_stdio_rpc(
                stdio_proc,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "github__list_issues", "arguments": {"repo": "aegis"}},
                },
            )
            text2 = ok2["result"]["content"][0]["text"]
            assert "call#1" in text2, f"expected cache hit call#1, got: {text2}"
        finally:
            stdio_proc.stdin.close()
            stdio_proc.wait(timeout=10)
        print("[PASS] serve --stdio (multiplex, policy, redaction, BLAKE3 cache)")

        # 3. Live Streamable HTTP Mode + IPC status + /health + /metrics
        http_proc = subprocess.Popen(
            [aegis, "serve", "--http", "127.0.0.1:17499", "--config", cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(40):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:17499/health", timeout=1) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.15)
            else:
                raise RuntimeError("HTTP gateway failed to become healthy")

            init_http, headers = http_json_post(
                "http://127.0.0.1:17499/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "antigravity-e2e", "version": "1.0"},
                    },
                },
            )
            assert init_http["result"]["protocolVersion"] == "2025-03-26"
            sid = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
            assert sid, f"missing Mcp-Session-Id header: {headers}"

            call_http, _ = http_json_post(
                "http://127.0.0.1:17499/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "github__list_issues", "arguments": {"repo": "aegis"}},
                },
                headers={"Mcp-Session-Id": sid},
            )
            assert "call#1" in call_http["result"]["content"][0]["text"]

            with urllib.request.urlopen("http://127.0.0.1:17499/metrics", timeout=5) as r:
                metrics = r.read().decode("utf-8")
                assert "aegis_calls_total 1" in metrics, metrics

            status_out, _ = run_cmd([aegis, "status", "--config", cfg_path, "--json"])
            status_json = json.loads(status_out)
            assert status_json["stats"]["cache_hits"] >= 1, status_json
        finally:
            http_proc.terminate()
            http_proc.wait(timeout=10)
        print("[PASS] serve --http (Streamable HTTP, Mcp-Session-Id, /health, /metrics, IPC status)")

        # 4. WAL Export (JSONL & OTel) + Replay (diff & serve-stdio)
        jsonl_out, _ = run_cmd([aegis, "export", wal_path, "--format", "jsonl"])
        records = [json.loads(l) for l in jsonl_out.strip().splitlines() if l.strip()]
        assert len(records) >= 4, len(records)

        otel_out, _ = run_cmd([aegis, "export", wal_path, "--format", "otel"])
        otel = json.loads(otel_out)
        assert len(otel["resourceSpans"][0]["scopeSpans"][0]["spans"]) == len(records)

        diff_out, _ = run_cmd([
            aegis,
            "replay",
            wal_path,
            "--mode",
            "diff",
            "--config",
            cfg_path,
            "--profile",
            "readonly",
            "--json",
        ])
        diff = json.loads(diff_out)
        assert diff["total_records"] == len(records), diff

        replay_proc = subprocess.Popen(
            [aegis, "replay", wal_path, "--mode", "serve-stdio", "--config", cfg_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            r_call = send_stdio_rpc(
                replay_proc,
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "github__list_issues", "arguments": {"repo": "aegis"}},
                },
            )
            assert "call#1" in r_call["result"]["content"][0]["text"]
        finally:
            replay_proc.stdin.close()
            replay_proc.wait(timeout=10)
        print("[PASS] WAL export (jsonl & otel) + replay (diff & serve-stdio)")

    print("ALL E2E SMOKE TESTS PASSED!")


if __name__ == "__main__":
    main()
