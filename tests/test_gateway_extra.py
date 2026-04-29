"""Extra gateway tests — Write/Edit/MultiEdit/WebSearch coverage."""

from __future__ import annotations

from secured_claude.gateway import map_tool_to_resource


def test_map_write_extracts_path_and_size() -> None:
    kind, _rid, action, attr = map_tool_to_resource(
        "Write", {"file_path": "/workspace/foo.py", "content": "hello world"}
    )
    assert kind == "file"
    assert action == "write"
    assert attr["path"] == "/workspace/foo.py"
    assert attr["size"] == len("hello world")


def test_map_write_with_path_alias() -> None:
    """The hook may pass `path` instead of `file_path` — we accept both."""
    kind, _rid, action, attr = map_tool_to_resource(
        "Write", {"path": "/workspace/foo.py", "content": "x"}
    )
    assert kind == "file"
    assert action == "write"
    assert attr["path"] == "/workspace/foo.py"


def test_map_write_no_content_zero_size() -> None:
    _kind, _rid, _action, attr = map_tool_to_resource("Write", {"file_path": "/x"})
    assert attr["size"] == 0


def test_map_write_non_string_content_zero_size() -> None:
    """Defensive: if content is not a string, size is reported as 0 (not crash)."""
    _kind, _rid, _action, attr = map_tool_to_resource(
        "Write", {"file_path": "/x", "content": {"unexpected": "shape"}}
    )
    assert attr["size"] == 0


def test_map_edit_extracts_path() -> None:
    kind, _rid, action, attr = map_tool_to_resource("Edit", {"file_path": "/workspace/foo.py"})
    assert kind == "file"
    assert action == "edit"
    assert attr["path"] == "/workspace/foo.py"


def test_map_multiedit_treated_as_edit() -> None:
    kind, _rid, action, attr = map_tool_to_resource("MultiEdit", {"file_path": "/workspace/foo.py"})
    assert kind == "file"
    assert action == "edit"
    assert attr["path"] == "/workspace/foo.py"


def test_map_websearch_extracts_query() -> None:
    kind, _rid, action, attr = map_tool_to_resource(
        "WebSearch", {"query": "claude code documentation"}
    )
    assert kind == "web_search"
    assert action == "query"
    assert attr["query_text"] == "claude code documentation"


def test_map_webfetch_with_http_default_port() -> None:
    """HTTP defaults to port 80, HTTPS to 443 — verify the default for plain HTTP."""
    _kind, _rid, _action, attr = map_tool_to_resource(
        "WebFetch", {"url": "http://example.com/path"}
    )
    assert attr["scheme"] == "http"
    assert attr["port"] == 80


def test_map_bash_empty_command() -> None:
    """An empty command means cmd_first_word is empty (defensive)."""
    _kind, _rid, _action, attr = map_tool_to_resource("Bash", {"command": ""})
    assert attr["cmd_first_word"] == ""


def test_map_mcp_with_only_two_segments() -> None:
    """Defensive: malformed MCP tool name with only one __ separator."""
    kind, _rid, _action, attr = map_tool_to_resource("mcp__only_server", {})
    assert kind == "mcp_tool"
    assert attr["server"] == "only_server"
    assert attr["tool"] == ""
