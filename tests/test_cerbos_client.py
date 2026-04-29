"""Tests for the Cerbos HTTP client (ADR-0001) — uses `responses` to mock HTTP."""

from __future__ import annotations

import json

import responses

from secured_claude.cerbos_client import CerbosClient


@responses.activate
def test_check_allow() -> None:
    responses.add(
        responses.POST,
        "http://127.0.0.1:3592/api/check/resources",
        json={"results": [{"actions": {"read": "EFFECT_ALLOW"}}]},
        status=200,
    )
    client = CerbosClient()
    result = client.check(
        principal_id="p",
        principal_roles=["agent"],
        principal_attr={"trust_level": 0},
        resource_kind="file",
        resource_id="/workspace/foo.py",
        resource_attr={"path": "/workspace/foo.py"},
        actions=["read"],
    )
    assert result.allow is True
    assert "EFFECT_ALLOW" in result.reason


@responses.activate
def test_check_deny() -> None:
    responses.add(
        responses.POST,
        "http://127.0.0.1:3592/api/check/resources",
        json={"results": [{"actions": {"read": "EFFECT_DENY"}}]},
        status=200,
    )
    client = CerbosClient()
    result = client.check(
        principal_id="p",
        principal_roles=["agent"],
        principal_attr={},
        resource_kind="file",
        resource_id="/etc/passwd",
        resource_attr={"path": "/etc/passwd"},
        actions=["read"],
    )
    assert result.allow is False
    assert "EFFECT_DENY" in result.reason


@responses.activate
def test_check_request_body_shape() -> None:
    """Verify the request body matches Cerbos's expected schema."""
    responses.add(
        responses.POST,
        "http://127.0.0.1:3592/api/check/resources",
        json={"results": [{"actions": {"read": "EFFECT_ALLOW"}}]},
        status=200,
    )
    client = CerbosClient()
    client.check(
        principal_id="claude-code-default",
        principal_roles=["agent"],
        principal_attr={"trust_level": 0},
        resource_kind="file",
        resource_id="/workspace/foo.py",
        resource_attr={"path": "/workspace/foo.py"},
        actions=["read"],
    )
    assert len(responses.calls) == 1
    raw = responses.calls[0].request.body or b""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    body = json.loads(raw)
    assert body["principal"]["id"] == "claude-code-default"
    assert body["principal"]["roles"] == ["agent"]
    assert body["resources"][0]["resource"]["kind"] == "file"
    assert body["resources"][0]["actions"] == ["read"]


@responses.activate
def test_check_no_results_treated_as_deny() -> None:
    responses.add(
        responses.POST,
        "http://127.0.0.1:3592/api/check/resources",
        json={"results": []},
        status=200,
    )
    result = CerbosClient().check(
        principal_id="p",
        principal_roles=["agent"],
        principal_attr={},
        resource_kind="file",
        resource_id="/x",
        resource_attr={"path": "/x"},
        actions=["read"],
    )
    assert result.allow is False
