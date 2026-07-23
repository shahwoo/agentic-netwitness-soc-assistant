from __future__ import annotations

import json

from backend.openai_client import extract_json_object


def test_extract_json_object_plain_object():
    assert extract_json_object('{"status": "ok", "items": []}') == {"status": "ok", "items": []}


def test_extract_json_object_strips_markdown_fence():
    raw = """```json
{"status": "ok", "items": ["a"]}
```"""
    assert extract_json_object(raw) == {"status": "ok", "items": ["a"]}


def test_extract_json_object_with_surrounding_text():
    raw = 'Here is the result:\n{"status": "ok", "value": 3}\nDone.'
    assert extract_json_object(raw) == {"status": "ok", "value": 3}


def test_extract_json_object_balanced_nested_object_with_braces_in_string():
    payload = {
        "status": "ok",
        "nested": {"message": "PowerShell used {not json} inside command text"},
        "items": [{"id": 1}],
    }
    raw = f"prefix {json.dumps(payload)} suffix {{this is not valid"
    assert extract_json_object(raw) == payload


def test_extract_json_object_invalid_or_non_object_returns_empty_dict():
    assert extract_json_object("not json") == {}
    assert extract_json_object('["not", "an", "object"]') == {}
