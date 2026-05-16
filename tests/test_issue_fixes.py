import json
import pytest
from core.llm_provider import parse_robust_json

def test_robust_json_unescaped_quotes():
    raw = '{"think": "test", "content": "<?xml version="1.0" encoding="UTF-8"?>", "status": "OK"}'
    parsed = parse_robust_json(raw)
    assert parsed is not None
    assert parsed["content"] == '<?xml version="1.0" encoding="UTF-8"?>'

def test_robust_json_with_garbage():
    raw = 'Here is the result: {"key": "value"} hope it helps.'
    parsed = parse_robust_json(raw)
    assert parsed == {"key": "value"}

def test_robust_json_truncated():
    raw = '{"key": "value", "nested": {"a": 1'
    parsed = parse_robust_json(raw)
    assert parsed["key"] == "value"
    assert parsed["nested"]["a"] == 1

if __name__ == "__main__":
    test_robust_json_unescaped_quotes()
    test_robust_json_with_garbage()
    test_robust_json_truncated()
    print("All robust JSON tests passed!")
