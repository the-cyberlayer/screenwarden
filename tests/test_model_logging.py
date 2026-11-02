import json

from screenwarden import Guard

XML = ('<hierarchy><node text="Hi" class="android.widget.TextView" package="com.example" '
       'bounds="[0,0][1080,2400]"/></hierarchy>')


def test_every_log_line_records_the_exact_model(tmp_path):
    log = tmp_path / "log.jsonl"
    guard = Guard("Read my messages", log_path=log, model="claude-test-20261102")
    guard.observe(XML, "com.example")
    guard.check({"type": "wait"})
    lines = [json.loads(line) for line in log.read_text().splitlines()]
    assert [line["event"] for line in lines] == ["sanitize_screen", "check_action"]
    assert all(line["model"] == "claude-test-20261102" for line in lines)
