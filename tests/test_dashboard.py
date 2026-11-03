"""Exercise the dashboard's actual HTTP boundary without running investigations."""
import json
from io import BytesIO

from harness.dashboard import make_handler


def test_dashboard_records_and_path_boundary(tmp_path):
    runs = tmp_path / "runs"
    folder = runs / "demo"
    folder.mkdir(parents=True)
    (folder / "run.json").write_text(json.dumps({"run_id": "recorded", "created_at": "2026-10-19"}))
    (folder / "findings.json").write_text('[{"title":"<script>untrusted</script>"}]')
    outside = tmp_path / "private"
    outside.mkdir()
    (outside / "run.json").write_text('{"secret":true}')
    # Feed real HTTP requests through BaseHTTPRequestHandler, without requiring
    # socket access in restricted development environments.
    class Connection:
        def __init__(self, path):
            self.input = BytesIO(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
            self.output = BytesIO()

        def makefile(self, *args):
            return self.input

        def sendall(self, content):
            self.output.write(content)

    def get(path):
        connection = Connection(path)
        make_handler(runs)(connection, ("127.0.0.1", 0), None)
        headers, body = connection.output.getvalue().split(b"\r\n\r\n", 1)
        return headers.decode(), body

    headers, body = get("/")
    assert "200 OK" in headers
    assert "frame-ancestors 'none'" in headers
    assert b"Investigation workspace" in body
    assert json.loads(get("/api/runs")[1])[0]["directory"] == "demo"
    result = json.loads(get("/api/runs/demo")[1])
    assert result["findings"][0]["title"] == "<script>untrusted</script>"
    assert result["events"] == []
    assert result["report"] == "Report not available yet."
    for path in ["/api/runs/..%2Fprivate", "/api/runs/missing", "/run.json"]:
        assert "404 Not Found" in get(path)[0]
