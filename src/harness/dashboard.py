"""Read-only, loopback dashboard over recorded investigation directories."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

STATIC = Path(__file__).with_name("web")


def read_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def read_lines(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.is_file() else []


def make_handler(runs_root: Path):
    root = runs_root.resolve()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = unquote(urlsplit(self.path).path)
            try:
                if path == "/api/runs":
                    runs = []
                    for folder in root.iterdir() if root.exists() else []:
                        if folder.is_symlink() or not folder.is_dir():
                            continue
                        try:
                            run = read_json(folder / "run.json", None)
                            if isinstance(run, dict):
                                runs.append({**run, "directory": folder.name})
                        except (ValueError, OSError):
                            continue
                    self.json_response(sorted(runs, key=lambda r: r.get("created_at", ""), reverse=True))
                    return
                if path.startswith("/api/runs/"):
                    name = path.removeprefix("/api/runs/")
                    folder = (root / name).resolve()
                    if not name or folder.parent != root or not (folder / "run.json").is_file():
                        self.send_error(404)
                        return
                    self.json_response({
                        "run": read_json(folder / "run.json", {}),
                        "findings": read_json(folder / "findings.json", []),
                        "observations": read_json(folder / "observations.json", []),
                        "events": read_lines(folder / "events.jsonl"),
                        "gaps": read_lines(folder / "gaps.jsonl"),
                        "report": (folder / "report.md").read_text(encoding="utf-8") if (folder / "report.md").is_file() else "Report not available yet.",
                    })
                    return
                assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
                if path not in assets:
                    self.send_error(404)
                    return
                file, mime = assets[path]
                self.respond((STATIC / file).read_bytes(), mime + "; charset=utf-8")
            except (OSError, ValueError):
                self.send_error(500, "Unable to read this investigation record")

        def json_response(self, data):
            self.respond(json.dumps(data).encode(), "application/json; charset=utf-8")

        def respond(self, content: bytes, mime: str):
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(content)

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--runs", type=Path, default=Path("runs"))
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.runs))
    print(f"Dashboard: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
