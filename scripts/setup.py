"""One-command setup for teammates:  python scripts/setup.py

Works on Windows, macOS and Linux with nothing but Python. It checks the tools you need, tells you
exactly what to install when one is missing or too old, then builds everything: Python harness,
signed lab scope, Laravel (.env, key, database, seed), frontend and (if PHP cannot verify HTTPS)
a CA bundle so you never have to edit php.ini.

    python scripts/setup.py            # full setup
    python scripts/setup.py --check    # only diagnose, change nothing
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = os.name == "nt"
VENV_PY = ROOT / ".venv" / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
CA_BUNDLE = ROOT / "storage" / "app" / "cacert.pem"
CA_URL = "https://curl.se/ca/cacert.pem"
MIN_PHP = (8, 3)
MIN_PYTHON = (3, 12)

problems: list[str] = []


def ok(msg: str) -> None:
    print(f"  [ok]   {msg}")


def bad(msg: str, fix: str) -> None:
    print(f"  [FAIL] {msg}\n         -> {fix}")
    problems.append(msg)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, **kw)


def step(title: str, cmd: list[str], env: dict | None = None) -> None:
    print(f"\n==> {title}")
    result = run(cmd, env={**os.environ, **(env or {})})
    if result.returncode != 0:
        sys.exit(f"\nStep failed: {title}\nFix the error above, then run this script again (it is safe to repeat).")


def tool(name: str) -> str | None:
    return shutil.which(name)


def php_version() -> tuple[int, int] | None:
    php = tool("php")
    if not php:
        return None
    out = run([php, "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"], capture_output=True).stdout
    m = re.match(r"(\d+)\.(\d+)", out.strip())
    return (int(m[1]), int(m[2])) if m else None


def php_https_errno() -> int | None:
    """cURL error number when PHP fetches an HTTPS page (60 = no CA bundle), 0 = fine."""
    php = tool("php")
    if not php:
        return None
    code = (
        "$c=curl_init('https://curl.se/');curl_setopt_array($c,[CURLOPT_NOBODY=>1,CURLOPT_TIMEOUT=>15]);"
        "curl_exec($c);echo curl_errno($c);"
    )
    out = run([php, "-r", code], capture_output=True).stdout.strip()
    return int(out) if out.isdigit() else None


def check() -> None:
    print("Checking your machine")
    if sys.version_info >= MIN_PYTHON:
        ok(f"Python {sys.version_info.major}.{sys.version_info.minor}")
    else:
        bad(f"Python {sys.version_info.major}.{sys.version_info.minor} is too old",
            f"install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ from python.org")

    ver = php_version()
    if ver is None:
        bad("PHP not found on PATH", "Windows: run  Set-ExecutionPolicy Bypass -Scope Process -Force; "
            "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient)"
            ".DownloadString('https://php.new/install/windows/8.4'))  then open a NEW terminal")
    elif ver >= MIN_PHP:
        ok(f"PHP {ver[0]}.{ver[1]}")
    else:
        bad(f"PHP {ver[0]}.{ver[1]} is too old (Laravel 13 needs {MIN_PHP[0]}.{MIN_PHP[1]}+; XAMPP ships 8.2)",
            "install PHP 8.4 via https://php.new and make sure it comes first on PATH "
            "(check with: php -v)")

    for name, hint in (("composer", "https://getcomposer.org/download/ (php.new installs it too)"),
                       ("npm", "install Node.js LTS from https://nodejs.org")):
        ok(name) if tool(name) else bad(f"{name} not found on PATH", hint)

    if ver and ver >= MIN_PHP:
        errno = php_https_errno()
        if errno == 0:
            ok("PHP can make HTTPS requests")
        elif errno in (60, 77):
            print("  [warn] PHP has no CA certificates (cURL error 60); setup will download a bundle for the app")
        elif errno is not None:
            print(f"  [warn] PHP could not reach https://curl.se (cURL error {errno}); are you online?")


def ensure_ca_bundle() -> None:
    errno = php_https_errno()
    if errno not in (60, 77):
        return
    print("\n==> Downloading a CA certificate bundle for PHP")
    CA_BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(CA_URL, timeout=60) as r:  # Python ships its own certificates
        CA_BUNDLE.write_bytes(r.read())
    set_env("AGENT_CA_BUNDLE", str(CA_BUNDLE))
    ok(f"saved {CA_BUNDLE} and set AGENT_CA_BUNDLE in .env")


def set_env(key: str, value: str) -> None:
    path = ROOT / ".env"
    text = path.read_text(encoding="utf-8")
    line = f"{key}={value}"
    if re.search(rf"^#?\s*{key}=.*$", text, re.M):
        text = re.sub(rf"^#?\s*{key}=.*$", lambda _m: line, text, count=1, flags=re.M)
    else:
        text += f"\n{line}\n"
    path.write_text(text, encoding="utf-8")


def setup() -> None:
    py = str(VENV_PY)
    scope_dir = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "security-agent-harness"
    scope_env = {"XDG_CONFIG_HOME": str(scope_dir.parent)}

    if not VENV_PY.exists():
        step("Creating the Python virtual environment (.venv)", [sys.executable, "-m", "venv", ".venv"])
    step("Installing the security harness", [py, "-m", "pip", "install", "-q", "-e", ".[dev]"])
    step("Creating the signing keypair (outside the repo)",
         [py, "-m", "scripts.gen_scope_keypair", "--skip-if-exists"], scope_env)
    step("Signing the lab scope", [py, "-m", "scripts.sign_lab_scope"], scope_env)

    step("Installing PHP packages", [tool("composer"), "install", "--no-interaction"])
    env_file = ROOT / ".env"
    if not env_file.exists():
        shutil.copy(ROOT / ".env.example", env_file)
        print("\n==> Created .env from .env.example")
    step("Generating the app key", ["php", "artisan", "key:generate", "--force"])
    ensure_ca_bundle()
    step("Creating the database and demo accounts", ["php", "artisan", "migrate:fresh", "--seed", "--force"])
    step("Installing frontend packages", [tool("npm"), "install", "--no-audit", "--no-fund"])
    step("Building the frontend", [tool("npm"), "run", "build"])
    step("Clearing caches", ["php", "artisan", "optimize:clear"])

    env_text = env_file.read_text(encoding="utf-8")
    has_key = re.search(r"^LLM_API_KEY=\S+", env_text, re.M) is not None
    print("\n" + "=" * 60)
    print("Setup finished.\n")
    if not has_key:
        print("LAST STEP: open .env and set LLM_API_KEY (and LLM_BASE_URL / LLM_MODEL if you do not use the ITS")
        print("gateway; .env.example shows a free Groq alternative). Ask your team for the shared key.\n")
    print("Start the app:   php artisan serve")
    print("Open:            http://127.0.0.1:8000   (login: test@example.com / password)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="only diagnose; change nothing")
    args = parser.parse_args()

    check()
    if problems:
        sys.exit("\nFix the [FAIL] items above, open a NEW terminal, and run this script again.")
    if args.check:
        print("\nEverything needed is present.")
        return
    setup()


if __name__ == "__main__":
    main()
