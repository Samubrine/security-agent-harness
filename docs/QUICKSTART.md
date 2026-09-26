# Quick start

The Security Agent Harness is a **command-line application**. It is not a desktop GUI and it is
not an interactive full-screen TUI: each `harness` command performs an operation, prints a
Rich-formatted result, and exits. Investigation records and reports are written to disk so they can
be audited or replayed later.

## 1. Install the command

Python 3.12 or newer is required. Download the `.whl` file for the desired version from
[GitHub Releases](https://github.com/Samubrine/security-agent-harness/releases), then install it
with `pipx`:

```bash
pipx install ./security_agent_harness-<version>-py3-none-any.whl
harness --help
harness doctor
```

The same wheel is tested on Linux, macOS and Windows before it is published. If `pipx` is not
available, activate a Python virtual environment and use `python -m pip install <wheel-file>`.

The installed command is suitable for working with your own signed scope records and providers.
The repository's sample lab, evaluation scenarios and fixture data are development assets and are
not included in the wheel.

## 2. Run the bundled safe demo

The quickest complete investigation uses the source checkout. Its default planner and fixture-backed
providers need no model server, scanner, Docker daemon or network access.

```bash
git clone https://github.com/Samubrine/security-agent-harness.git
cd security-agent-harness
python -m venv .venv
```

Activate the environment:

### Linux or macOS

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the project and create the local authorization material:

```bash
python -m pip install -e ".[dev]"
python -m scripts.gen_scope_keypair --skip-if-exists
python -m scripts.sign_lab_scope
```

The private signing key is deliberately stored outside the repository under
`~/.config/security-agent-harness`. Keep it private: possession of this key grants the ability to
authorize targets.

Run a deterministic investigation from the repository root.

### Linux or macOS

```bash
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/security-agent-harness"
harness run \
  --skill port_scan \
  --objective "Enumerate the services on lab-web-01 and identify version-level weaknesses." \
  --target lab-web-01 \
  --scope "$CONFIG_DIR/lab_scope.signed.json" \
  --public-key "$CONFIG_DIR/scope_ed25519_public.pem" \
  --out runs/quickstart
```

### Windows PowerShell

```powershell
$configDir = Join-Path $HOME ".config\security-agent-harness"
harness run `
  --skill port_scan `
  --objective "Enumerate the services on lab-web-01 and identify version-level weaknesses." `
  --target lab-web-01 `
  --scope (Join-Path $configDir "lab_scope.signed.json") `
  --public-key (Join-Path $configDir "scope_ed25519_public.pem") `
  --out "runs/quickstart"
```

## 3. Inspect and replay the result

Open `runs/quickstart/report.md` for the human-readable report. The same directory contains the
structured findings, evidence, event chain and run manifest.

```bash
harness verify runs/quickstart
harness replay runs/quickstart
```

`verify` audits the run's references and provenance. `replay` reconstructs its result without
calling a model or touching a target.

## Optional components

- `nmap` enables live native service enumeration. Without it, the demo uses recorded fixtures.
- Docker is only required for the isolated development lab described in `lab/README.md`.
- A local Ollama or OpenAI-compatible endpoint is only required when replacing the deterministic
  scripted planner with a model.

Only investigate systems you own or have explicit authorization to test. Scope signatures are an
enforced runtime boundary, not a substitute for legal authorization.
