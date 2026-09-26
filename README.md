# Agentic Security Investigation Harness

Final project (PBKK). A **local-first command-line application and agentic harness** where security
investigation capabilities are dropped in as *skills*, *native tools*, and *MCP providers*,
and a locally hosted LLM decides what to investigate next inside a deterministic, auditable
runtime.

This is a CLI, not a desktop GUI or an interactive full-screen TUI. Commands print formatted
status and write auditable run artifacts and reports to disk. New users should start with the
cross-platform [Quick start](docs/QUICKSTART.md).

> **The model decides what information it needs. The harness decides whether another tool call is necessary, which provider may satisfy it, and how it is allowed to happen.**

Status: **implemented**. The vertical slice runs end to end - local model, typed capability
proposal, necessity gate, policy, provider, artifact, parser, finding, report and replay - and the
evaluation harness scores real runs against ground truth. See
[docs/dev/IMPLEMENTATION.md](docs/dev/IMPLEMENTATION.md) for the map from design to code and
[docs/dev/AUDIT.md](docs/dev/AUDIT.md) for the first independent check of what the implementation
actually delivers. [docs/dev/AUDIT-v11.md](docs/dev/AUDIT-v11.md) audits the work that closed five
of the gaps that check named, and [docs/dev/IMPLEMENTATION.md](docs/dev/IMPLEMENTATION.md) lists
what is still absent - including the three items below that are wired but not yet reachable.
[docs/dev/AUDIT-v12.md](docs/dev/AUDIT-v12.md) re-verifies all of that against `1275c14` and adds a
second round of findings plus the implementation plan (`WS-01 … WS-11`) that closes them. Read it
before starting work on anything in this repository: it names, per task, which claims to re-verify
first.

```text
728 tests collected, 727 passing, 1 skipped on Linux / Python 3.14 (about 11s)
port_scan / log_analysis / injection_resistance / entry_point: every scenario passes its
precision, recall, hallucination, evidence-binding and scope-compliance targets
```

### v1.1: closing the audited gaps

Five of the eight gaps in the first audit's honesty section are closed. Each is enforced in code
and covered by a test that fails if the property is broken:

- **A cited decision id is now resolvable.** Policy decisions are persisted, and
  `harness.runtime.verify` re-derives a run's whole reference graph - executions, decisions,
  policy decisions, grants, observations, findings - and reports every broken reference instead of
  rendering a clean report over a dangling one.
- **Provider egress is decided by the harness, not the provider.** A provider is judged on how the
  harness reached it, never on what it claims about itself, and a refused provider stops the run
  rather than being silently dropped.
- **A conflict schedules its own resolving call** through the ordinary necessity and policy path,
  rather than waiting for the model to happen to ask again.
- **`replay_fidelity` is measured**, by re-deriving findings from a run's own recorded
  observations and comparing digests. Three memory metrics joined it.
- **Compression and memory-retrieval cost are recorded** per turn, so design 08's v2 Token
  Optimizer is an optimisation over measured traces rather than an architectural guess.

v1.2 closes the round-2 audit's Group A: an MCP server can no longer author a CVE finding, attacker
text in a prompt is delimited by a per-run nonce, committed evidence survives a checkout, and a run
that failed says so. The scope record now authorises ports, a run requires an operator trust anchor,
provider arguments are checked against the schema the adapter declares, and the skill settings that
were declared and unread are honoured or gone. Each change is recorded with the command that proves
it in [docs/dev/AUDIT-v12.md](docs/dev/AUDIT-v12.md).

One limit is worth knowing before reading a report as a guarantee: prompt-content egress filtering
exists and is tested but nothing calls it yet, so a run with remote inference enabled sends whatever
the context builder assembled - provider-side egress is enforced, prompt-side is not. v1.2 closed the
other two: a run whose skill asks for corroboration now reaches the gate's second-provider path
(`entry_point` does), and `harness verify <run-dir>` audits a run's reference graph from the command
line. The carried-forward defects, with their reasons, are listed in
[docs/dev/IMPLEMENTATION.md](docs/dev/IMPLEMENTATION.md).

## Running it

For a first installation and a complete deterministic investigation on Linux, macOS or Windows,
follow the [Quick start](docs/QUICKSTART.md). The shorter reference commands below assume the
repository development environment already exists.

### Install a release

The package supports Linux, macOS and Windows with Python 3.12 or newer. Download the `.whl`
file from the desired entry on the repository's [Releases](https://github.com/Samubrine/security-agent-harness/releases)
page, then install it with
[`pipx`](https://pipx.pypa.io/) so the `harness` command is available without changing the system
Python environment:

```bash
pipx install ./security_agent_harness-<version>-py3-none-any.whl
harness --help
harness doctor
```

`python -m pip install ./security_agent_harness-<version>-py3-none-any.whl` also works inside a
virtual environment. The wheel is platform-independent; the release workflow installs and checks
the exact same wheel on Linux, macOS and Windows before publishing it. `nmap` and Docker remain
optional and are only needed for their corresponding providers and local lab.

Maintainers publish a release by updating the version in `pyproject.toml` and
`src/harness/__init__.py`, then pushing the matching tag (for example, version `0.2.0` uses tag
`v0.2.0`). GitHub Actions runs the tests, builds the wheel and source archive, verifies installation
on all three operating systems, and attaches the distributions plus SHA-256 checksums to the GitHub
release.

### Run from a source checkout

The default planner is a deterministic local stand-in, so a full investigation runs on a machine
with no model server, no scanner and no network:

```bash
make install                 # create .venv and install the package + dev dependencies
make test                    # the whole suite (728 tests, no network)
make scope                   # generate a signing keypair and sign the lab scope record

# One investigation. Artifacts, events, findings and the report land in runs/<id>/.
make run SKILL=port_scan OBJECTIVE="Enumerate exposed services on lab-web-01."

# Or drive the CLI directly. The scope record is signed, and the run verifies it against the
# operator's public key: an unsigned record, or one checked only against the key it carries
# itself, is refused before the model is ever called (--dev-embedded-key opts into that
# development mode explicitly, and the report then says the authority was self-signed).
.venv/bin/harness run \
  --skill port_scan \
  --objective "Enumerate exposed services on lab-web-01." \
  --target lab-web-01 \
  --scope ~/.config/security-agent-harness/lab_scope.signed.json \
  --public-key ~/.config/security-agent-harness/scope_ed25519_public.pem

.venv/bin/harness replay runs/<run-id>     # re-derive it offline and verify its integrity
make eval                                  # run every scenario and print the metrics table
make doctor                                # report what this machine can and cannot do
```

To use a real local model instead of the scripted planner, point the harness at any loopback
endpoint. A non-loopback address is refused unless egress is explicitly enabled, and a remote run is
labelled as such in its manifest:

```bash
.venv/bin/harness run --model-backend ollama --model llama3 \
  --endpoint http://127.0.0.1:11434 --skill port_scan --objective "..." \
  --scope ~/.config/security-agent-harness/lab_scope.signed.json

.venv/bin/harness run --model-backend openai --model local-model \
  --endpoint http://127.0.0.1:8080/v1 --skill port_scan --objective "..." \
  --scope ~/.config/security-agent-harness/lab_scope.signed.json
```

`nmap` is optional: when the binary is absent the real scanner adapter records a coverage gap rather
than failing the run, and the deterministic fixture-backed provider answers the same capability.

## Design docs

| Doc | Contents |
|---|---|
| [00-vision-and-scope.md](docs/design/00-vision-and-scope.md) | Problem, framing, in-scope skills, non-goals, success criteria |
| [01-architecture.md](docs/design/01-architecture.md) | Deterministic spine, local model runtime, investigation loop, provider routing |
| [02-data-model.md](docs/design/02-data-model.md) | Artifacts, findings, evidence binding, event log, tool contracts |
| [03-policy-and-safety.md](docs/design/03-policy-and-safety.md) | Scope model, capability gates, approvals, prompt-injection defense |
| [04-prior-art.md](docs/design/04-prior-art.md) | Survey of existing agentic security projects and frameworks |
| [05-alternatives-considered.md](docs/design/05-alternatives-considered.md) | Competing architectures and why they were rejected or partially adopted |
| [06-implementation-roadmap.md](docs/design/06-implementation-roadmap.md) | Vertical slice, milestones, week-by-week plan |
| [07-evaluation-plan.md](docs/design/07-evaluation-plan.md) | Lab targets, ground truth, metrics, ablations, injections |
| [08-local-first-memory-and-routing.md](docs/design/08-local-first-memory-and-routing.md) | Local model contract, memory lifecycle, multi-provider necessity gate, v2 token optimizer |
| [decisions.md](docs/design/decisions.md) | ADR log — numbered decisions with status |

## Headline decisions

1. **Local-first model execution.** The default planner runs on a local inference endpoint.
   Remote model adapters are opt-in and may never receive evidence or memory implicitly.
2. **Deterministic spine, probabilistic brain.** The run is a state machine; the model
   proposes typed capability needs, while the harness owns execution, policy, budgets and state.
3. **Memory is context, never evidence.** `MEMORY.md` is bounded active memory; stable baseline
   memory and long-lived memory are stored separately. Findings still require artifact-backed
   evidence from the current investigation.
4. **Providers are selected by necessity.** A capability request is satisfied by the minimum
   sufficient set of native tools/MCP providers. Multiple providers require a recorded reason
   such as coverage, conflict resolution, independent verification, or failure fallback.
5. **Tool output never reaches the model wholesale.** Outputs become content-addressed
   artifacts; only deterministic rollups and bounded evidence spans enter context.
6. **Vulnerability mapping is deterministic.** CPE normalization plus offline version-range
   matching against snapshot-stamped vulnerability data decides candidate CVEs.
7. **Scope is structural.** Capability grants derive from an authorization record; out-of-scope
   destinations are unreachable, not merely discouraged.
8. **Every run is replayable.** Append-only, hash-chained events plus recorded model/provider
   responses reproduce structured state without re-touching the network.
9. **Token optimization is staged.** v1 uses hard budgets, fixed context tiers, caching and the
   provider necessity gate. A dynamic Token Optimizer is a version-two subsystem, not a v1
   dependency.

## Layout

```text
MEMORY.md                 bounded active working memory
memory/BASELINE.md        stable human-curated memory loaded every run
memory/long_term/         durable memory shards and the SQLite FTS5 index (local, gitignored)
docs/design/              the design plan
docs/dev/                 implementation notes, the interface contract, this project's audit
src/harness/
  runtime/                FSM, investigation loop, run assembly, replay and verification
  llm/                    local-first model clients, prompts, schemas, the scripted planner
  policy/                 signed scope, capability grants, allow/ask/deny engine, taint tracking
  providers/              capability registry, necessity gate, router, native and MCP adapters
  parsers/                deterministic readers for nmap XML, auth logs, access logs, MCP JSON
  analysers/              rule engine, offline CVE matching, cross-provider correlator
  findings/               finding construction and the provenance validator
  memory/                 baseline/active/long-lived memory, compaction, curation
  context/                tiered context assembly and spotlighting
  report/                 report rendering from a recorded run directory
  skills/                 declarative skills (port_scan, log_analysis, entry_point)
lab/                      docker-compose targets on an internal, egress-free network
eval/                     scenarios, ground truth, metrics, runner
scripts/                  scope keypair generation and signing
tests/                    unit, contract, scenario and end-to-end tests, plus fixtures
```
