# 00 — Vision and Scope

## 1. Problem

Security tooling is not missing tools. `nmap`, `tshark`, log parsers, SIEM queries,
and vulnerability databases all exist and are good. What is missing is
**orchestration and reasoning across them**: an analyst manually moves findings
between stages, translates output formats by hand, and rebuilds the same
correlation logic for every investigation.

Traditional automation solves this with a fixed pipeline: `scan → parse → report`.
That pipeline cannot adapt. If the scan reveals an unexpected service, the pipeline
has no way to decide "this deserves three more probes before I write the report".

## 2. What we are building

An **agentic security investigation harness**: an extensible runtime in which
capabilities are registered declaratively and an LLM plans the investigation.

```
Objective  →  Reason  →  Investigate  →  Discover  →  Adapt  →  Correlate  →  Report
```

versus the fixed pipeline:

```
Scan  →  Parse  →  Report
```

The port scanner and log analyser are **the first two skills on the harness**, not
the product itself. That distinction is the project's story: the deliverable is the
runtime, and the security capabilities are evidence that the runtime generalises.

## 3. Framing the project for a report

| Framing | Verdict |
|---|---|
| "An AI port scanner" | Weak. Reads as a thin LLM wrapper. |
| "An extensible agentic harness for security investigation, demonstrated through network scanning and log analysis" | Strong. The runtime is the contribution; the skills are the proof. |

## 4. Skills in scope

| Skill | Objective | Status |
|---|---|---|
| `port_scan` | Enumerate exposed services on authorised targets, map to candidate vulnerabilities | Milestone 1 |
| `log_analysis` | Detect suspicious authentication and HTTP activity in a log corpus | Milestone 2 |
| `entry_point` | Correlate scan + log evidence into a supported attack-entry-point hypothesis | Milestone 3 |
| `pcap_analysis`, `ioc_hunt`, `config_audit` | — | Out of scope; future work only |

The third skill is deliberately chosen because it is **cross-source**: it can only
succeed if artifacts, findings, and the event log are modelled properly. It is the
strongest single demonstration that this is a harness and not a script.

## 5. Non-goals

- **No scanning of systems we do not own.** The harness only runs against the local
  lab defined in `lab/`. There is no public-internet target support.
- **No exploitation.** No metasploit, no payload delivery, no credential
  brute-forcing beyond a seeded weak-credential check. Findings are *candidates*
  with a stated confidence basis, never demonstrated compromise.
- **No autonomous remediation.** The harness reports; it does not patch, block, or
  reconfigure anything.
- **No SIEM or production-network integration.**
- **Not a general chat assistant.** Interactions are scoped to an investigation run
  with a lifecycle.

## 6. Success criteria

The project is successful if a grader can observe all of the following:

1. **End-to-end run.** One command takes an objective and a target and produces a
   report with findings, reproducibly.
2. **Every finding is verifiable.** Each finding cites an artifact and a byte range;
   opening that range shows the raw evidence. No finding lacks a citation.
3. **Zero fabricated vulnerabilities in the evaluation corpus.** Measured, not
   asserted — see the hallucination-rate metric in 07.
4. **Out-of-scope action is blocked, visibly.** A seeded prompt injection in
   attacker-controlled log content attempts to expand scope; the run shows the
   denial in the event log and continues.
5. **Extensibility is demonstrated, not claimed.** Adding the third skill requires
   zero changes to runtime, policy, event, artifact, or report code — shown as a
   diff of added files only.
6. **Replay.** A recorded run can be re-executed deterministically and produce the
   same findings.

## 7. Vocabulary

Precise terms matter, because the original design blurred them.

| Term | Meaning |
|---|---|
| **Harness** | The whole platform: runtime, policy, tools, artifacts, reporting |
| **Runtime** | The orchestration engine that owns the run lifecycle and state |
| **Agent** | The reasoning policy: propose-next-action, given state |
| **Skill** | A declarative objective: required inputs, allowed capabilities, output shape |
| **Tool** | An atomic, typed, side-effecting action with a declared risk class |
| **MCP** | A protocol/provider for tools the harness did not write |
| **Artifact** | Immutable raw output, content-addressed and hashed |
| **Finding** | An interpreted, evidence-bound claim produced from artifacts |
| **Evidence** | A byte range inside a named artifact, with a hash |
| **Policy** | The component that converts an action request into allow / ask / deny |
| **Run** | One investigation: objective + scope + budget + event log |

## 8. Constraints

- Solo implementer, approximately one semester.
- All targets local, containerised, and self-owned.
- Commodity LLM API budget — cost per investigation is a tracked metric, so the
  design must avoid pathologically large prompts.
- Graded on demonstrable, verifiable behaviour rather than architectural ambition.

That last constraint is why this plan repeatedly prefers *fewer, provable components*
over a complete conceptual taxonomy.

