# 10 — What is agentic in AEGIS (for the lecturer)

An *agent* here means a system where a language model, not a fixed script, chooses what to do next
toward a goal, acts on the world through tools, observes the result, and repeats until it can
answer. Everything below can be checked in the code and seen in the UI.

## 1. Autonomy: the model chooses the tools and the order

`App\Agent\AgentRunner::respond()` runs the loop *question → model → tool calls → results → model …
→ answer*. Nothing in PHP decides that a CVE lookup follows a scan; the model decides after reading
the scan result. "Is lab-web-01 safe?" usually becomes `run_investigation` then `lookup_cve` on the
worst flaw, but a different question produces a different chain (`list_investigations`,
`get_investigation`, `search_cves`, or no tool at all).
*In the UI:* each reply shows the route the agent took, one stop per tool call.

## 2. Goal-directed behaviour without a question

The **Run a full check-up** button (`ChatSessionController::checkup`) gives the agent only a goal:
check everything in scope and brief me. The agent works out which machines and log sources exist
(from the signed scope in its system prompt), investigates each, looks up the worst flaws and writes
the briefing. No human chooses a target.

## 3. Visible planning and reasons

Before each tool call the model writes one plain sentence saying what it is about to do and why
(`SystemPrompt`). `AgentRunner` stores it as `tool_execution_logs.rationale`, and the route shows it
under the step. Where a model leaves it out, `Plain::toolReason()` supplies a fixed explanation so the
UI never shows an unexplained action.

## 4. Tools that act on the world

| Tool | Acts on | Kind |
|---|---|---|
| `run_investigation` | the lab (port scan, log analysis, entry-point analysis) via the Python harness | action |
| `lookup_cve`, `search_cves` | the public NIST NVD database (with CISA "exploited in the wild" flag) | external knowledge |
| `list_investigations`, `get_investigation` | the archive of past runs | memory |

Adding a tool is one `AgentTool` class and one line in `AppServiceProvider`.

## 5. Memory

* Short term: the last `AGENT_HISTORY_MESSAGES` messages, with a one-line note of which tools and run
  ids each earlier answer used, so "tell me more about that Tomcat issue" reuses the run instead of
  scanning again.
* Long term: every investigation is stored on disk (`storage/app/harness-runs`). The agent is told to
  check `list_investigations` before repeating a scan, and the home page summarises the newest runs.

## 6. Error recovery and bounded autonomy

* A failing or refused tool call is returned to the model as data (`{"error": …}`), so it can correct
  itself, for example by choosing an in-scope target.
* If the harness' LLM planner cannot produce a valid plan, the run is repeated with the scripted
  planner and the result says so (`planner_note`).
* The loop has a hard step limit; when it is reached the model must answer from what it has.
* HTTP 429 rate limits are waited out and retried (`LlmClient`).

## 7. Guardrails: the agent is autonomous *inside* a fence

* The model never supplies a host, port or path. It picks a scope **alias**; Laravel rejects anything
  outside the Ed25519-signed scope before a process starts, and the harness verifies the signature
  itself. The home page shows the allowed aliases and how many calls were stopped.
* Output from scanned machines is untrusted. The lab's own banner contains "ignore previous
  instructions"; the harness records it as a finding and the system prompt forbids acting on it.
* Inside the harness the model proposes what information is needed next, and a deterministic
  necessity gate and policy engine decide whether it is allowed (docs 00–08).

## 8. The agent proposes what to do next

Each answer ends with up to three follow-up actions the agent suggests (`[[next: …]]`, parsed in
`AgentRunner::extractSuggestions`). They appear as buttons under the newest answer.

## 9. Interaction styles

Four agent modes change the strategy, not only the tone: act on its own, teach as it goes, triage
what is urgent, or audit conservatively (`SystemPrompt::MODES`).

## Limits, stated honestly

* The agent reacts to a request; it does not run on a schedule or watch the lab by itself. A
  `php artisan schedule:run` job that triggers the check-up would be the next step.
* One agent, one loop. There is no separate planner/critic agent and no self-verification pass
  beyond the grounding rules in the system prompt.
* Small models sometimes skip the one-sentence plan or the follow-up lines; the UI degrades
  gracefully in both cases.
