# v1.1 Implementation Audit

Audited commit: `3243b6de0f4a8bfff681d21af4e5314b925968a1` (working tree clean at the time of the
probes below except for this document).

```text
.venv/bin/python -m pytest -p no:cacheprovider
595 passed in 4.19s
```

The full evaluation pipeline was also run (`make eval`, three scenarios through the real CLI). The
headline line it prints for each scenario, quoted verbatim:

```text
| replay_fidelity              | 1.000 | >=1.0 | pass   | findings=5; matching=f-05273e3462a3,...; mismatched=- |
| memory_persistence           | 1.000 | report | report | promoted=4; attributed=mem-7de5aa525bc5,...; unattributed=-; run_id=eval-port-scan-01 |
| memory_evidence_isolation    | 1.000 | >=1.0 | pass   | findings=5; offending=- |
| memory_retrieval_cost        | 3903.000 | report | report | unit=tokens; memory_tokens=3903; retrieved_entries=18; turns_measured=3 |
```

`replay_fidelity` was `not_measured` for every scenario before this work; it is now measured and
passing. `memory_retrieval_cost` is a token figure because the run measured it, and the unit is named
in the inputs rather than assumed, because a v1 run can only supply an entry count.

Running it also produced finding 7h below, which is the strongest argument for running a pipeline
end to end rather than trusting a unit suite.

## Who performed this audit, and why that matters

This audit was **not written by an independent reviewer.** The plan was to delegate it to a
separate agent with a read-only scope, and that agent was spawned twice. Both attempts failed
before producing anything, with the same error:

```text
{"status":{"errored":"exceeded retry limit, last status: 429 Too Many Requests"}}
{"status":{"errored":"exceeded retry limit, last status: 429 Too Many Requests"}}
```

The spawn channel was rate-limited, not the task, so the work was done here instead. The probes
below are real and their raw output is quoted, but the *judgement* about what they show is the same
judgement that wrote the code. Where that is a weakness it is called out rather than papered over,
and section 8 lists the places where a reader should trust a second pair of eyes over this one.

Audited against the gap list in `docs/dev/AUDIT.md` section 6 and the contract in
`docs/dev/INTERFACES.md` section 6.

## 1. Invariant 6 - a cited decision id resolves

Verdict: **HOLDS**, with a caveat for v1 directories.

Probe: audit the committed run, then fabricate a policy decision id on one execution and re-audit.

```text
=== PROBE 1: invariant 6 ===
committed v1 run -> ok: True codes: ['grants_record_absent', 'policy_decision_record_absent'] checked.gr 0
  policy ids derived from provenance: 10
fabricated policy id -> ok: False codes: ['execution_policy_decision_missing', 'grants_record_absent', 'policy_decision_record_absent']
```

What was tried in order to break it: the fabricated id is caught, and the check is not merely a
presence test - it resolves the id against the run's own records. The tampered case also shows the
check still works when the strong source is missing: `policy-decisions.jsonl` does not exist in a
v1 directory, so the verifier recovers 10 policy ids from `provenance.jsonl` `governed_by` triples
and says so with `policy_decision_record_absent` (a warning, not an error) rather than silently
checking nothing.

Caveat: on a v1 directory the ids come from the provenance triples written by the same component
that wrote the execution, so the check is weaker there than on a v1.1 run, where
`policy-decisions.jsonl` is authoritative. `tests/test_integration_v11.py` asserts that a v1.1 run
does **not** produce that warning.

## 2. Invariant 12 - provider-side egress

Verdict: **HOLDS** for provider egress. The content-side filter is a separate finding - see 7d.

```text
=== PROBE 2: invariant 12 ===
self-declared-local + public endpoint: False
local subprocess, declared egress=True : True mismatch: False
no endpoint, no egress               : False
egress.py mentions socket/getaddrinfo: False
```

The original audit's objection was that a provider declaring `requires_network_egress=False` was
believed. The first line is that exact case and it is now refused: the endpoint decides, not the
declaration. The second line is the correction that took two attempts - nmap declares
`requires_network_egress=True` while running wholly as a local process, because it sends packets at
a target rather than calling a remote service, so under local execution there is deliberately no
`declaration_mismatch` and no false alarm on every nmap run. The third line is the fail-closed
direction: an endpoint the harness cannot classify is not treated as local.

No name resolution happens. `tests/test_policy_egress.py` pins the permission table itself,
including that `unknown` with egress disabled is refused and that `local_subprocess=True` is
permitted even with egress disabled.

## 3. Conflict-driven re-planning

Verdict: the mechanism **HOLDS**; the claim that a real run cannot reach it **HOLDS**.

Probe on a real CLI run:

```text
=== PROBE 3: conflict reachability on a REAL run ===
correlations.jsonl present: False | rows: None
follow-ups.jsonl present   : False | rows: None
executions by capability   : [('service.enumerate', 'native:synthetic'), ('vulnerability.match', 'native:cve_matcher')]
```

No correlations at all, and exactly one provider per capability. That is the sub-claim in
`tests/test_integration_v11.py::test_with_the_shipped_planner_no_conflict_is_reachable`, and it
survives: a conflict needs two providers observing one subject, and the scripted planner re-requests
a capability only after a *failed* attempt - a successful one is recorded as completed and skipped.
The two paths that select two providers are `conflict_resolution` (needs a conflict to exist first)
and `trust_diversity` (never requested by the loop), and the retry path returns verdict `single`
with one provider, so it never iterates twice either.

So the wiring is real, tested, and **currently exercises nothing in production**. That is reported
here and in `IMPLEMENTATION.md` rather than left for a reader to discover.

## 4. Replay fidelity, and the trace it must not destroy

Verdict: **HOLDS**.

```text
=== PROBE 4: replay split ===
replayed digests: 5 | match: True
replay.json sha256 before: 88a22e753eb96b76e160b3856cf25159b8d22f53593bfe6ab0e8e8cb2f053602
replay.json sha256 after : 88a22e753eb96b76e160b3856cf25159b8d22f53593bfe6ab0e8e8cb2f053602
replay.json UNCHANGED: yes
replay-report.json exists: yes
offline replay still works:
  error-ish lines: 0
replay_fidelity: measured 1.0
after tampering one claim: measured 0.8
```

The byte-identical hash is the point: an earlier version of this pass wrote its digest document into
`replay.json`, which is the JSONL model/provider trace `ReplayModelClient.from_path` reads, and
that turned every subsequent offline replay into a `JSONDecodeError`. The report now has its own
file. The last two lines are the measurement: 5 of 5 digests match on a clean run, and 4 of 5 match
(0.8) once one recorded claim statement is tampered with. A metric that cannot fail is not a metric.

## 5. The three memory metrics

Verdict: **HOLDS**.

```text
=== PROBE 5: memory metrics ===
memory_evidence_isolation    empty bundle -> not_measured
memory_persistence           empty bundle -> not_measured
memory_retrieval_cost        empty bundle -> not_measured
isolation with one memory-citing claim: 0.5 {'f-2': ['mem-deadbeef']}
persistence with one mis-attributed promotion: 0.5 unattributed: ["mem-b cites run 'run-OTHER', not 'run-1'"]
```

All three return `not_measured` rather than a flattering number when their input is absent, which is
the property that matters most: a run that did not exercise memory is a different fact from a run
that used it badly, and only the second is a finding. Both negative cases move the metric, and
`memory_persistence` treats a promotion naming a *different* run as worse than an unattributed one,
because it is a durable claim about an investigation that did not produce it.

## 6. The FSM change

Verdict: **HOLDS**, with a residual risk noted.

```text
tests/test_integration_v11.py::test_a_conflict_schedules_its_own_resolving_call PASSED
  -> decision verdict=expand expansion_reason=conflict_resolution, len(selected) >= 2,
     both providers executed without an illegal-transition assertion
```

The claim under test is that `_pursue` iterates every provider a decision selected while
`_run_provider` leaves the machine at `FINDINGS`, and that `FINDINGS -> POLICY` was not legal, so
the second provider asserted `illegal transition findings -> policy`. That is why the transition was
added. It had never fired because neither two-provider path had ever executed.

Residual risk, stated plainly: widening a transition table is exactly the kind of change that can
mask a real sequencing bug. The justification is narrow - the transition is only reachable from
`_pursue`'s loop, and necessity has already been decided for that selection so re-deriving it per
provider would be wrong - but a reviewer who distrusts this change is not being paranoid, and the
alternative (walking `FINDINGS -> PLANNING -> VALIDATING -> NECESSITY`) would be more honest about
the machine's shape.

## 7. Claims that exceed what the code delivers, ranked by cost to close

**a. A remote-inference run sends unfiltered context.** `policy/egress.py` provides
`classify_prompt_content` and `redact_for_egress`, and `tests/test_policy_egress.py` covers them
thoroughly - including that a sha256 digest, a `mem-` reference, a `run-` id and `MEMORY.md` are all
recognised. Nothing calls either function:

```text
classify_prompt_content    non-test call sites: 1
       src/harness/policy/egress.py:22: (module docstring)
audit_run_dir              non-test call sites: 3
       src/harness/runtime/verify.py:17,47,320 (definition, __all__, docstring)
trust_diversity_required   non-test call sites: 0
```

So provider-side egress is enforced and prompt-side egress is *available*. Cost to close: moderate,
and the change is not mechanical - deciding what to redact or refuse before a remote call needs a
policy decision about which context tiers may leave, not just a call to an existing helper.
**This is the highest-cost gap because the prose around "egress" invites a reader to assume the
content side is covered.**

**b. `audit_run_dir` is not on any operator path.** The checker that closes invariant 6 is reachable
only from tests. `harness replay` verifies the event chain and evidence spans but does not call it,
so no command tells an operator that a run cites a decision, grant or observation that does not
exist. Cost to close: low - a flag on `harness replay`, or a new subcommand.

**c. Conflict re-planning cannot be reached by a real run.** Section 3. Cost to close: moderate, and
it is a design decision rather than a bug fix - the loop would have to honour
`SkillSpec.verification` / `trust_diversity_required`, which changes what a run does by default and
would move every evaluation number.

**d. `independent_verification` is unreachable.** The gate supports `trust_diversity_required` and
design 08 lists the reason, but no non-test call site sets the flag, so no skill can ask for its
conclusion to rest on two sources. Cost to close: low, and it is the same change as (c).

**e. `memory_persistence` measures attribution, not the byte cap.** It answers "does every promoted
entry name its run" and not "did `MEMORY.md` end under its cap", because the active file lives in
the workspace rather than the run directory. The cap is still enforced and tested by
`MemoryManager`; what is missing is the measurement. Cost to close: low.

**f. Committed run directories cannot have their grant references checked.** They predate
`grants.json`, so the verifier reports `grants_record_absent` and `checked["grants"] == 0`. This is
the honest behaviour and it is tested, but it means the grant half of the reference graph is
verifiable only for runs made after this change. Cost to close: low - regenerate
`eval/results/*/run` (which requires the signing key on the machine doing it).

**g. The verifier's own docstring overstates one thing.** `_load_grants` originally claimed an
unreadable scope "is reported, not assumed empty" while returning an empty list in silence. That was
fixed, and the fix is why `grants_record_absent` exists - but it is worth recording that the claim
had been wrong in exactly the direction an audit should catch: the code reported success over no
data.

**h. The suite's green result was not reproducible from the repository. FOUND AND FIXED.** Two test
files read their fixture run directory from `eval/results/port_scan/run`, which is **gitignored**:
it is the local output of `make eval`, not tracked content. On a fresh clone the directory does not
exist, so those tests would have errored - and, worse, they would have passed on the machine that
generated it, giving a green suite that proved nothing about the repository. Running `make eval`
exposed it, because regenerating the run changed every random id the tests pinned.

Fixed by freezing a recorded run under `tests/fixtures/run/port_scan` (a tracked path) and pointing
both files at it through a session fixture. Verified the only way that means anything: with
`eval/results/` moved out of the tree entirely, `pytest` reports **595 passed**. Cost to close was
low; the cost of not noticing was an unbounded amount of false confidence.

Residual brittleness, stated rather than hidden: those tests pin ids that come from `new_id`, so
regenerating the frozen fixture requires updating the constants. `test_recorded_run_is_the_fixture`
fails loudly when they drift, which is how this was caught - but a fixture whose ids cannot be
recomputed is a fixture that must not be casually regenerated.

## 8. What was not tested, and why

- **A live lab run and a real `nmap` scan.** `nmap` is not installed here and no container was
  started. The adapter's degradation path is tested; a genuine scan was not performed. Unchanged
  from the first audit.
- **A third-party MCP server.** The client is exercised over a real pipe against a hand-written
  server, including a misbehaving one. No external implementation was available.
- **The adversarial quality of the 89 egress tests.** They were read and spot-checked, and their
  count is reported, but each was not independently re-derived.
- **Whether `FINDINGS -> POLICY` can mask a loop bug elsewhere.** Section 6 states the residual
  risk; establishing the negative would need a much wider search than this audit performed.
- **This audit's own independence.** It has none. See the header.
