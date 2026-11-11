# agentic-bugbounty

A scope-locked harness that lets a language model drive real offensive-security tooling
through MCP — Burp Suite as the spine — without letting it wander off-scope.

Not a "hacking bot". The model is the reasoning layer; the enforcement is Python the
model cannot edit at runtime. Every request it sends has already passed a scope check, a
policy check, and a transcript write. When you read the transcript later, you can
reconstruct exactly why each request was allowed.

```
        objective
            │
            ▼
   ┌─────────────────┐   tool_use    ┌──────────────────────┐
   │   agent loop    │ ────────────► │  scope guard  (deny  │──refusal──┐
   │  (model, tools) │               │  by default)         │           │
   └─────────────────┘               │  policy       (deny  │           │
            ▲                        │  irreversible ops)   │           │
            │                        └──────────┬───────────┘           │
            │                                   │ allow                 │
            │                        ┌──────────▼───────────┐           │
            │                        │  Burp MCP :9876/mcp  │           │
            │                        │  27 tools            │           │
            │                        └──────────┬───────────┘           │
            │                                   │                       │
            │              ┌────────────────────┼────────────────────┐  │
            │              ▼                    ▼                    ▼  │
            │         send HTTP          proxy history        encode/decode
            │              │                    │                       │
            └──────────────┴──── transcript + evidence bundle ◄─────────┘
```

## What this is

A working pattern for agentic security testing, taken from a live bug-bounty workflow:

- **`scope/guard.py`** — fail-closed scope enforcement. Wildcards, exclusions, schemes,
  ports, methods, forbidden techniques, per-host rate limits and request caps. An empty
  allowlist refuses to start rather than defaulting to "everything".
- **`agent/policy.py`** — hard limits on irreversible actions (service shutdown, `DROP
  TABLE`, unbounded deletes, bulk messaging). It does **not** censor payloads: a
  `xp_cmdshell` probe is the job, a `TRUNCATE` is an incident.
- **`burp_mcp/client.py`** — dependency-free MCP client for the Burp extension over
  streamable HTTP, with the `/sse` vs `/mcp` trap documented where you will hit it.
- **`agent/loop.py`** — the loop, five tools, transcript logging, one gate in front of
  every call.
- **`evidence/capture.py`** — request/response bundles with sha256, scope decision, and
  redaction that keeps evidence linkable without keeping credentials usable.

## What this is not

- Not a scanner. It sends the requests a human decided were worth sending.
- Not autonomous on scope. It cannot expand its own boundary; the boundary is a file the
  operator writes.
- Not a substitute for a human calling severity. Models inflate; the report is yours.

## Quickstart

Requires Python 3.10+, Burp Suite with the **MCP Server** extension enabled, and a model
provider configured for the `anthropic` SDK.

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

cp scope/scope.example.yaml scope/scope.yaml   # fill from the program brief
.venv/bin/python -m agent.loop --scope scope/scope.yaml --dry-run
```

`--dry-run` prints the parsed scope and the tool set without touching a model or a
target. Run it every time, before every session — a typo'd wildcard is how you end up
testing a host you were not authorised to touch.

Then:

```bash
export AGENT_MODEL=<a model id your provider serves>
.venv/bin/python -m agent.loop \
  --scope scope/scope.yaml \
  --objective "map the unauthenticated surface of the widget bootstrap endpoint"
```

Add `--allow-writes` only when the brief covers state-changing tests, and
`--allow-risky` only for slow or high-volume work you have explicitly budgeted.

Check the Burp connection on its own:

```bash
.venv/bin/python scripts/smoke.py
```

```
server: {'name': 'burp-suite', 'version': '1.1.2'} protocol: 2025-06-18
tools: 27
history call ok: True | reply: Reached end of items
url_encode ok: True | a+b%26c
```

## The loop that actually finds bugs

1. **Map the surface.** Read proxy history and JS. Enumerate endpoints, then the fields
   each one accepts. The model is good at this — it does not get bored at endpoint 40.
2. **Pick one invariant per endpoint.** "This endpoint mints a signed token." "This
   object is addressed by an id the client chooses." "This amount is computed server-side."
3. **Ask who trusts what.** The bug is almost never the parameter; it is the downstream
   system that trusts it. A signature that attests *who issued* a token says nothing
   about *who asked for it*.
4. **Send the one request that proves the invariant is unenforced.** One request, one
   observation, one line in the transcript.
5. **Observe, do not infer.** If the harness refused, the test did not run. If the
   response was a 500 from a broken WAF, that is not a finding.
6. **Capture before you celebrate.** `record_finding` writes the exact bytes and hashes.
   Screenshots of terminals are not evidence.
7. **Name what you did not test.** An endpoint is finished when every applicable class has
   a verdict, including "clean" and "deferred, needs auth". Silence is not a verdict.

## What agents are genuinely good and bad at

Good:

- Breadth. Reading hundreds of history entries and surfacing the one endpoint whose
  response shape does not match its request.
- Consistency. Applying the same authorisation check to every sibling endpoint, every
  time, in the same order.
- Drafting. Turning a captured pair into a report skeleton with the right sections.
- Second-order reasoning. "This field is signed" → "who validates the signature" →
  "does the signature bind the *requester*".

Bad:

- Product judgement. Whether an endpoint is by design requires context the model does
  not have. Two of three findings in a recent run were "reassessed likely-by-design"
  after filing; a human caught that, not the agent.
- Severity honesty. Models trend upward. Score with a CVSS calculator and a human.
- Silence. A model that did not test something reports nothing, and nothing reads like
  "clean". Force an explicit verdict per class or you will ship blind spots.
- Sessions. MFA, phone callbacks, real user accounts — the parts of a target that need a
  human stay human.

## Hard limits, enforced in code

| Limit | Where | Behaviour |
|---|---|---|
| Off-scope host/scheme/port/method | `scope/guard.py` | refused before send, reason returned to the model |
| Empty allowlist | `scope/guard.py` | process refuses to start |
| Rate / per-host cap | `scope/guard.py` | token bucket, refusal names the limit |
| Service shutdown, `DROP`, unbounded delete | `agent/policy.py` | refused |
| State-changing request | `agent/policy.py` | refused unless `--allow-writes` |
| Slow / high-volume test | `agent/policy.py` | refused unless `--allow-risky` |
| Secrets in evidence | `evidence/capture.py` | redacted, hashes preserved |

No DoS. No social engineering. No real user data. No persistence. Program rules beat this
repo; the law beats program rules.

## Layout

```
scope/guard.py        fail-closed scope enforcement
scope/scope.example.yaml
agent/loop.py         model → gate → MCP → observation
agent/policy.py       irreversible-action limits
burp_mcp/client.py    MCP over streamable HTTP, stdlib only
evidence/capture.py   evidence bundles with hashes and redaction
tests/                31 tests, all of the guard's failure modes
scripts/smoke.py      prove Burp is wired up before you hunt
scripts/preflight.sh  refuse to push a repo with a secret in it
docs/AUTHORIZATION.md rules-of-engagement checklist
docs/WORKFLOW.md      the hunting loop, with a worked example
```

## Disclosure hygiene

This repo is meant to be publishable at any moment. That imposes two habits:

- `scope/scope.yaml` and `state/` are gitignored. A program brief is not yours to
  publish, and a transcript names hosts you were authorised to touch and nobody else was.
- Findings stay out of the repo until the program has fixed them or cleared disclosure.
  Put a live, unfiled vulnerability in a public README and you have published someone
  else's incident, not your research.

`scripts/preflight.sh` greps the staged tree for `ghp_`, `github_pat_`, `sk-`, `AKIA`,
PEM blocks and JWTs, and exits non-zero. Wire it as a pre-push hook:

```bash
ln -sf ../../scripts/preflight.sh .git/hooks/pre-push
```

## License

MIT — see `LICENSE`.
