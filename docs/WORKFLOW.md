# The hunting loop

How an agent-driven session actually runs, and where it earns its keep.

## Stage 0 — boot

```bash
.venv/bin/python scripts/smoke.py                 # Burp reachable, tools listed
.venv/bin/python -m agent.loop --dry-run          # scope parsed, tools known
```

If smoke fails, stop. A half-wired Burp shows up later as "the endpoint returned
nothing", and you will believe it.

## Stage 1 — surface

Feed the agent proxy history, not a wish. The objective names one endpoint family:

> `map the request/response shape of /open-widget/{id}: fields accepted, fields echoed,
> fields signed, and any field the server returns but never reads.`

The output you want is a table, not prose:

| field | accepted | echoed | signed | validated |
|---|---|---|---|---|
| `target.address` | yes | yes | yes | no |

That table is the bug surface. A field that is accepted, signed, and unvalidated is a
hypothesis with a shape.

## Stage 2 — one invariant, one request

Pick the invariant the product implies:

- "A checkout token describes a checkout the merchant configured."
- "An object at `/api/users/{id}` belongs to the session's user."
- "The price is computed from the catalogue, not from the request."

Then ask the question that breaks it: *who trusts this value, and does the trust survive
the value changing?*

One request. Not a fuzz sweep. If it does not prove the invariant is unenforced, the
hypothesis is dead and you write that down.

## Stage 3 — the gap that matters

The highest-yield pattern in practice is not the parameter, it is the **trust boundary
between two systems**:

```
client ──► endpoint A ──signs──► token ──► system B trusts token
```

If A will sign whatever it is handed, B's trust in the signature is misplaced, because
the signature attests *issuer*, not *requester*. No injection, no payload — just two
systems disagreeing about what a signature means. Models are unusually good at spotting
this shape, because it is a consistency question rather than a payload question.

Same shape, other clothes:

- client sends `role: "user"` → server writes it → admin panel trusts the row.
- client sends `amount` → gateway signs it → settlement trusts the signed amount.
- client sends `redirect` → token embeds it → browser follows it with the victim's cookies.

## Stage 4 — observe, then write

```jsonc
// state/transcript.jsonl — one line per gate decision and per request
{"ts":"…","kind":"scope","tool":"http_request","method":"POST","url":"https://…","allowed":true,"rule":"allowed"}
{"ts":"…","kind":"http","url":"https://…","ok":true,"response":"HTTP/1.1 200 OK…"}
```

`record_finding` turns a captured pair into `state/findings/<slug>.md` plus raw
`-request.http`, `-response.http` and `-meta.json` with sha256 of both. A triager can
replay the request and verify the bytes; that is the standard the bundle is built to.

## Stage 5 — the part the agent cannot do

Call severity, and decide what you did **not** test.

- Score with a CVSS calculator, not with the model's enthusiasm. `AV:N/AC:L/PR:N/UI:R`
  versus `UI:N` is often the difference between 8.1 and 9.1, and only you know whether a
  victim action is genuinely required.
- Write the "not tested" list: every class you skipped and why. `deferred(needs auth)`,
  `deferred(harness refused)`, `clean (n=3 payloads)` are all verdicts. Blank is not.
- Before filing, re-read your own report as the triager: does the observed impact match
  the severity claim, or is §12 describing a world you did not prove?

## Worked example (synthetic)

A payments widget exposes `POST /bootstrap/{id}` which mints a signed checkout token.

1. Surface: body accepts `destination`, `lockDestination`, `feePercent`, `redirect`.
   All five are echoed into the token. None are validated.
2. Invariant: *the token describes a checkout the merchant configured.*
3. One request sets `lockDestination: true`, a fresh destination, and `feePercent: 6`.
   Response 200 with a token signed by the platform's own key.
4. Read the token: every attacker field present verbatim, one constant `kid` across two
   mints — same key, different requester.
5. Finding: the mint authenticates nothing, and the signature covers data it should have
   derived. Severity depends on whether the destination is real money in production —
   say sandbox only, and say it in the report.

Steps 1–4 are agent work. Step 5 is yours.
