# Rules of engagement

Fill this in before the first request. If a line cannot be filled, that line is why the
run is not authorised yet. Keep the filled copy at `scope/ROE.local.md` — it is
gitignored with the rest of `scope/scope.yaml`.

## 1. Authority

- Program / client: 
- Platform and policy URL: 
- Written authorisation on file (where): 
- Authorised researcher identity (platform handle, account): 
- Engagement window (from / to, timezone): 

An authorisation that cannot be produced on request is not an authorisation. Screenshot
the program brief the day you start; briefs change and the version you read is your
defence.

## 2. Scope, exactly as written

- In-scope hosts / wildcards (copy verbatim, do not "clean up"):
- Explicitly out of scope:
- Third-party services in the path (payment processors, CDNs, email vendors) — **not in
  scope unless named**:
- Mobile apps / APIs / hostnames discovered later: in or out?

Anything not named is out. "The program probably means the whole domain" is how accounts
get banned.

## 3. Permitted techniques

| Technique | Allowed | Notes |
|---|---|---|
| Authentication / authorisation testing | | |
| Injection (SQLi, NoSQL, SSTI, XXE, cmdi) | | |
| Stored / reflected XSS | | |
| SSRF (incl. internal hosts) | | |
| File upload | | |
| Rate-limit / race conditions | | |
| Subdomain takeover | | |
| Social engineering / phishing | almost always no | |
| Denial of service / stress testing | almost always no | |
| Physical | no | |
| Automated scanning | | volume caps? |

## 4. Data handling

- Real user data: do not access, do not download, do not screenshot. If a response
  contains another user's PII, stop, record the minimum needed to prove the bug, and
  report the exposure without keeping the data.
- Credentials found in scope: report, do not use, do not store.
- Retention: delete raw captures after the report is triaged unless the program requires
  them retained. Note the date you will delete.
- Encryption at rest for the evidence directory: 

## 5. Rate and volume

- Requests per second, per host: 
- Maximum requests per host per session: 
- Testing window (business hours only?): 
- Stop condition: if a target returns 5xx at a sustained rate, stop and reassess — that is
  the point where "testing" becomes "breaking".

## 6. Escalation

- If you find evidence of an active breach: stop testing, preserve evidence, notify
  <contact> immediately. Do not investigate further; you are a witness, not an incident
  responder.
- If you knock something over: stop, notify, do not attempt to restore state yourself.
- Emergency contact and channel: 

## 7. Disclosure

- Report channel (platform / email / PGP): 
- Embargo terms: 
- Permission to publish a write-up after fix: 
- What may never be published: 

## 8. Agent-specific addendum

Because a model is sending some of these requests:

- The scope file is the only source of scope; it is written by a human from §2 above.
- `--allow-writes` is granted per session, not permanently.
- Every session's transcript is kept at `state/transcript.jsonl` and reviewed by a human
  before any report is filed.
- A model refusal is not a verdict. If the harness blocked a test, the class is
  `deferred(harness)`, not `clean`.
