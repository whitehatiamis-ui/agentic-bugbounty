# Security policy

This is an offensive-security harness. It is meant to be pointed at systems you are
authorised to test, and it is built so that pointing it anywhere else fails closed.

## Using it

- Write `scope/scope.yaml` from a written authorisation you can produce on request.
- Run `--dry-run` first, every session. A malformed wildcard is a scope bug.
- Keep `state/` and `scope/scope.yaml` off any remote. They are gitignored; do not
  override that.

## Reporting a problem in this harness

If you find a way to make the guard allow an out-of-scope request, or to make the policy
module pass an irreversible action, that is the most important class of bug this project
can have. Open an issue with:

- the scope file used,
- the request that got through,
- which check should have caught it.

Please do not include a live credential or another party's data in the report.

## What is out of scope for this project

- DoS, mass scanning, and social engineering are excluded by design, not by configuration.
- The harness does not ship payloads. Bring your own, and bring authorisation with them.
