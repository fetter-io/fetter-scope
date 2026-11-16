# monitor-diff event streams

Recorded from fetter 5.0.0 (`fetter-scope install-fetter`, from crates.io) running

```
fetter -E npm --root <proj> --cache-directory <tmp> -q monitor-diff \
    --period 600 --report-period 600 [--report always] --control stdin json
```

over a scratch npm project (`package.json` and `package-lock.json`), with every scan after the first
driven by control commands so the streams are deterministic. The username and hostname were then
replaced with `user` and `host`, and the project path with `/home/user/proj`. Times are as recorded.
Vulnerability findings are OSV's at recording time.

- `quiet.jsonl` (`--report always`, an empty cache): `start` (rolling, no baseline yet); the `start`
  scan; a `report` that establishes the baseline, whose `new_vulns` have source `existing` (lodash
  4.17.21's advisories), so its status is `alert`; then `report` on the control channel: a `request`
  scan and an `unchanged` report. Exit 0 after `stop`.
- `changes.jsonl` (`--report change`, the cache from `quiet`): `start` with the rolling
  `baseline_time`; the `start` scan; the lockfile is edited (lodash 4.17.21 → 4.17.15, left-pad
  1.3.0 added); `scan`: a `request` scan with an `added` and a `downgraded` change; `report`: a
  `request` scan with no changes since the previous scan, then an `alert` report (the downgrade and
  the `introduced` vulnerabilities); then `bogus`: an `error` event `Unknown control command`.
  After `stop`, fetter exited with 3, since the last report was an alert (see SPEC: Process
  lifecycle).

Not covered by a recording: hooks (an npm lockfile has none), violations (no `--bound`), and
`audit_error`. Tests for those, and for unknown events, newer schemas, extra fields and non-JSON
lines, build their events inline.

To re-record, run fetter as above and repeat the replacements; check the result for the
username, hostname and local paths before committing.
