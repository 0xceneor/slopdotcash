# Project security vetting worker

PRD section 8 requires a scan of submitted project code for malicious
behavior before contributors install or run it: wallet drainers, password
and credential theft, secret exfiltration, harmful installation scripts and
agent prompt injection. The result binds the checked revision. A scan is not
a guarantee of safety, and an incomplete scan never establishes clearance.
Issues #909 and #911; audit findings 8 and 9.

## Bounded malicious-code scan

`bounded-scan.ts` implements the ordinary scan. It produces a
`slop-vetting-result-v2` result (`backend/vetting/scan-result.ts`). "Scan
passed" (`clean`) means exactly that these defined checks passed on every
defined surface of the exact assessed commit and skill template. It does not
mean the code is free of all malware.

| Surface | What it reads |
| --- | --- |
| `source` | Code and configuration files of the executable inventory |
| `manifests` | `package.json`, `pyproject.toml`, `Cargo.toml`, `go.mod` and similar |
| `dependencies` | Lockfiles; each lock digest is recorded |
| `installScripts` | Package lifecycle hooks, `setup.py`, `build.rs`, Makefiles, `.husky`, `.devcontainer`, `.vscode` tasks, install and bootstrap scripts |
| `downloads` | URLs that install-time content downloads, and committed binaries or archives |
| `agentInstructions` | `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, README, `SKILL.md`, Cursor, Claude, Copilot and similar rule files |

Each surface is checked for the five threats: `wallet-drainer`,
`credential-theft`, `secret-exfiltration`, `unsafe-execution` and
`prompt-injection`. The deterministic rules in `bounded-scan.ts` are
indicators, never confirmations. A match marks the check `flagged`.

The flow for one queued assessment:

1. `acquire.ts` and `queue.ts` fetch the exact queued commit and template
   inputs without execution. `readAcquiredSource` rereads every stored object
   by its SHA-256 and carries acquisition gaps (submodules, links, LFS) into
   the scan.
2. `inspectRepository` sorts files into surfaces and runs the checks. It is
   pure and deterministic. It builds one evidence bundle of at most 1 MiB and
   1,024 items. Content that does not fit, does not decode, exceeds 256 KiB or
   was not acquired is a visibility gap, never a silent skip.
3. `reviewScan` (`scanners.ts`, prompt `slop-scan-review-1`) runs one primary
   model review of that bundle. Its risk is read from the review itself: any
   suspected malice or high finding is `high`; any other finding or partial
   coverage is `ambiguous`; otherwise `low`. No score threshold is used.
4. A second model or specialist review runs only when the result is
   ambiguous or high risk: a non-low primary review, a flagged check, a
   medium or worse finding, or an unreleased binary or download.
   `composeScanResult` reports `needsSpecialist`.
5. `composeScanResult` derives the disposition. A separate trusted reviewer's
   confirmation makes it `malicious`; a model label never does. Otherwise it
   is `clean` only if the intake rules accept clean, and `incomplete` in every
   other case.
6. Retain the private report, inventory, dependency locks and every named
   artifact under the scan run in the restricted evidence store
   ([EVIDENCE.md](../../backend/vetting/EVIDENCE.md)), then publish once with
   `publishResult` ([PUBLICATION.md](PUBLICATION.md)).

### Cache and rescans

The inventory digest covers executable content only. Documentation that is
not an agent instruction file does not change it. A later commit whose
executable inventory, skill template and scan policy are byte-identical to a
clean scan reuses that result with `reuseCleanScan`; the intake checks that
the cited original is a clean, non-reused scan of the same repository,
inventory, template, policy, run and report. Any change to executable
content produces a new digest and a new scan.

The signed service calls `POST /api/v1/vetting/refresh` before reading the
queue. Slop then queues, for the project steward, a scan of every listed
project whose current content or live pin has no scan, and one fresh scan per
live pin for a project that contributor flags alone paused. Banned and
moderator-restricted projects wait for a moderator. An admin can still queue a
scan by hand.

### Isolated execution

Ordinary source needs no execution. When an install hook or download cannot
be judged from its bytes, an operator may retrieve it or run it in an isolated
runner and pass the retrieved bytes to `inspectRepository`, recording the run
in the result's `execution` field. The contract has no way to say that a
secret was provided: `secretsProvided` must be `false` and egress
`default-deny`. An unretrieved download keeps `downloads` partial, and an
unanalyzed binary stays quarantined, so the result stays incomplete until a
specialist or the isolated analysis releases it.

## Evidence

```sh
bun test scripts/vetting-bounded-scan.test.ts scripts/vetting-scan-flags.test.ts
```

The worker tests use harmless fixtures and a real local HTTP server that
answers in the Anthropic Messages format. They check surface coverage, threat
flags, gap handling, cache-digest stability, reuse refusal for changed
content, specialist escalation and composition into an accepted result. The
API workflow runs on the real migrations and handlers with an ephemeral
Ed25519 key and local workerd R2. It proves that a clean supported scan lets
activation proceed, reuse and automatic rescans, refusal without retained
evidence, and that incomplete results stay quarantined.

These tests do not prove a real provider review, the deployed scanner
service, an approved isolated runner or live acceptance. No real provider
call, key or project is used.

## Other components

These earlier components remain available. They are no longer a prerequisite
for an ordinary clean result:

- [Isolated artifact inventory](#isolated-artifact-inventory) (`artifacts.py`)
  for recursive archive inspection.
- [Offline VM evidence](VM.md), [assembly](ASSEMBLY.md),
  [dependencies](DEPENDENCIES.md), [provenance](PROVENANCE.md) and
  [events](EVENTS.md) for advanced detonation of risky artifacts.
- `slop-vetting-result-v1` secure-VM results keep their parser and rules.
  Old incomplete scans stay incomplete; nothing reinterprets them as clean.

### Isolated artifact inventory

`artifacts.py` inspects one supplied file recursively. It never executes or
releases input. Run it on an unprivileged, dedicated Linux analysis host with
Python 3.12 or later and Bubblewrap 0.9 or later:

```sh
python3 workers/vetting/artifacts.py /private/quarantine/object
python3 workers/vetting/artifacts_workflow_test.py
```

Treat stdout as private evidence. The launcher copies at most 32 MiB from a
regular file without following its final symlink, into separate user,
process, mount and network namespaces with no home mount, host network,
inherited environment or device passthrough. The parser reads ZIP and TAR
members in memory, rejects links, special files, encrypted members, duplicate
paths and traversal, and limits depth to 6, records to 1,024 and expanded
bytes to 64 MiB. Failure returns an `incomplete` result with no partial
inventory; every record stays `quarantined`. A host that blocks namespace
creation fails closed. A namespace isolates this parser; it is not a hardware
VM.

## Remaining work and operator decisions

| Item | Status |
| --- | --- |
| Scanner service deployment | Not deployed by this source. It needs its Ed25519 key, the public key in `VETTING_RESULT_PUBLIC_KEYS`, a provider profile and the evidence store policy. |
| Provider and model | Owner decision D16: Surplus `claude-opus-5.5` is the primary model and Surplus `gpt-6.1-sol` is the specialist, only for ambiguous or high-risk artifacts. The operator pins both in the provider profile; the source has no default. |
| Isolated runner | Owner decision D16: Cloudflare Sandboxes/Containers, one disposable sandbox per risky artifact, with `enableInternet: false` set explicitly and no secrets. Adapting this worker from the Bubblewrap host to that runner is follow-up work. |
| Specialist authority | Owner decision D3: moderators confirm malice and release quarantined artifacts. A model label alone cannot; a signed malicious result restricts the project until a moderator decides. |
| Live acceptance | Clean, incomplete, malicious, flag and reinstatement paths on staging with the real services. |
