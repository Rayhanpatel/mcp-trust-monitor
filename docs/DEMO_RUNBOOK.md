# Demo evidence and recording runbook

> Historical development/experiment record. Current public-alpha behavior and
> release verification are described in [HANDOFF.md](HANDOFF.md) and
> [RELEASE_RESULT.md](RELEASE_RESULT.md). Private source/lesson approvals and raw
> provider evidence are retained privately and are not included in this release.


The console shows records from the owning SDK. A recording of those records is a
**read-only product tour**, not proof that the recorded browser executed an
approval, blocked a call, published a lesson, or improved a model result. Keep
the executable rehearsal reports alongside the clip when presenting those claims.

## Evidence available at this checkpoint

The original six-case rehearsal has run through the public SDK with live model
assessment. The retained report is
`runtime/release/library-regression/20261012T221832Z-live-f8375cbd/report.json`:

- Combined outcomes matched all six expected cases; deterministic checks matched
  all six expectations. Four model assessments matched expectations and two were
  skipped because deterministic rules had already denied them.
- Each of three independent blocked-call counters stayed at `1 → 1`; each
  corresponding direct fixture control advanced to `2`.
- The separate local-only run retains its combined semantic miss (the model was disabled). A local-only
  run does not establish live model coverage.

These are functional synthetic regression results, not an unbiased accuracy
estimate. The later `reverification.json` independently reconfirmed three blocked
counters at `1 → 1`, with separate controls advancing `2 → 3`, and retained the
original report unchanged.

The user authorized four source verdicts and separately approved all four exact
lesson bodies and digests. All four were privately published to Senso and verified
before activation. See `LESSON_PUBLICATION_REVIEW.md` for those contents. The
completed original `library-live/memory-rehearsal.json` then revoked one actually
retrieved lesson, rejected the stale assessment, excluded that lesson from the
next scoped search, verified its remote document remained, and preserved every
quarantined state. The resulting registry has **three active lessons and one
revoked**. The provider response had completed and was held before local
validation; this does not prove the network request was pending at revocation.

Keep the following evaluation records separate:

- The original `library-live/paired-results.json` contains 48 completed attempts,
  but model-visible server IDs exposed benign/policy case-name hints. Retain it
  as functional evidence only; it cannot support an unbiased semantic-accuracy or
  memory-improvement claim.
- `library-live/evaluations/opaque-v2/paired-results.json` retains all 48 scheduled
  errors from a tuple/list snapshot-serialization guard failure. No model calls
  or opaque trial observations occurred. Do not erase or replace this failed
  preflight report.
- `library-live/evaluations/opaque-v3/` completed the corrected 48-attempt schedule with opaque model-visible server IDs and the
  three remaining active approved lessons. It reuses the same eight synthetic
  cases; these are not new independent cases. Its protocol, plan, snapshot, and
  results are separate from the original four-lesson treatment. Do not pool them
  or represent repeated trials as independent cases. Both modes matched 24/24
  expected outcomes; there was no demonstrated decision improvement. Memory
  remains off by default.

The original revocation rehearsal remains valid integrity evidence because the
held model response was discarded. A second revocation is not needed to finish
this release and would change the three-lesson comparison treatment.

## Repeat the executable six-case rehearsal

From the repository root, use a fresh evidence directory for each run:

```sh
uv run python scripts/rehearse_library.py
uv run python scripts/rehearse_library.py --live --env-file /absolute/private/project.env
```

Each invocation creates a unique directory under `runtime/release/library-regression`.
The first command exercises local deterministic rules and enforcement. The second
uses the configured live model and reports its actual outcomes and usage. These
commands use the original regression fixtures; they do not train memory or run
the held-out comparison. Inspect the new `report.json`, counters, and exported
decision records before quoting a result. Preserve failed runs as well as passes.

Fixture baseline approvals in this rehearsal are synthetic test actions. They are
not substitutes for the human verdict or lesson-content approval gates.

## Record a read-only console tour

Run the console in the process that owns the SDK store. Write its private URL into
a file with owner-only permissions; supply that **file path**, never the URL, to
the recorder. The console must already be listening. Shut it down cleanly when
finished so a later publication or evaluation process can acquire store ownership.

For the current release workspace, the private helper
`runtime/release/serve_preview.py` displays stored records without starting the
monitor or making model calls. That helper is a local release artifact, not a
shipped example. Do not run `examples/reviewed_monitor.py` against the release
configuration containing unrun evaluation profiles: starting observation over
those profiles would consume cases before their frozen schedule.

The recorder uses an installed Google Chrome with a temporary browser profile.
It permits only same-origin GET requests and never clicks action buttons. Server
selection, tabs, and native disclosure controls are navigational only.

```sh
uv run --no-project --with playwright python scripts/record_console.py \
  --url-file /absolute/private/console-url.txt \
  --output-dir /absolute/private/console-tour-new \
  --hold-seconds 4 --mp4
```

The output directory must not already exist. Optional arguments are
`--server-id EXACT_CONFIGURED_ID`, `--width`, `--height`, `--chrome`, and `--ffmpeg`.
On the release machine the native FFmpeg executable is
`/opt/homebrew/bin/ffmpeg`. The installed Google Chrome is used; no Chromium
download is required. If Playwright reports that its recording FFmpeg asset is
missing, install that official asset and rerun with a new output directory:

```sh
uv run --no-project --with playwright python -m playwright install ffmpeg
```

Outputs include silent `console-tour.webm`, optional `console-tour.mp4`, numbered
screenshots, and `recording.json`. The report records whether navigation completed,
blocked requests, JavaScript error count, the displayed state, and catalog count.
It explicitly marks `workflow_execution_proof: false`. A successful tour only
establishes that those real views were rendered and navigated during capture.

The recorder does not retain the URL, token, browser profile, network response
bodies, or traces. Screenshots and video **do contain the console's displayed
metadata and lesson text**. Keep them private until those contents have been
reviewed for sharing. A running monitor may change state independently during a
tour; the recorder does not freeze backend state.

The post-revocation recording is `runtime/release/console-tour-final/recording.json`.
It shows the actual three-active/one-revoked registry and performed no mutation
requests. It is a silent navigation clip, not a workflow execution proof. The
earlier draft-state recording remains a historical artifact and should not be
presented as the current registry.

## Run a versioned comparison without replacing evidence

The current release already has approved and verified lessons. Do not re-record
its verdicts, regenerate drafts, republish lessons, or reactivate the revoked
lesson to make a comparison look consistent with the original run.

For a future explicitly authorized complete comparison, stop the console owner
and choose a **new, unused lowercase evaluation ID**:

```sh
uv run python scripts/release_memory.py evaluate \
  --directory runtime/release/library-live \
  --env-file /absolute/private/project.env \
  --evaluation-id new-comparison-01
```

`--evaluation-id` is required for `evaluate`; existing namespaces are refused.
The command freezes the currently eligible approved memory and writes
`protocol.json`, `active-memory.json`, `paired-plan.json`, and `paired-results.json`
under `evaluations/<ID>/`. Opaque trial identities hide the internal case labels
from the model. The protocol binds the trial mapping, model, policy, rules,
review limits, memory snapshot, and retained prior artifacts. The same-case reuse
and changed lesson count must be disclosed.

Each complete schedule has eight cases, three paired repetitions, and two modes:
**48 scheduled attempts, or 24 pairs**. Retain outcomes, timeouts, and errors; do
not replace poor outcomes or selectively rerun them. Inspect per-case and
aggregate results before any memory-effect claim. A tie, regression, or
inconclusive result is valid. Repeated trials are not independent observations.

The optional post-evaluation integrity rehearsal can target a completed version:

```sh
uv run python scripts/rehearse_memory.py \
  --directory runtime/release/library-live \
  --env-file /absolute/private/project.env \
  --evaluation-id new-comparison-01
```

Omitting `--evaluation-id` selects the original root evaluation. Existing rehearsal
reports are refused. This command makes one disclosed extra model attempt and
locally revokes one actually retrieved lesson; it changes future eligibility.
Use it only when that new revocation is intended, after the selected comparison,
and never silently alter a frozen run's treatment. For this release, retain the
already completed original rehearsal instead of running another one.

For exact arguments, use each script's `--help`. Publication, evaluation, and the
revocation rehearsal use external services; the recorder only reads the local
console. Preserve the original reports and all versioned run directories.

## Assemble the final presentation

Use the SDK rehearsal for the executable before/after sequence: safe baseline,
metadata change, blocked managed call, independent fixture counter, and the
separate operator recovery control. Use the console tour to make the recorded
revision, decision, lesson state, and event evidence understandable. Show the
event's verification level: a local non-dispatch claim is different from an
independent server-side counter observation.

A narrated evidence edit can combine the actual executed counter and lifecycle
proofs with the read-only console capture. The finished 90-second video is
`runtime/release/demo-video-final/mcp-trust-monitor-demo.mp4`, with transcript,
captions and media QA alongside it. The corrected comparison tied at 24/24
expected outcomes in each mode. State that the original label-leaking run
and failed preflight were retained, and that the correction reused eight cases
with three active lessons. This recorder never executes the workflow; do not edit
it into apparent approval or publication actions that did not happen.

Suggested 90-second narration, adapted to the evidence actually shown:

> MCP tools can change after an application first connects. MCP Trust Monitor
> gives the application a managed catalog and call path whose approvals bind the
> observed metadata, launch identity, policy, and current generation. A metadata
> change can close that path until the operator reviews it again.
>
> Deterministic rules and model assessment have separate roles. Rules can deny
> known violations; model recommendations can request review or quarantine. The
> model cannot approve a tool. Monitoring metadata does not establish that the
> server's implementation is safe.
>
> Here the console shows the actual observation, state, and recorded evidence.
> Operational approval is separate from a human verdict about an assessment.
> Four human verdicts supported four lessons whose exact contents were approved,
> privately published, and verified. One lesson was later revoked in a separate
> integrity rehearsal; three remain active.
>
> Lessons are versioned context, not new authority. The record distinguishes
> sources requested, returned, and cited, and preserves the final action and its
> verification level. Revocation removes a lesson's future eligibility without
> restoring a quarantined tool.
>
> We test enforcement with independent fixture counters. Our original comparison
> exposed case-label hints, so we retained it and a failed preflight, then completed
> a complete opaque-ID correction using the same eight cases and three active
> lessons. Both modes matched 24/24 expected outcomes; there was no demonstrated
> decision improvement. We report the measured outcomes without pooling those treatments or
> assuming that adding memory makes decisions better.

Use the actual reported result without expanding its scope. Add a visible “synthetic controlled demo” label when
showing the fixtures; present the read-only tour as “recorded console state.”
