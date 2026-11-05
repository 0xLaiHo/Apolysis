# Harness intent: bounded live validation

[English](harness-intent-live-validation.md) | [简体中文](harness-intent-live-validation.zh-CN.md)

On 2026-11-05, the synthetic harness marker/reason gate and general live
observer regression passed on **x86_64 Linux 6.18.55-2-cachyos-lts** after the
managed-gate descriptor fix and final bridge changes described below. The
expanded fixture gate completed seven captures.
Native Claude Code, Pi, and OpenCode runs have now passed with the explicit
shell bridge. In those 2026-11-05 runs, Codex was blocked by provider
connectivity and Cursor by expired authentication; neither passed that gate.
The newer Codex native-entry pass is recorded separately below.
A separate Claude run also passed the controlled model-written summary gate
described below, including actual login-regression execution and exact
kernel-event attribution.
These results qualify only the listed local paths, product versions, and
provider configurations. Other kernels and stress/loss qualification remain open. Work is
tracked in [PR #87](https://github.com/0xLaiHo/Apolysis/pull/87).
The newer Rust native-launch entry has separate [validation results](#native-entry-validation)
below; the earlier script-based runs do not qualify that entry automatically.

## What changed

Live loading exposed two defects that ordinary Rust tests did not exercise:

- CO-RE relocation failed on the raw-tracepoint context's zero-length `args`
  array. Reading the raw-tracepoint arguments without that array relocation
  fixes the Aya bounds failure. The opt-in host-BTF regression reproduces the
  failure before the fix and passes after it.
- Scanning the complete executable path caused kernel-verifier state growth.
  Fixed-length basename-tail checks preserve exact shell-name recognition
  without the path-scanning loop. The kernel code and native regression share
  the C helper, covering valid shell paths, lookalike names, and bounds.

`make test-bpf-relocation` builds the object and applies all observer CO-RE
relocations to readable host BTF without BPF privileges or kernel loading.
Native helper tests run with `cargo test -p apolysis-observer --test intent_header`.
Neither check substitutes for kernel-verifier acceptance and live assertions.

A later observer regression exposed a managed-launch descriptor defect:
`dup2(3, 3)` preserves `FD_CLOEXEC`, so the exec'd shell wrapper could lose its
gate and exit with `Bad file descriptor`/status 127. An isolated subprocess
reserves descriptor 3 before creating Tokio, then releases only that owned
descriptor and calls the actual managed-launch function. This reproduced the
failure twice before the fix; explicitly clearing `FD_CLOEXEC` made it pass.
A separate regression reproduced a leaked read descriptor when spawning
failed. Owning both pipe ends with `OwnedFd` now closes them on that error path.
Neither test closes descriptors owned by other test threads or requires BPF
privileges. Both regressions and the original gate-release test pass.

## Observed results

| Gate | Result |
| --- | --- |
| Host-BTF relocation regression | Pre-fix failure reproduced; fixed object passes: 1 passed. |
| Synthetic live marker gate | 7 complete captures, 303 raw kernel events after the descriptor and bridge fixes. Every capture includes its managed target exec, successful workload exit, and a nonempty summary consistent with the raw-event count. |
| Positive marker case | Same-PID exec, fork without exec, fork from a remaining thread after leader exit, three distinct file-attempt process identities, and loopback-connect attribution passed. `intent_capture_incomplete:true` is absent from the positive capture. |
| Reason relation and correction | A declared reason annotates the exact file and network attempt relations. A late correction changes the active reason without changing raw events or execution-relation edges. Prompt, tool-result, and native-description sentinels are absent from persisted intent/reason records. |
| Five negative marker cases | Ordinary argv, a script argument, a later comment, a short token, and an uppercase token produce no attributed intent. |
| Capture health | Drop/map-pressure/decode/load/attach failure counters are zero. Truncation counts in capture order are **2, 3, 1, 1, 1, 1, 1**. |
| General live observer regression | Post-fix run: 1 passed, 0 ignored; 3.84 seconds; zero dropped events and 1 truncation. |
| Managed-gate descriptor regressions | Descriptor-3 launch and spawn-error cleanup both reproduced failures before their respective fixes and passed afterward. |
| Local gates | `cargo test`: 541 passed, 91 ignored. Observer crate: 59 passed, 1 ignored. CLI `observe`: 20 passed, 1 ignored. Node bridge tests: 14 passed. Formatting, Clippy, quickstart, and diff checks passed. Opt-in BTF and live results are reported separately above. |
| Native-product gate | Claude Code, Pi, and OpenCode passed with the explicit `/bin/bash` bridge; counts and versions appear below. Codex connectivity and Cursor authentication blocked that dated script run. |
| Expanded synthetic gate | The real `eval`-wrapped bridge case passed, including three file-attempt process identities and network-attempt attribution. It is included in the seven-capture total. |
| Model-written summary gate | Claude Code 2.1.295: 4 login regressions passed, 2,800 raw kernel events, 12 truncations, zero loss/failures. A real native call's declared summary reached an exact `verify_login.py` file-attempt relation. This is a separate capture from the gates above. |
| Summary-protocol parser | 8 non-provider regressions passed; ordinary descriptions, malformed JSON, duplicate/unknown fields, invalid codes, and invalid summaries are rejected without manufacturing a declaration. |

Truncation diagnostics are retained. They cover bounded diagnostic argv and
malformed-header negative cases; they do not establish complete coverage.
The positive case explicitly checks marker-capture completeness separately.
The test uses `pthread_join` to establish that the leader exited before the
remaining thread's observations, rather than relying on a timing delay.

These are attempts and relation checks, not proof that a network connection
succeeded or that any observed action was authorized. A reason is declared
metadata, not an independent explanation of an action. The seven-capture gate
uses a synthetic Claude-shaped hook payload passed to Apolysis, not a live
Claude Code session.

## Reproduction and cleanup boundary

The privileged synthetic gate attaches audit-only probes to fixture scopes,
reads only temporary fixture files, and attempts a loopback connection. It
requires BPF/perf capabilities (or `CAP_SYS_ADMIN`), readable host BTF, tracing
prerequisites, and the eBPF build tools. It does not contact a provider or
Kubernetes, change policies, pin maps, or mount filesystems. Build the CLI and
the 648-byte-ABI eBPF object from the same source.

The successful marker invocation used an independent transient systemd scope:

```bash
cargo build -p apolysis-cli
sudo env APOLYSIS_REQUIRE_BPF=1 systemd-run --scope --quiet \
  --unit=apolysis-intent-validation-20261105 \
  ./scripts/test-live-harness-intent.sh
```

`APOLYSIS_REQUIRE_BPF=1` makes missing prerequisites fail instead of skipping.
The nonprivileged `APOLYSIS_REQUIRE_BPF=1 make test-bpf-relocation` also passed;
its checked-in runner performs prerequisite checks before building and testing.
`make test-live-harness-intent` is the normal opt-in runner when the caller
already has the required capabilities and toolchain access.

For the general regression, compile as the ordinary user with
`cargo test -p apolysis-cli --test observe --no-run`, then execute the resulting
`observe` test artifact in a separate privileged scope with arguments
`live_observer --ignored --nocapture`. Cargo reports the artifact path; its
build-dependent filename is not a stable interface. The checked-in
[`test-live-observer.sh`](../scripts/test-live-observer.sh) is the equivalent
runner when the privileged environment has Rust toolchain access.

The completed marker/observer scopes were absent/inactive after exit. Cleanup
found no remaining native-product test processes, fixture directories, or
Apolysis BPF programs/maps. Twelve explicitly retained failed native fixtures
were removed after diagnosis; successful fixtures were removed automatically. The two root-built BPF objects were
restored to the invoking user's ownership and mode `0644`. Raw captures,
verifier addresses, and temporary reproduction files are not committed.

## Earlier script gate: three passes, two blocked

All three completed runs explicitly selected `--shell-bridge /bin/bash`
(`APOLYSIS_SHELL_BRIDGE=/bin/bash` for the script integrations). Each passed
the zero-drop/failure diagnostic checks, linked the native declared reason
exactly to the synthetic `cat` fixture-file attempt, and retained no prompt
sentinel in the persisted JSONL outputs.
The final rerun used temporary masks for existing user shell profiles as well
as global hooks. All three selected products passed; no prerequisite was skipped.
These three runs retained `reason_code=verify_change` and `reason_summary=null`;
they did not demonstrate model-written free-text summaries.

| Product | Tested version/configuration | Raw kernel events | Truncations | Result |
| --- | --- | --- | --- | --- |
| Claude Code | 2.1.295, tested installed Claude configuration | 2593 | 12 | Passed with explicit bridge |
| Pi | 1.5.0, DeepSeek flash | 551 | 6 | Passed with explicit bridge |
| OpenCode | 1.18.31, DeepSeek v4 flash | 690 | 5 | Passed with explicit bridge |
| Codex | 0.162.0, existing ChatGPT authentication | — | — | Provider connectivity failed in this dated script run |
| Cursor | 2026.07.20, expired access and refresh authentication | — | — | Authentication failed in this dated script run |

Codex's isolated authentication binding refers to the same underlying file as
the native installation, and its token was not expired. This does not prove a
successful provider request: ordinary-user HTTP HEAD probes outside the harness
also failed. The configured proxy returned a TLS unexpected EOF with no HTTP
response for the ChatGPT/OpenAI API endpoints; direct ChatGPT access timed out
and direct API access could not connect. The observed blocker is therefore not
established as an Apolysis hook failure. No proxy addresses, environment values,
or authentication contents are included here.

Cursor's access and refresh tokens were both expired. Its cached `logged_in`
status did not establish usable API authentication. Neither product passed
this earlier script gate; the subsequent native-entry Codex pass below replaces
the blanket connectivity-blocked status for its tested configuration.

These are partial native-product results for the tested versions and provider
configurations, not a five-product qualification. The bridge is non-default
and creates a subshell: cwd changes, environment changes, and functions do not
propagate back to the product's outer shell. These passes therefore do not
establish transparent default-mode attribution or general stateful-shell
compatibility. The earlier Claude default-comment run persisted its declaration
and reason but failed exact execution attribution because the command was
embedded in the product's `eval` wrapper.

The checked-in [`test-live-reason-products.py`](../scripts/test-live-reason-products.py)
and `make test-live-reason-products` exercise actual native products and provider
calls. Build the CLI and eBPF object first. The runner requires explicit sudo
execution with the invoking user's `PATH` preserved, a non-root invoking user,
live BPF prerequisites, installed product CLIs, Bubblewrap, and usable existing
product authentication. Provider requests may incur charges. The Make target
explicitly selects `--shell-bridge /bin/bash` and uses `--require-all`, so missing
prerequisites cannot produce an overall pass.

The workload is a temporary synthetic file read with a leading reason code.
Private temporary hook configuration is used inside a Bubblewrap mount
namespace: the host is read-only except for the fixture directory, and existing
global hooks/instructions are masked without modifying their host files.
Authentication remains in place; where an isolated product directory needs an
authentication file, the existing file is bound read-only without copying its
contents. This is a bounded integration-test guard, not a hostile-agent sandbox.
The gate does not use Kubernetes or modify global product configuration.

The runner checks a successful native exit, a complete nonempty kernel capture,
one native Tool Call declaration and content-off reason, and an exact relation
from that reason to the fixture file attempt. It prints counts and fixed error
categories, not raw product output or credentials. Temporary captures and
private product logs are removed on normal and error exits by default;
`--keep-failed-private` explicitly retains failed fixtures for local diagnosis.
This dated script gate cannot claim five-product qualification. Subsequent
native-entry results are a separate qualification surface.

## Model-written summary: controlled Claude protocol

The Python scripts in this report are independent validation gates. Their
recorded product runs and counts retain their original scope; they are not
the runtime implementation or qualification results of the Rust
[`apolysis chat`](reason-chat.md) command.

The separate [`test-live-reason-summary.py`](../scripts/test-live-reason-summary.py)
gate ran Claude Code **2.1.295** against a temporary synthetic login project on
the same host. The final run completed **4 tests with no failures or errors**,
produced **2,800 raw kernel events** and **12 truncations**, and reported zero
loss/map-pressure/decode/load/attach failures. The earlier run also passed;
the final run added explicit raw/canonical event, executable, and reason-field
equality checks. The observed model declaration was `verify_change`, with
`reason_source=agent_declared` and this retained summary:

> 运行回归测试验证登录修复是否正确

The model was asked to invoke `python3 verify_login.py` once and declare its
purpose in native `Bash.description` as `APOLYSIS_REASON_JSON=` followed by a
JSON object containing only `reason_code` and `reason_summary`. It selected the
code from the supported enum and wrote the Chinese sentence itself; neither
the prompt nor the adapter supplied that sentence. The test-only adapter
strictly parses this explicit protocol and passes the two values unchanged to
the existing `apolysis_reason` input. It does not infer a reason from an
ordinary description, fill in a missing summary, or fabricate native identity.
The existing hook is invoked with `--allow-reason-summary` and
`--shell-bridge /bin/bash`; the gate checks that the stored summary remains
identical to the model's declaration and is not a redaction placeholder.

The command actually ran the valid-login, wrong-credential, unknown-user, and
empty-input regressions. The exported evidence connects the real native
session/call ID to one intent and reason, then to a `python3` `openat` attempt
on `verify_login.py` using `match_basis=intent_id` and `relation_status=exact`.
The selected raw event, canonical event, and relation agree on the intent,
event reference, process, and file; the relation retains the same reason ID,
code, source, and summary. Test results and successful native exit separately
establish that the synthetic regression suite passed. A file-open attempt
alone would not establish that outcome or verify the model's stated motive.

The script preserves only a minimal evidence bundle under
`target/native-reason-evidence-*`: `intent.jsonl`, `reason.jsonl`, the selected
raw/canonical pair in `kernel-evidence.jsonl`, one `correlation.jsonl` relation,
`native-declaration.json`, and `result.json`. The declaration receipt retains
the accepted reason and native identity, not the complete tool arguments or
description. The result records the tested version, counts, test outcome,
source commit, and runner/CLI/BPF artifact hashes. The full capture, prompt,
tool input, and private product stream are not exported; temporary working
files and logs are removed by default. The prompt-only sentinel is checked
absent from every persisted capture/declaration/reason/relation output. The
local evidence directory is mode `0700`, files are `0600`, and the bundle is
Git-ignored and not committed. Both live runs removed their temporary fixture
directories; cleanup found no remaining Apolysis BPF programs or maps. The six
retained files passed the prompt-canary and credential-marker checks, and
their reported runner/CLI/BPF hashes were independently rechecked. Explicit
summary retention still requires review of any text
before sharing; best-effort redaction is not a secrecy guarantee.

Build as the ordinary user, then run the opt-in provider/BPF gate with the
existing authenticated user's network environment preserved by name:

```bash
cargo build -p apolysis-cli
make build-ebpf
make test-reason-summary-adapter
sudo --preserve-env=PATH,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy \
  env PYTHONDONTWRITEBYTECODE=1 python3 -u ./scripts/test-live-reason-summary.py --require-all
```

`make test-live-reason-summary` invokes the same Python gate; run it through
the same explicit sudo environment after building. A non-root invoking user,
usable existing Claude authentication/provider routing, installed Claude and
Bubblewrap, and live BPF prerequisites are required. Preserve any required
existing provider-auth environment variables by name as well; do not place
their values on the command line or in the repository. The runner restores
the invoking user's real home and reuses the native gate's temporary hook and
shell-profile masks without changing global configuration. It makes a real
provider call. Missing prerequisites fail under `--require-all`. The pure
parser regressions also run in `make test` and make no provider calls.

This addition changes validation tooling only. It proves a bounded,
explicitly prompted declaration protocol with a test adapter and the opt-in
bridge, not that unmodified Claude or all five products automatically expose
why they act. The three code-only native results and the two failed runs
above retain their historical scope; current native-entry status is listed
separately below. Default summary retention remains off.

Passing this bounded gate does not qualify all process shapes, kernels, load,
event loss, or product versions, and does not resolve integration conflicts
with the protected `pre-release` branch. CI and review remain required before
merge. See [design](design.md), [roadmap](roadmap.md), and
[harness integration](harness-intent.md).

## Native entry validation

On **2026-11-06 (Asia/Kuala_Lumpur)**, the Rust
[`apolysis observe --agent`](native-observe.md) entry was exercised with real
native applications, existing provider configuration and live eBPF on the same
Linux host. The application ran as the ordinary user with its real terminal,
original configuration and native permission workflow; only the separate
collector requested sudo. These runs did not use the custom `apolysis chat`
conversation interface. The shell bridge was explicitly selected for local
attribution.

| Native path | Raw events | Truncations | Loss/failures | Observed result |
| --- | ---: | ---: | ---: | --- |
| Claude Code **2.1.318**, actual TUI with a native “Yes, once” tool approval | 18,317 | 106 | 0 | Application exit 0; capture, correlation and report checks complete. Three Bash declarations; the explicit `verify_change` call has 67 Exact Relations and creates the expected synthetic file. |
| Pi, actual TUI, earlier 1 MiB ring configuration | 21,952 | 32 | 0 | Application exit 0; complete capture/correlation/report; one actual bash call and 67 Exact Relations. |
| Checked-in Claude native noninteractive gate, final 8 MiB configuration | 9,024 | 83 | 0 | One actual Tool Call, 67 Exact Relations; exact output-file bytes, raw/canonical/intent/file chain, report generation and absent prompt canary all pass. |
| Checked-in Pi native noninteractive gate, final 8 MiB configuration | 4,891 | 16 | 0 | One actual Tool Call, 67 Exact Relations; the same file, identity-chain, report and privacy checks pass using the existing DeepSeek configuration. |
| Checked-in Codex native noninteractive gate, final 8 MiB configuration | 10,045 | 98 | 0 | One actual Tool Call, 67 Exact Relations; file bytes, raw/canonical/exact identity chain, report and prompt-canary checks pass with explicitly selected test sandbox/hook-trust flags. |
| Checked-in OpenCode native noninteractive gate, final 8 MiB configuration | 2,352 | 8 | 0 | One actual Tool Call, 67 Exact Relations; file, identity-chain, report and privacy checks pass with an explicitly selected available DeepSeek model. |
| Current Cursor native-entry attempt | 809 | 8 | 0 | Application exit 1: authentication required. Zero calls/relations; capture checks complete but product qualification fails. |

The final Claude TUI capture also retains **two unobserved declarations** and
**85 inferred candidates**; they are not added to the 67 Exact Relations.
Its one explicit reason is `verify_change` / `agent_declared`, with no retained
summary. The other two reasons are ordinary `tool_description` records with
code `unknown` and no exact execution attribution. The report labels those
sources separately; three bound reason records do not mean three verified
motives. The target file's separately checked content is `native-ui-final-ok`.
That outcome check is independent of the file syscall attempt; the generic
report still leaves arbitrary task outcome `not_verified`.

An earlier Claude TUI attempt had **18,542 events, 109 truncations and two
reserve failures**. Its application exited normally, but capture and report
remain **incomplete**; it is not counted as a passed live capture. Startup and
hook bursts motivated an 8 MiB userspace ring-capacity override only for the
controlled native collector. The event ABI, object default, legacy live
observer and daemon defaults are unchanged. The final Claude TUI and the successful
checked-in gate runs above used that override. A zero-loss bounded rerun does
not qualify sustained load or eliminate the reported truncations.

The checked-in [`test-live-native-observe.sh`](../scripts/test-live-native-observe.sh)
deliberately selects each application's own noninteractive mode. Claude's
`-p --allowedTools Bash --output-format json` and Pi's `-p` plus provider/model
arguments reach the original applications; they are not silently imposed by
the daily launcher. The gate records `interactive_tui_verified:false`, so it
does not substitute for the separate terminal interactions above. Build as the
ordinary user, then explicitly run a real-provider gate:

```bash
cargo build -p apolysis-cli
APOLYSIS_REQUIRE_BPF=1 make build-ebpf
./scripts/test-live-native-observe.sh --agent claude --require-all
./scripts/test-live-native-observe.sh --agent pi --require-all -- --provider deepseek --model deepseek-flash
./scripts/test-live-native-observe.sh --agent opencode --require-all -- --model deepseek/deepseek-flash
```

The Codex pass additionally required **explicit test-only** writable-workspace
and hook-trust choices for this trusted, temporary, noninteractive fixture:

```bash
APOLYSIS_NATIVE_TEST_TIMEOUT=90 ./scripts/test-live-native-observe.sh --agent codex --require-all -- --sandbox workspace-write --dangerously-bypass-hook-trust
```

The daily native entry does not add either of these options. Its interactive
session retains Codex's own sandbox and hook-trust decisions. An earlier Codex
default-config attempt reached the real model and exited 0, but read-only
execution and untrusted hooks left no output file, zero declarations and zero
Exact Relations; that validation failed. Native MCP authentication warnings did
not prevent the separately verified model/tool path from passing in the final
test. OpenCode's earlier immediate `UnknownError` was diagnosed as
`ProviderModelNotFoundError` for the configured `deepseek-v4-flash`, reproduced
outside Apolysis. Its successful rerun selected the natively listed
`deepseek/deepseek-flash`; no adapter bypass or global configuration masking was
used to manufacture a pass.

Existing usable authentication, provider access, sudo capability and installed
product CLIs remain prerequisites. The script runs as the ordinary user;
Apolysis elevates its collector. Missing prerequisites under `--require-all`,
provider failures and timeouts are failures, not passes. It checks exact bytes
in a synthetic workspace and verifies an actual native-root exec plus the
target file's unique declaration and matching raw, canonical and exact records.
It discards native stdout instead of saving a transcript and checks a
prompt-only canary is absent from exported JSONL. Native application history
and other existing hooks retain their own behavior.

The final Pi rerun used the final binary and gate, deliberately gave the native
application umask `022`, and still verified that every exported evidence file
was owned by the invoking user with mode `0600`, under a mode-`0700` evidence
directory. Its 4,891-event result above replaces the earlier 4,890-event pass
as the final Pi gate result; both runs were real provider/eBPF executions.
Final cleanup found no remaining Apolysis BPF programs/maps or native capture/
control temporary directories; the final native root process had exited.
Temporary sudo authorization was invalidated after the check.

Local source gates for this native-entry implementation completed separately:

| Gate | Final result |
| --- | --- |
| `cargo test` | 635 passed, 91 ignored, zero failures. Ignored opt-in tests are not counted as passes. |
| `make test-native-observe` | 32 module tests, 5 public-CLI tests and 9 local-process tests passed: 46 total. |
| `cargo test -p apolysis-cli --test observe` | 20 passed, 1 opt-in ignored. |
| `cargo test -p apolysis-observer` | 65 passed, 1 opt-in ignored. |
| Native bridge and independent summary-parser regressions | 15 Node bridge tests and 8 Python parser tests passed; neither is a provider test. |
| `cargo fmt --all -- --check`, `make lint`, `git diff --check` | Passed; lint includes workspace Clippy with warnings denied. |
| `APOLYSIS_REQUIRE_BPF=1 make build-ebpf` | Matching BPF artifacts rebuilt successfully. |

Every run automatically produced `result.json`, `report.md` and offline
`report.html`. A real generated HTML report was rendered locally with Firefox
headless in an isolated profile with external resource loading disabled; the
call card, reason source, counts, truncation and unknown task result remained
readable. The report folds background/unattributed evidence and policy notices
separately, rather than presenting every JSONL line as a syscall or attack.
Source captures and generated evidence are not committed. Canonical cwd
and `PWD` now agree for native launch, preventing an inherited shell directory
from redirecting the application's workspace interpretation.

These are four product passes for the listed native-entry configurations only.
Codex reached the real provider and tool successfully in the explicit test
configuration, so the earlier connectivity blocker must not be presented as
its current status. OpenCode passed after selecting an available model; its
earlier failed attempt remains failed. Cursor still requires usable
authentication. No default
marker-only, five-product, hostile-workload or all-version qualification is
claimed. Native arguments that disable hooks or relocate execution beyond the
local process tree remain explicit unsupported modes.
