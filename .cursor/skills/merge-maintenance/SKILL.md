---
name: merge-maintenance
description: Resolve upstream merges in the ProxiFyre repository while preserving the project UI, configuration-driven functionality, native routing behavior, and modular file ownership. Use automatically when merging branches, resolving conflicts, rebasing, or repairing regressions caused by an upstream merge.
---

# ProxiFyre Merge Maintenance

Use this as supplementary expanded guidance when the task involves a merge,
rebase, cherry-pick, conflict resolution, or regression caused by integrating
another branch. The always-on rule and AGENTS.md are sufficient and remain the
primary policy; this document must never be a prerequisite for compliance.

## Pre-merge inventory

Record before editing:

- merge base, current parent, and incoming parent;
- changed files and unmerged paths;
- owning project/module for each file;
- generated or build output that must remain untouched.

Use `git status`, `git diff --name-only`, `git diff --name-only --diff-filter=U`,
and parent-specific file inspection. Preserve the user's existing worktree changes.

For every configuration-related conflict, create a field inventory before
editing. For each root and rule node record the JSON property name and casing,
model property, serializer/deserializer behavior, normalizer/copy/clone path,
validator behavior, runtime registration or UI consumer, native/UI boundary
when applicable, and its regression test. Treat loss in any intermediate
representation as a merge failure: model presence alone is not support.
Compare the known-good parent with the merged path to find mappers, adapters,
normalizers, or DTOs that may drop fields. Keep fields in the module that owns
their concern; do not add routing policy to transport/native settings DTOs.
Every new or merged node needs a round-trip or end-to-end pipeline test covering
populated and omitted/null semantics where meaningful, using the product's
actual configuration shape rather than only a directly instantiated model.

For native or cross-process behavior, inventory the identity contract as well:
record how values are normalized when registered and when looked up. Check
paths, basename extraction, case, executable extensions, handles, indexes, and
serialized names. A policy store that accepts one spelling but looks up another
is a merge regression even when registration logs are correct.

## Non-negotiable product behavior

- `ProxiFyre` is the engine-hosting WinForms surface. Its `Program.cs` owns
  the single entry point, `MainForm` owns its UI, and `ProxiFyreService` owns
  runtime/network bootstrap.
- `ProxiFyreUI` plus `ProxiFyreUILauncher` is the separate configuration and
  service-management surface. It edits configuration and controls the engine,
  must not load `socksify.dll`, and must remain functional with the engine UI.
- Both surfaces share the intended service/configuration contracts; neither
  may create a second networking engine.
- Startup must load `app-config.json` beside the executable, configure `NLog.config`, create the native `Socksifier`, register proxies, exclusions, LAN bypass, and per-process CIDR rules, then start the router.
- Preserve the existing configuration schema and case-sensitive JSON property mappings unless a deliberate migration is implemented and tested.
- Never associate a process with an invalid proxy handle. Check the result of `AddSocks5Proxy` before calling association or CIDR APIs.
- Optional upstream PASS-filter installation must not invalidate an otherwise usable proxy. It is a driver-dependent optimization, not proof that proxy construction failed.
- Preserve native routing and policy behavior, including TLS, IPv4/IPv6 support, process exclusions, unresolved-process policy, and destination inclusion.

## File and module ownership

Keep changes in the smallest responsible module:

- Engine UI/bootstrap: `ProxiFyre/Program.cs`, `ProxiFyre/MainForm.cs`,
  `ProxiFyre/ProxiFyreService.cs`.
- Management UI: `ProxiFyreUI/`; native management host:
  `ProxiFyreUILauncher/`.
- Schema, serializer, normalization, validation, persistence, compatibility:
  `ProxiFyre.Configuration/`.
- Managed/native boundary: `socksify/Socksifier.*`.
- Native routing and process policy: `netlib/src/proxy/`, including
  `netlib/src/proxy/process_routing_policy.h`.
- Destination inclusion policy: `socksify/policy/`.
- Installer/setup: `ProxiFyre.Installer/`, `ProxiFyre.Bundle/`,
  `ProxiFyreSetupBootstrapper/`, `ProxiFyreSetupEngineExtension/`.
- Deterministic validation/tests: `scripts/` and `ProxiFyre.Tests/`.

Do not move service code into the UI entry-point file, duplicate classes across files, or combine unrelated upstream features into a monolithic conflict resolution. Prefer a new adapter/helper file when two branches modify the same large file for unrelated reasons.

### Conflict classification

| Conflict area | Owner | Required resolution |
| --- | --- | --- |
| Startup/window lifecycle | `ProxiFyre` UI | Keep one `Main`, launch `MainForm` |
| Config/proxy bootstrap | `ProxiFyreService` | Preserve schema, path, logging, and registrations |
| Managed/native API | `socksify` | Preserve stable overloads and handle semantics |
| Packet routing/filtering | `netlib` | Preserve routing policy, rollback, and lifecycle safety |
| Installer/service commands | `ProxiFyre`, installer projects | Preserve service scope and command behavior |
| Models/validation | `ProxiFyre.Configuration` | Keep compatibility unless explicitly migrated |
| Checks/tests | `scripts`, `ProxiFyre.Tests` | Keep deterministic and driver-independent |

Enforce one concern per change. When unrelated branches repeatedly edit one
large file, extract a coordinator, adapter, or helper with a stable interface;
do not repeatedly grow the hotspot. Keep compatibility shims at module
boundaries and put new behavior in the owning module.

Prefer a new narrow helper or adapter for merge-specific behavior when it can
reduce edits to an upstream hotspot. Keep the integration seam explicit and
small. Do not move a concern merely to avoid a conflict if that would duplicate
ownership or weaken the existing public contract. Project and solution metadata
are part of the conflict surface: include each file once, and keep standalone
tests outside the main solution when they do not need solution-level wiring.

Preserve configuration schema, property casing, normalization, validation,
first-match ordering, and unknown-field compatibility. Keep stable public APIs
and use narrow interfaces, adapters, or overloads at cross-module seams.
Include each project file exactly once. Preserve UI log ordering/readability,
explicit startup-sized bounded retention, and independent full file logging.
Preserve service commands, installer payloads, shortcuts, protected paths,
architecture-specific packaging, and native handle/index semantics including
valid zero-based index handling, lifecycle locks, rollback, optional-filter
fallback, and diagnostics.

Known hotspots and preferred seams:
- `Program.cs` ↔ `ProxiFyreService.cs`: keep dispatch/UI separate and use one
  service implementation;
- `ProxiFyre.Configuration/` ↔ `socksify/`: use typed registration adapters;
- `socksify/` ↔ `netlib/src/proxy/`: preserve handle, lifecycle, rollback, and
  optional-filter contracts;
- `build.ps1` ↔ `scripts/Test-ArtifactProvenance.ps1` ↔ installers: use one
  published manifest-backed artifact set;
- `ProxiFyreUI/Infrastructure/EngineLocator.cs` ↔ service/launcher paths:
  reject stale executable identity.

## Conflict-resolution procedure

1. Record the merge base, both parents, changed files, and all unmerged paths.
2. Classify each conflict by module ownership before editing.
3. Inspect both parent versions and the surrounding call graph. Never choose “ours” or “theirs” for a large file without checking behavior.
4. Preserve both independent features through small, explicit edits. Keep stable public APIs and add overloads/adapters instead of rewriting callers.
5. Resolve startup first: exactly one valid `Main`, `OutputType` remains `WinExe`, `MainForm` is compiled, and `ProxiFyreService.cs` is included exactly once.
6. Resolve configuration next: verify the executable-relative path, JSON model, NLog setup, proxy creation, association, exclusions, and router start.
7. Resolve native behavior next: verify handle/index lifetimes, filter ownership, rollback, thread/lifecycle locking, and optional-driver operations.
8. Search the repository for conflict markers, duplicate type names, stale file includes, TODOs, placeholder success responses, and calls using invalid handles.
9. Build the affected project, then the solution. Run focused tests and a UI/runtime smoke check when the environment supports them.
10. Review the final diff by module. Leave generated output unstaged and report any runtime or driver limitation honestly.

For a regression, add a causal proof before declaring the merge resolved:
identify the first layer that diverges from the known-good parent, add a test at
that layer, and add one end-to-end check across the affected boundary. Do not
accept a log-only proof when the behavior is enforced by native code, a driver,
or a deployed artifact.

## README policy

`README.md` is always the fork's own version. During any merge, rebase,
cherry-pick, or conflict resolution, keep our side and never take the upstream
(`wiresock/proxifyre`) text:

- On conflict, resolve `README.md` with `git checkout --ours -- README.md`
  (or the equivalent `ours` side for the current branch), then `git add`.
- Never accept upstream README changes, even when the merge is otherwise clean.
  If a merge would change it, restore the fork version afterwards and verify
  with `git diff HEAD -- README.md` (expected: no changes).
- Do not edit README content as part of a merge. Documentation changes belong in
  a separate, explicitly requested commit.
- The current fork version is the one committed in `d2a4771` ("Revert readme")
  on `merge/1118`. Treat that as the baseline until the owner changes it.

## Required invariants

- UI startup remains a WinForms `WinExe`; `Program.Main` launches `MainForm`.
- `MainForm` and `ProxiFyreService` remain separate; the service performs config-driven runtime initialization.
- `app-config.json` is loaded beside the executable with its existing property names and case behavior.
- Proxy, exclusion, LAN bypass, CIDR, TLS, IPv4/IPv6, and unresolved-process policies remain reachable.
- Installer/service scope and commands remain unchanged unless an explicit tested fix requires otherwise.
- Native handles are checked before association, and ownership/lifetime remains index-safe.
- Optional driver-dependent optimizations may fall back, but filter failures must remain diagnosable and must not erase required routing.
- Logging must not duplicate one native event through multiple uncoordinated sinks.

Validation layers are distinct: source/static correctness, affected-project
build, solution/installer build, published-artifact provenance, UI/service
smoke behavior, and native driver/endpoint integration. Success in an earlier
layer never proves a later layer. Report unavailable Windows tooling, driver,
endpoint, or installer validation honestly.

When output or deployment files change, verify canonical
`bin\exe\<platform>\<configuration>` versus published `Build\exe`, matching
executable, managed assemblies, `socksify.dll`, configuration, and manifest,
plus architecture/version/hash consistency. Verify service `ImagePath`,
shortcuts, launcher, UI-selected engine path, installer payload, exact
process executable, and loaded assembly/native paths. A successful build or
repository path is not runtime proof.

## Validation matrix

| Check | Purpose | If unavailable |
| --- | --- | --- |
| Read-only repository check | markers, duplicate types/includes, stale references, handles, generated output | fix reported source issue |
| Affected-project build | local syntax and project membership | report tool/environment blocker |
| Solution build | cross-project contracts and installer wiring | report exact failing project |
| Focused tests | config, UI seams, policy, and lifecycle behavior | run deterministic checks; document gap |
| Artifact provenance | hashes, versions, architecture, manifest, paths | report stale/mismatched output |
| Executable/UI smoke test | actual `MainForm` launch and config bootstrap | document Windows/UI limitation |
| Service/installer check | command and package behavior | document unavailable Windows tooling |
| Driver-dependent check | NDIS/filter/routing behavior | do not fake success; report driver limitation |

The repository check is `scripts/Test-MergeMaintenance.ps1`; run it with no
arguments from the repository or with `-RepoRoot <path>`. Use
`-VerifyConfigurationSchema` for the optional model/pipeline coverage check. It is read-only
and must not require a SOCKS5 server, NDIS driver, database, or network.

## Unsafe or ambiguous conflicts

Stop and report the exact blocker when a conflict would require deleting
unknown user behavior, changing public/configuration contracts without a
migration, choosing a whole large file without parent inspection, or
disambiguating multiple valid UI/service entry points without evidence.
Do not use a wholesale `ours`/`theirs` resolution. Leave the worktree
recoverable and request a decision when behavior cannot be inferred safely.

## Common traps

- A successful compilation does not prove the UI launches. Test the actual executable entry point.
- Renaming `Program` or `ServiceProgram` during a merge can silently select the wrong startup path.
- Deleting a source file without removing its explicit `.csproj` `<Compile>` entry breaks the build; retaining both creates duplicate types.
- A failed native filter insertion can be non-fatal. Do not convert an optional optimization failure into `-1` proxy creation.
- Logging the same event through both NLog and redirected console output creates misleading duplicates.
- Association “index out of range” usually means proxy creation failed earlier. Fix the first failure and guard the caller.
- A successful build does not prove the selected executable, managed DLL,
  native DLL, configuration, service registration, or shortcut belong together.
- Do not hide a driver failure by deleting all filter logic. Preserve the established fallback behavior and make the failure diagnosable at the correct severity.
- Do not fix overlap warnings by changing first-match rule ordering.
- Do not silently truncate or duplicate bounded UI logs; full file history is
  independent of the visible pane.
- Do not run broad formatting or generated-file rewrites while resolving a merge; they increase future conflict surface.
- Do not change installer/service behavior merely to make an interactive UI build pass.
- Do not assume a field is supported because it exists in a model or startup
  log; normalization, cloning, adapters, native key lookup, and deployed
  artifact selection can still discard or bypass it.
- Do not normalize registration names and lookup names independently. Reuse one
  canonical helper, especially for process names, paths, extensions, casing,
  handles, and serialized identifiers.

## GUI authority

The fork's GUI is authoritative. Upstream (`upstream/main`) contributes
libraries only (for example `netlib`, `ndisapi`, and vcpkg/NuGet packages).
Never take upstream UI or entry-point code. Fork-owned paths that must match the
fork (`origin/main`) after every merge unless the owner changes them:

- `ProxiFyre/Program.cs`, `ProxiFyre/MainForm.cs`, `ProxiFyre/NLog.config`,
  `ProxiFyre/MainForm.Designer.cs`, `ProxiFyre/ProxiFyreService.cs`,
  `ProxiFyre/ArtifactIdentity.cs`, `ProxiFyre/ConsoleTextWriter.cs`,
  `ProxiFyre/NativeDependencyLoader.cs`, `ProxiFyre/ProxiFyre.csproj`,
  `ProxiFyre/app.ico`;
- `ProxiFyreUI/**` and `ProxiFyreUILauncher/**`.

Upstream differs here: its `ProxiFyre/Program.cs` is a console Topshelf `Exe`
targeting .NET Framework 4.7.2, and its `ProxiFyreUI/Forms/MainForm.cs` is not
the fork's. Verify after resolving with blob equality:

```
git rev-parse HEAD:ProxiFyre/Program.cs origin/main:ProxiFyre/Program.cs
```

If the GUI blobs differ from `origin/main`, the GUI leaked from upstream. Restore
the fork's files (`git checkout origin/main -- <path>`) and re-check the native
or library changes separately.

### Engine window logging (NLog console target)

The engine's own WinForms window (`ProxiFyre/MainForm.cs`, launched by
`Program.RunEngineWinForms`) shows only what is written to `Console.Out` and
`Console.Error`. It does not read the log file. The redirection is
`Console.SetOut(new MultiTextWriter(...))` in `Program.cs`.

So `ProxiFyre/NLog.config` must keep a console target and send `Info` and above
to it. The correct setting is:

- a `Console` target (`name="console"`) with the layout
  `${longdate}|${uppercase:${level}}|${logger}|${message}${exception:format=ToString}`;
- `<logger name="*" minlevel="Info" writeTo="file,console" />`.

Upstream's `NLog.config` (commit `ed9213e`, 2026-10-13) removed the console
target. A clean auto-merge took it with no conflict, so the engine window showed
only its own startup lines and the service log never appeared. Because this is
not a conflict, the merge tooling does not flag it. After every merge, check
`ProxiFyre/NLog.config` against this rule, and do not accept upstream's version.
## Feature contract (README)

`README.md` (fork version) lists user-visible features. Each one is a merge
contract. After a merge, verify each feature has code, a test, and a build path:

- `ipRanges` (per-rule destination CIDR): JSON model, normalizer copy,
  validator, registration, `Socksifier`, `socksify_unmanaged`, `dip_*` policy,
  and `netlib` `redirect_decider` call sites;
- `--allow-not-admin`: `EngineCommandLinePolicy` and its tests;
- SOCKS5 over TLS, LAN bypass, excludes, log level, and the Windows GUI with
  Apply & Restart.

A feature missing from any layer is a regression even when the build passes.

## Anti-patterns and best practices from real regressions

Source: `1ff93d4..4b553b0` (fixes for the `Fix merge error` base commit).

Anti-patterns that happened:

1. **Field dropped in the normalizer.** The model had `IpRanges`, but
   `ConfigurationNormalizer.NormalizeRule` did not copy it. The feature vanished
   silently on normalize, and the GUI save path (`ConfigurationWorkspace` →
   normalizer) would erase it. Best practice: a coverage check that every
   `[JsonProperty]` model property is assigned in the normalizer, plus a JSON →
   validate → normalize → runtime test (`ConfigurationNormalizerTests`,
   `ProxiFyreServiceBootstrapTests`).
2. **Boolean result ignored.** `if (engine.IncludeProcessDestinationCidr(...))
   info(...)` had no `else`, so a rejected CIDR was never reported. Best practice:
   check every managed/native return value and emit a warning with rule index,
   process name, and value; continue registration for the other rules. Test with
   a fake engine that rejects.
3. **Validation gap.** Malformed CIDRs were accepted at config time. Best
   practice: one parser shared by validation and copy
   (`ProxyRuleDestinationRangePolicy.TryValidate`), with `IP_RANGE_INVALID`
   diagnostics and tests for valid and invalid inputs. The native `dip_*` parser
   must reject the same malformed inputs; keep a native test for that.
4. **Hybrid entry point.** The base commit had a WinForms `Main()` that launches
   `MainForm` next to a Topshelf `ServiceProgram` host. Two competing bootstraps
   are a regression. Keep one `Main` (fork version) and let the service coordinator
   own runtime bootstrap.
5. **Upstream file taken for a conflict.** Upstream's console `Program.cs` and
   `ProxiFyreUI/Forms/MainForm.cs` are not the fork's. Resolve GUI conflicts with
   the fork version and verify by blob (see GUI authority).
6. **Upstream netlib router taken wholesale.** Upstream `socks_local_router.h` has
   no `redirect_decider` hook. Taking it silently disables `ipRanges` routing. For
   `netlib`, keep the fork's hook and add only the narrow upstream fixes.
7. **Documentation drift.** After the merge, `.github/copilot-instructions.md`
   described ProxiFyre as a console app on .NET 4.7.2, while the csproj is a
   `WinExe` on 4.8. Docs must match the project file in the same merge.
8. **Weak checks.** The original `-VerifyConfigurationSchema` only confirmed that
   `NormalizeRule` exists and that tests mention the serializer and normalizer.
   It passed even when a field was missing. The script now parses every
   `[JsonProperty]` model property per class and fails if the normalizer
   initializer for that class does not assign it, or does not clone
   `ExtensionData`. Still treat it as a static check: it does not prove the
   runtime or GUI path, so keep the pipeline tests.

9. **Silent auto-merge of a file the fork's window depends on.** Upstream removed
   the console NLog target (`ed9213e`). The merge took it with no conflict, so
   the engine window lost every service line. Best practice: list each fork-owned
   file a UI depends on under GUI authority, and check it after the merge (see
   "Engine window logging").

Best practices to follow:

- Clone rules through `ConfigurationSerializer.CloneRule` (JSON round trip), as
  `ProxyRuleEditorForm.BuildCandidate` does. Do not rebuild a `ProxyRule`
  field-by-field, because that drops fields the GUI does not show, such as
  `ipRanges`.
- Keep the native enforcement chain intact: `Socksifier.cpp` →
  `socksify_unmanaged.cpp` → `dip_should_redirect_for` → `socks_local_router`
  `redirect_decider_`. Check each link after a merge; a missing link is silent.
- Keep the policy seam narrow: `socksify/policy/POLICY-INTEGRATION.md` names
  the three `normalize_process_key` call sites that must survive a merge.
- Keep generated and build output untracked (`external/`, `Build/`,
  `socksify/socksify/` appeared as untracked in this repo). Do not stage them
  during a merge.
- Record which layer proved each fix: a test for the normalizer, a test for the
  registration warning, and a native test for the `dip_*` parser. A build alone
  proves none of them.

## Completion gate

The merge is complete only when:

- no unmerged paths or conflict markers remain;
- one UI entry point launches `MainForm`;
- both UI surfaces remain functional with one engine/service implementation;
- the original configuration-driven bootstrap is present and reachable;
- every native handle is validated before use;
- module boundaries are clear and duplicate implementations are removed;
- focused build/tests pass, or a concrete external blocker is documented.
- the read-only merge-maintenance check passes;
- artifact/deployment identity is verified whenever output paths changed;
- remaining hotspots and Windows/driver-only limitations are explicitly reported.
