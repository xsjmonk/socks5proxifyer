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
