---
name: merge-maintenance
description: Resolve upstream merges in the ProxiFyre repository while preserving the project UI, configuration-driven functionality, native routing behavior, and modular file ownership. Use automatically when merging branches, resolving conflicts, rebasing, or repairing regressions caused by an upstream merge.
---

# ProxiFyre Merge Maintenance

Use this workflow for every merge, rebase, or conflict repair.

## Non-negotiable product behavior

- The WinForms application is the primary UI. `ProxiFyre/Program.cs` must launch `MainForm`; do not replace it with a service-only or Topshelf entry point.
- `MainForm` owns the desktop UI. `ProxiFyreService` owns runtime initialization. Keep them as separate classes and files.
- Startup must load `app-config.json` beside the executable, configure `NLog.config`, create the native `Socksifier`, register proxies, exclusions, LAN bypass, and per-process CIDR rules, then start the router.
- Preserve the existing configuration schema and case-sensitive JSON property mappings unless a deliberate migration is implemented and tested.
- Never associate a process with an invalid proxy handle. Check the result of `AddSocks5Proxy` before calling association or CIDR APIs.
- Optional upstream PASS-filter installation must not invalidate an otherwise usable proxy. It is a driver-dependent optimization, not proof that proxy construction failed.
- Preserve native routing and policy behavior, including TLS, IPv4/IPv6 support, process exclusions, unresolved-process policy, and destination inclusion.

## File and module ownership

Keep changes in the smallest responsible module:

- UI startup and window behavior: `ProxiFyre/Program.cs`, `ProxiFyre/MainForm.cs`, and designer files.
- Configuration and proxy bootstrap: `ProxiFyre/ProxiFyreService.cs`.
- Managed/native boundary: `socksify/Socksifier.*`.
- Native router and packet policy: `netlib/src/proxy/*`.
- Destination inclusion policy: `socksify/policy/*`.
- Configuration models and validation: `ProxiFyre.Configuration/*`.
- Tests for each module stay with that module.

Do not move service code into the UI entry-point file, duplicate classes across files, or combine unrelated upstream features into a monolithic conflict resolution. Prefer a new adapter/helper file when two branches modify the same large file for unrelated reasons.

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

## Common traps

- A successful compilation does not prove the UI launches. Test the actual executable entry point.
- Renaming `Program` or `ServiceProgram` during a merge can silently select the wrong startup path.
- Deleting a source file without removing its explicit `.csproj` `<Compile>` entry breaks the build; retaining both creates duplicate types.
- A failed native filter insertion can be non-fatal. Do not convert an optional optimization failure into `-1` proxy creation.
- Logging the same event through both NLog and redirected console output creates misleading duplicates.
- Association “index out of range” usually means proxy creation failed earlier. Fix the first failure and guard the caller.
- Do not hide a driver failure by deleting all filter logic. Preserve the established fallback behavior and make the failure diagnosable at the correct severity.
- Do not run broad formatting or generated-file rewrites while resolving a merge; they increase future conflict surface.

## Completion gate

The merge is complete only when:

- no unmerged paths or conflict markers remain;
- one UI entry point launches `MainForm`;
- the original configuration-driven bootstrap is present and reachable;
- every native handle is validated before use;
- module boundaries are clear and duplicate implementations are removed;
- focused build/tests pass, or a concrete external blocker is documented.
