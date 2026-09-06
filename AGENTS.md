# Agent Instructions

For any merge, rebase, cherry-pick, conflict-resolution, or merge-regression
task, automatically apply `.cursor/rules/merge-maintenance.mdc`. It is the
primary, agent-neutral policy and does not require a special command or manual
skill invocation. The detailed skill at
`.cursor/skills/merge-maintenance/SKILL.md` is supplementary context only.

`ProxiFyre` is the engine-hosting WinForms surface: preserve its `MainForm`
entry point, executable-relative `app-config.json` loading, and separate
`ProxiFyreService` bootstrap. `ProxiFyreUI` and `ProxiFyreUILauncher` are the
separate configuration/service-management surface and must not load the
networking DLL. Resolve changes by verified module ownership, keep one
concern per change, and run the deterministic
`scripts/Test-MergeMaintenance.ps1` check after conflict edits.

Do not use wholesale ours/theirs resolutions, change configuration contracts,
or claim runtime/driver validation without evidence. Report Windows-only
limitations and remaining conflict hotspots explicitly. Separate source,
build, artifact/deployment, UI/service smoke, and driver/endpoint evidence.
