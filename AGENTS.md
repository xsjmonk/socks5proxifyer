# Agent Instructions

For any merge, rebase, cherry-pick, conflict-resolution, or merge-regression
task, first read and follow:

- `.cursor/rules/merge-maintenance.mdc`
- `.cursor/skills/merge-maintenance/SKILL.md`

The WinForms UI in `ProxiFyre` is the primary application UI. Preserve its
entry point, `MainForm`, executable-relative `app-config.json` loading, and
the separate `ProxiFyreService` bootstrap. Resolve changes by module
ownership, keep one concern per change, and run the deterministic
`scripts/Test-MergeMaintenance.ps1` check after conflict edits.

Do not use wholesale ours/theirs resolutions, change configuration contracts,
or claim runtime/driver validation without evidence.
