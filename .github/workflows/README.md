# CI Workflows — Fork Customization Guide

This document describes how the HODL1 fork manages upstream GitHub Actions workflows.

## Policy: What to change from upstream

| Category | Action | Reason |
|----------|--------|--------|
| Branch triggers (`main` only) | Add `custom` to `branches:` | CI must run on `custom` branch PRs too |
| Google-internal services (CLA, ClawHub, internal npm) | Delete the workflow | Not available outside Google infrastructure |
| Google-internal bot integrations (Gemini Code Assist) | Remove the specific jobs | Not available outside Google infrastructure |
| Upstream release pipelines (cargo-dist, changesets) | Delete the workflow | Fork uses its own versioning (`-hodl1.N`) |
| Workflows already covering `custom` (schedule, `branches-ignore`) | Keep as-is | No changes needed |

## Current state

### Kept & modified

| Workflow | File | Changes from upstream |
|----------|------|----------------------|
| CI | `ci.yml` | Added `custom` to push/PR branch triggers |
| Coverage | `coverage.yml` | Added `custom` to push/PR branch triggers |
| Policy | `policy.yml` | Added `custom` to push/PR branch triggers |
| Automation | `automation.yml` | Added `custom` to push trigger; removed Gemini review/reviewed jobs and `pull_request_review` trigger |

### Kept as-is (no changes needed)

| Workflow | File | Reason |
|----------|------|--------|
| Stale | `stale.yml` | Runs on schedule, branch-independent |
| Generate Skills | `generate-skills.yml` | Uses `branches-ignore: [main]`, already covers `custom` |
| Deploy Cloud Run | `deploy-cloud-run.yml` | Already triggers on `custom` branch (fork-specific) |

### Deleted

| Workflow | File | Reason |
|----------|------|--------|
| CLA | `cla.yml` | Google CLA enforcement, not applicable to fork |
| Release | `release.yml` | cargo-dist + Google internal npm registry (`wombat-dressing-room`) |
| Release (Changeset) | `release-changesets.yml` | Upstream release cycle, depends on `GOOGLEWORKSPACE_BOT_TOKEN` |
| Publish Skills | `publish-skills.yml` | Publishes to ClawHub (Google internal platform) |

## When upstream workflows change

After syncing with upstream (`git merge main` into `custom`), review workflow changes:

```bash
git diff main...custom -- .github/workflows/
```

### Checklist

1. **New workflow added upstream** — Evaluate using the policy table above. If it references Google-internal services or secrets (`GOOGLEWORKSPACE_BOT_TOKEN`, `wombat-dressing-room`, `gemini-code-assist`, `clawhub`), delete it. Otherwise, add `custom` to branch triggers if needed.
2. **Existing workflow modified upstream** — Merge conflicts in modified files (`ci.yml`, `coverage.yml`, `policy.yml`, `automation.yml`) will need manual resolution. Keep the `custom` branch additions and Gemini removal intact.
3. **Workflow deleted upstream** — If we already deleted it, no conflict. If we modified it, decide whether to keep our version or drop it.
4. **Deleted workflow re-appears after merge** — This means upstream re-added or renamed it. Re-evaluate and delete again if still Google-internal.
