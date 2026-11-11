# Veracode Bulk GitHub Integration: Enterprise Onboarding Guide

## Do you need enterprise mode?

A **GitHub Enterprise** account sits above your organizations: one enterprise owns many orgs. The `--enterprise` flag asks GitHub for **every org in that enterprise** so you do not have to list them yourself.

**Most teams should not use it.** If you are rolling out to your own org or a known set of orgs, use the **Per-Org Onboarding Guide** instead (`--orgs-file`). It needs fewer permissions and only touches the orgs you name.

| | `--orgs-file` (per org) | `--enterprise` |
| --- | --- | --- |
| Who runs it | Owner of the orgs being onboarded | Someone with access to the enterprise account, typically an enterprise owner |
| Org list comes from | A file you write | GitHub, at run time |
| Extra token scope | None | `read:enterprise` |
| Good for | Business-unit or team rollouts, pilots, adding a few orgs | Central platform team onboarding the whole enterprise at once |

Use `--enterprise` only when a central team is onboarding all (or most) orgs and does not already have the list.

## How enterprise discovery works

- The script pages through the enterprise's orgs using GitHub's GraphQL API. If GitHub times out on a page (502/504), it retries the same page with a smaller page size, so large enterprises still complete.
- At the end it compares the list with GitHub's own org count and prints either `[OK] Discovery verified complete: N orgs == totalCount N` or a warning explaining the gap.
- Orgs the token is not SSO-authorized for are **hidden by GitHub** and will not be onboarded. The warning tells you how many.

**The recommended pattern:** use `--enterprise` only for the dry run, copy the list it writes to `out/orgs.txt`, review it, then run the apply with `--orgs-file` pointing at your reviewed copy (without `--enterprise`). Apply then changes exactly the orgs you reviewed.

## Before you start

| Item | What it must be | Environment variable |
| --- | --- | --- |
| GitHub token | Personal access token (classic) with `read:enterprise`, `admin:org`, `repo`, `workflow`. The user must be an **owner** of every org being onboarded, and the token must be SSO-authorized for each org that enforces SAML. | `GITHUB_TOKEN` |
| Veracode admin credentials | API ID/key of a **human user** with the **Administrator** role. Never stored in GitHub. | `VERACODE_API_ID`, `VERACODE_API_KEY` |
| Veracode service account | API ID/key of an API service account. Written to each org's Actions secrets. | `VERACODE_SA_API_ID`, `VERACODE_SA_API_KEY` |
| Python | 3.9 or later | - |
| git | On the PATH, with outbound access to github.com | - |

```bash
pip install requests veracode-api-signing pynacl

export GITHUB_TOKEN="..."
export VERACODE_API_ID="admin_api_id"
export VERACODE_API_KEY="admin_api_key"
export VERACODE_SA_API_ID="service_account_api_id"
export VERACODE_SA_API_KEY="service_account_api_key"
```

The integration is not supported in the Veracode United States Federal Region. On GHES, add `--api-base https://HOST/api/v3 --web-base https://HOST` to every command.

## Step 1: Discover and dry run

```bash
python script.py --enterprise YOUR-ENTERPRISE --workers 5
```

Check the discovery line at the top of the output, then review the files in `out/`:

| Output file | What to do with it |
| --- | --- |
| `orgs.txt` | The discovered org list. Copy it (for example to `rollout-orgs.txt`) and remove any orgs you do not want to onboard now. Every dry run overwrites `out/orgs.txt`, so do not edit it in place. |
| `teams_map.csv` | Fill in the `teams` column if teams are not simply the org names. |
| `missing_veracode_repo.csv` | Orgs that still need the `veracode` repo. |
| `manual_install_links.csv` | App install links, used in Step 3. |
| `actions_allowlist_issues.csv` | Orgs whose Actions policy blocks the Veracode actions. Fix in `Settings > Actions > General`. |
| `audit_report_<timestamp>.json` | Full per-org state. |

To onboard only part of the enterprise while still discovering it, combine both flags: `--enterprise YOUR-ENTERPRISE --orgs-file subset.txt` keeps only the listed orgs.

Teams options (pick one):

| Option | Team name |
| --- | --- |
| `--set-teams-auto` | The org name |
| `--set-teams-file out/teams_map.csv` | The CSV value; blank rows get no team |
| `--set-teams-hybrid out/teams_map.csv` | The CSV value; blank rows fall back to the org name |

Add `--team-prefix "gh-"` to prefix every team name. Use one team name per CSV row. `teams_map.csv` is only generated when it does not exist yet, so delete it before a new dry run if your org list changed.

## Step 2: Onboarding run

Apply from the reviewed list, not from live discovery:

```bash
python script.py --apply \
  --orgs-file rollout-orgs.txt \
  --import-repo \
  --set-teams-file out/teams_map.csv \
  --team-prefix "gh-" \
  --create-teams \
  --set-secrets \
  --link-teams-to-workspaces \
  --workers 5
```

| Flag | What it does |
| --- | --- |
| `--import-repo` | Creates the private `veracode` repo, imports the workflow templates, sets `main` as default branch, adds the onboarding `veracode.yml` (static-scan gating off; IaC policy findings and SCA errors still break builds). |
| `--set-teams-*` | Adds `teams:` to the policy and sandbox scan workflows, and switches the IaC/Secrets workflow to the Veracode CLI with `--app-name`, `--create-app` and `--teams` (RBAC). Add `--skip-iac-rbac` to leave the IaC workflow unchanged. |
| `--team-prefix` | Optional prefix on every team name. |
| `--create-teams` | Creates the team on the Veracode platform if it does not exist. |
| `--set-secrets` | Creates the SCA workspace and agent token per org and sets the three Veracode org secrets. |
| `--link-teams-to-workspaces` | Gives each team visibility of its org's SCA workspace results. |
| `--workers 5` | Parallel orgs. GitHub's write limits cap throughput at roughly 70 orgs per hour whatever the worker count. |

The script asks you to type `yes` before changing anything. If the run is interrupted, re-run the same command with `--continue`.

## Step 3: Install the app and verify

Org owners install `veracode-workflow-app` from the links in `out/manual_install_links.csv`. For a large enterprise, send each org owner their row.

Then verify:

```bash
python script.py --orgs-file rollout-orgs.txt --workers 5
```

An org is done when `audit_report_<timestamp>.json` shows the repo present, the app installed, `secrets.status` `all_exist`, and the actions allowlist `all_allowed` or `selected_ok`. The Step 2 report should show each team `created` or `already_exists` and each workspace link `linked` or `already_linked`.

## After onboarding

| Situation | What to run |
| --- | --- |
| New orgs were added to the enterprise | Run Step 1 again, put **only the new orgs** in a file, and apply with that file. Re-running `--set-secrets` on onboarded orgs regenerates their agent tokens. |
| Repos look wrong | `--fix-repos` (dry run first). Cannot be combined with `--import-repo`. |
| Turn on build gating | `--apply --update-veracode-yml my-veracode.yml` |
| Annual credential rotation | New `VERACODE_SA_API_ID`/`VERACODE_SA_API_KEY`, then `--apply --orgs-file rollout-orgs.txt --set-secrets` |

If something fails, keep `out/audit_report_<timestamp>.json`, the command you ran, and whether you are on GitHub.com or GHES.
