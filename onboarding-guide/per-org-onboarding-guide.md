# Veracode Bulk GitHub Integration: Per-Org Onboarding Guide

Use this guide when you are rolling out to **one org or a list of orgs you already know**. This is the recommended way for most teams: you only need to be an owner of the orgs you are onboarding, not of the whole GitHub Enterprise.

Onboarding is three steps:

1. **Dry run**: read-only check of your orgs, generates the files you fill in
2. **Onboarding run**: one apply with all onboarding flags
3. **App install and verify**: install the GitHub App, re-run the dry run to confirm

## Before you start

| Item | What it must be | Environment variable |
| --- | --- | --- |
| GitHub token | Personal access token (classic) with `admin:org`, `repo`, `workflow`. You must be an **owner** of every org in your list. | `GITHUB_TOKEN` |
| Veracode admin credentials | API ID/key of a **human user** with the **Administrator** role. Used by the script only, never stored in GitHub. | `VERACODE_API_ID`, `VERACODE_API_KEY` |
| Veracode service account | API ID/key of an API service account. Written to each org's Actions secrets and used by the workflows at scan time. | `VERACODE_SA_API_ID`, `VERACODE_SA_API_KEY` |
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

Also check:

- **SAML SSO:** if your orgs enforce SSO, authorize the token for each org (`Settings > Developer settings > Personal access tokens > Configure SSO`).
- **Region:** the integration is not supported in the Veracode United States Federal Region.
- **GHES:** add `--api-base https://HOST/api/v3 --web-base https://HOST` to every command.

## Your orgs file

`orgs.txt` has one org login per line. Lines starting with `#` are ignored. For a single org, the file has one line.

```
# Payments business unit
acme-payments
acme-payments-mobile
```

**Don't know your org list? Let the dry run build it.** Run a dry run with no `--orgs-file`:

```bash
python script.py
```

With no scope flag, the script lists every org your token's user is a member of and writes it to `out/orgs.txt`. It changes nothing. Then copy that file and trim it to the orgs you are onboarding:

```bash
cp out/orgs.txt orgs.txt
# edit orgs.txt: keep only the orgs you own and want to onboard now
```

Things to know:

- **Membership is not ownership.** The list includes every org you belong to, but you can only onboard orgs you **own**. Remove the rest.
- **Every dry run overwrites `out/orgs.txt`** with the orgs of that run. Never edit `out/orgs.txt` in place or point `--orgs-file` at it for your real list. Keep your edited copy outside `out/`, as `orgs.txt` above.
- **Never run the apply without `--orgs-file`.** Without it the apply falls back to every org you are a member of, not just the ones you picked.

Every command below uses `--orgs-file orgs.txt`, so the script only ever touches the orgs in your edited file.

## Step 1: Dry run

The dry run changes nothing. It checks each org and writes files to `out/`.

```bash
python script.py --orgs-file orgs.txt
```

| Output file | What to do with it |
| --- | --- |
| `teams_map.csv` | Fill in the `teams` column: the Veracode team for each org (only if you use `--set-teams-file`). |
| `missing_veracode_repo.csv` | Orgs that still need the `veracode` repo. Step 2 creates them. |
| `manual_install_links.csv` | Install link for each org missing the Veracode Workflow App. Used in Step 3. |
| `actions_allowlist_issues.csv` | Orgs whose Actions policy blocks the Veracode actions. Fix in `Settings > Actions > General` or scans will not run. |
| `audit_report_<timestamp>.json` | Full per-org state. |

### Choose how teams are named

Every org needs a Veracode team so scan results land with the right people. Pick **one** of these:

| Option | Use it when | Team name |
| --- | --- | --- |
| `--set-teams-auto` | Each org maps to one team named after the org. Simplest. | `acme-payments` |
| `--set-teams-file out/teams_map.csv` | Teams have their own names. Fill in `teams_map.csv`. Blank rows get no team. | Whatever you put in the CSV |
| `--set-teams-hybrid out/teams_map.csv` | Most orgs use the org name, a few need custom names. Blank rows fall back to the org name. | CSV value, or org name if blank |

Add `--team-prefix "gh-"` if your Veracode teams follow a naming convention (`acme-payments` becomes `gh-acme-payments`).

Example `teams_map.csv`:

```
"org","teams"
"acme-payments","payments-team"
"acme-payments-mobile","payments-team"
```

Use one team name per row. `--create-teams` and `--link-teams-to-workspaces` treat a comma-separated value as a single team name.

`teams_map.csv` is only generated when it does not exist yet. If it was created by the untrimmed dry run, it lists orgs you removed; those rows are ignored, because only orgs in `orgs.txt` are processed. If you later add orgs to `orgs.txt`, add their rows by hand or delete the file and re-run the dry run.

## Step 2: Onboarding run

Run one apply with all onboarding flags. The script asks you to type `yes` before changing anything.

```bash
python script.py --apply \
  --orgs-file orgs.txt \
  --import-repo \
  --set-teams-auto \
  --create-teams \
  --set-secrets \
  --link-teams-to-workspaces
```

Swap `--set-teams-auto` for `--set-teams-file out/teams_map.csv` or `--set-teams-hybrid out/teams_map.csv` if you chose that option. For more than a handful of orgs, add `--workers 3`.

### What each flag is for

| Flag | What it does | What goes wrong without it |
| --- | --- | --- |
| `--apply` | Turns on changes. Without it every run is a dry run. | Nothing is changed. |
| `--orgs-file orgs.txt` | Limits the run to the orgs in your file. | The script falls back to every org your token can see. |
| `--import-repo` | Creates the private `veracode` repo in each org, imports the Veracode workflow templates, sets `main` as default branch, adds the onboarding `veracode.yml` (build gating off). | No workflows exist, so nothing scans. |
| `--set-teams-auto` / `-file` / `-hybrid` | Adds `teams:` to the policy and sandbox scan workflows. | Scan results are not assigned to any team. |
| `--team-prefix PREFIX` | Optional prefix on every team name. | Teams are named exactly as the org or CSV value. |
| `--create-teams` | Creates each team on the Veracode platform if it does not exist yet. | Workflows point at teams that do not exist on the platform. |
| `--set-secrets` | Creates an SCA workspace and agent token per org, then sets `VERACODE_API_ID`, `VERACODE_API_KEY`, `VERACODE_AGENT_TOKEN` as org Actions secrets. | Scans fail: no credentials in the org. |
| `--link-teams-to-workspaces` | Adds each org's team to its SCA workspace. | SCA agent-based results are only visible to existing workspace members, not the team. |
| `--workers N` | Processes N orgs in parallel. 3 to 5 is the useful range. | One org at a time (fine for small lists). |

The script handles the order for you: the team is created before it is written into workflows, and the workspace exists before the team is linked to it.

## Step 3: Install the app and verify

The Veracode Workflow App cannot be installed through the API. An org owner opens each link in `out/manual_install_links.csv` and installs `veracode-workflow-app`.

Then re-run the dry run:

```bash
python script.py --orgs-file orgs.txt
```

An org is done when its entry in `audit_report_<timestamp>.json` shows:

- [ ] `veracode_repo.present`: `true`
- [ ] `workflow_app.installed`: `true`
- [ ] `secrets.status`: `all_exist`
- [ ] `actions_allowlist.status`: `all_allowed` or `selected_ok`
- [ ] `veracode_team_platform.action`: `created` or `already_exists` (Step 2 report)
- [ ] `veracode_team_workspace_link.action`: `linked` or `already_linked` (Step 2 report)

To prove it end to end, open an issue in any repo with the title `Veracode All Scans`.

## After onboarding

Every operation is safe to re-run. Keep the same `--orgs-file` and teams flag you used in Step 2.

| Situation | What to run |
| --- | --- |
| The run was interrupted | Same Step 2 command + `--continue` |
| Start from a specific org | Same Step 2 command + `--skip-to ORG` |
| Repos look wrong (default branch not `main`, missing `veracode.yml`, no `teams:`) | `--dry-run --fix-repos` to audit, then `--apply --fix-repos` with your teams flag. Cannot be combined with `--import-repo`. |
| Turn on build gating | `--apply --update-veracode-yml my-veracode.yml` with `break_build_policy_findings: true` and `break_build_invalid_policy: true` set in your file. The old file is kept as `default-veracode.yml`. |
| Annual credential rotation | Export the new `VERACODE_SA_API_ID`/`VERACODE_SA_API_KEY`, then `--apply --set-secrets`. This also regenerates the SCA agent token. |
| More orgs to onboard | Put **only the new orgs** in a new orgs file and repeat Steps 1 to 3. Re-running `--set-secrets` on already-onboarded orgs regenerates their agent tokens. |

If something fails, keep `out/audit_report_<timestamp>.json` and the exact command you ran.
