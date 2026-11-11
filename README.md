# Veracode Bulk GitHub Workflow Integration

`script.py` rolls out the [Veracode GitHub Workflow Integration](https://github.com/veracode/github-actions-integration) across many GitHub organizations. For each org it can create the `veracode` repo, assign Veracode teams to scan results, create Veracode teams, set Actions secrets and SCA workspaces, and link teams to workspaces. Every action is idempotent and logged to an audit report. The script resumes after interruption and can run orgs in parallel.

Step-by-step guides: [enterprise onboarding](onboarding-guide/enterprise-onboarding-guide.md) (`--enterprise`) and [per-org onboarding](onboarding-guide/per-org-onboarding-guide.md) (`--orgs-file`).

> Community tool, not officially supported by Veracode. Not supported in the Veracode US Federal Region.

-----

## Requirements

|Requirement|Needed for|
|---|---|
|Python 3.9+|Always|
|`pip install requests`|Always|
|`pip install veracode-api-signing`|`--create-teams`, `--set-secrets`, `--link-teams-to-workspaces`|
|`pip install pynacl`|`--set-secrets` (checked at startup)|
|`git` on `PATH`|`--import-repo`, and `--fix-repos` when it re-imports a broken repo|
|`veracode.yml` next to `script.py`|`--import-repo` (onboarding config; without it the repo is imported but the file is skipped) and `--fix-repos`|
|GitHub org owner rights|Installing the workflow app, org secrets, Actions policy|
|Veracode Administrator account|Veracode API flags (see [Credentials](#credentials))|

```bash
pip install requests veracode-api-signing pynacl
```

-----

## Quick Start

1. Run a dry run (read-only). It writes `out/orgs.txt`, `out/teams_map.csv` and the CSV reports.

   ```bash
   export GITHUB_TOKEN="..."
   python script.py --enterprise YOUR-ENTERPRISE
   ```

2. If teams are not simply the org names, fill in the `teams` column of `out/teams_map.csv`.

3. Apply. The script prints a summary and waits for you to type `yes`.

   ```bash
   export VERACODE_API_ID="admin_api_id"          # human Administrator account
   export VERACODE_API_KEY="admin_api_key"
   export VERACODE_SA_API_ID="service_account_api_id"
   export VERACODE_SA_API_KEY="service_account_api_key"

   python script.py --apply --enterprise YOUR-ENTERPRISE \
     --import-repo \
     --set-teams-file out/teams_map.csv \
     --create-teams \
     --set-secrets \
     --link-teams-to-workspaces
   ```

4. Install `veracode-workflow-app` in each org using `out/manual_install_links.csv`. The GitHub API cannot install third-party apps, so this step is manual.

5. Re-run the dry run to confirm. If the apply was interrupted, re-run the same command with `--continue`.

-----

## What Runs Per Org

1. **`--import-repo`**: creates the private `veracode` repo, mirror-imports `github.com/veracode/github-actions-integration`, sets `main` as the default branch as soon as it is visible, and adds the onboarding `veracode.yml`.
2. **`--create-teams`**: creates the Veracode team if it does not exist.
3. **`--set-teams-*`**: writes `teams:` into the policy and sandbox scan workflows and converts the IaC/Secrets workflow to the Veracode CLI with RBAC.
4. **`--set-secrets`**: creates or reuses the org's SCA workspace and agent, regenerates the agent token, and sets the `VERACODE_API_ID`, `VERACODE_API_KEY` and `VERACODE_AGENT_TOKEN` org secrets.
5. **`--link-teams-to-workspaces`**: adds the team to the org's SCA workspace.
6. **Always**: checks whether the app is installed and whether the Actions policy allows the required actions.

An import that finished after a timeout is detected on the next run (no `default-veracode.yml` yet), and the missing post-import steps run then.

-----

## Credentials

|Variable|Used for|Account|
|---|---|---|
|`GITHUB_TOKEN`|All GitHub calls. Use `--token-env NAME` to read another variable.|Classic PAT, see [GitHub token](#github-token)|
|`VERACODE_API_ID` / `VERACODE_API_KEY`|Script calls to Veracode APIs: teams, workspaces, agent tokens, links. Never stored in GitHub.|**Human user** with the **Administrator** role|
|`VERACODE_SA_API_ID` / `VERACODE_SA_API_KEY`|Stored as `VERACODE_API_ID` / `VERACODE_API_KEY` org secrets and used by workflows at scan time|API service account|

|Flag|Admin `VERACODE_API_*`|Service account `VERACODE_SA_API_*`|
|---|---|---|
|`--create-teams`|Required|-|
|`--set-secrets`|Required|Required|
|`--link-teams-to-workspaces`|Required|-|
|Everything else|-|-|

Missing required variables stop the run at startup. Credentials are also validated against GitHub and Veracode before any org is processed.

The admin pair must be a human Administrator account: SCA workspace and agent-token operations require it. The Identity API (`--create-teams`) alone would also accept an API service account with the Admin API role.

-----

## GitHub Token

Use a **classic personal access token**. The token's user must be an **owner** of each org.

|Scope|Needed for|Endpoints|
|---|---|---|
|`admin:org`|Always (includes `read:org`): secrets, Actions policy, app installation check, org details|`/orgs/{org}/actions/secrets/*`, `/orgs/{org}/actions/permissions*`, `/orgs/{org}/installations`, `/orgs/{org}`|
|`repo`|Always: read and create the `veracode` repo, write `veracode.yml`, set default branch, mirror push|`/orgs/{org}/repos`, `/repos/{org}/veracode/*`|
|`workflow`|Apply runs: writing `.github/workflows/*` (teams, IaC RBAC, import, `--fix-repos`). GitHub rejects the mirror push of workflow files without it.|`/repos/{org}/veracode/contents/.github/workflows/*`|
|`read:enterprise`|`--enterprise` discovery|GraphQL `enterprise { organizations }`|

If orgs enforce SAML SSO, authorize the token for each one (`Settings > Developer settings > Personal access tokens > Configure SSO`). Unauthorized orgs are hidden from discovery and reported in the [completeness check](#discovery).

-----

## Command-Line Reference

### Modes

|Flag|Behavior|
|---|---|
|`--dry-run` *(default)*|Read-only. Reports state and writes the output files.|
|`--apply`|Makes changes for the action flags given. Asks for `yes` unless `--continue` is set.|

### Action flags (need `--apply`, except `--fix-repos`)

|Flag|Description|
|---|---|
|`--import-repo`|Create and import the `veracode` repo. See [What Runs Per Org](#what-runs-per-org).|
|`--set-teams-auto`|Team = org name.|
|`--set-teams-file FILE`|Team from `teams_map.csv`; blank rows get no team.|
|`--set-teams-hybrid FILE`|Team from `teams_map.csv`; blank rows fall back to the org name.|
|`--team-prefix PREFIX`|Prepend `PREFIX` to every resolved team (`gh-` + `acme-dev` = `gh-acme-dev`). Orgs without a team are not affected.|
|`--skip-iac-rbac`|Leave the IaC/Secrets workflow unchanged. See [IaC/Secrets RBAC](#iacsecrets-rbac).|
|`--create-teams`|Create the resolved team on the Veracode platform. **Ignored without a `--set-teams-*` flag.**|
|`--set-secrets`|Set the three org secrets. Always overwrites them and regenerates the SCA agent token (`token:regenerate`), which invalidates the old one.|
|`--link-teams-to-workspaces`|Add the resolved team to the org's SCA workspace. **Rejected at startup without a `--set-teams-*` flag.**|
|`--update-veracode-yml [FILE]`|Push `veracode.yml` to every org, after backing up the current one as `default-veracode.yml`. Without `FILE`, fetches it from `raw.githubusercontent.com` (upstream integration repo).|
|`--fix-repos`|Audit (dry run) or repair (apply) already-imported repos. See [Fix Existing Repos](#fix-existing-repos).|

### Configuration flags

|Flag|Default|Description|
|---|---|---|
|`--enterprise SLUG`|-|Discover orgs from the enterprise (GraphQL).|
|`--orgs-file FILE`|-|One org per line, `#` comments allowed. Alone: the org list. With `--enterprise`: a filter.|
|`--api-base URL`|`$GITHUB_API_BASE` or `https://api.github.com`|GHES: `https://HOST/api/v3`|
|`--web-base URL`|`$GITHUB_WEB_BASE` or `https://github.com`|GHES: `https://HOST` (used for install links)|
|`--token-env NAME`|`GITHUB_TOKEN`|Environment variable that holds the PAT.|
|`--out DIR`|`out`|Output directory.|
|`--skip-to ORG`|-|Start at this org. Warns and processes all orgs if not found.|
|`--continue`|-|Resume from `out/checkpoint.json` and skip the confirmation prompt.|
|`--workers N`|`1`|Parallel orgs. Must be >= 1; above 10 prints a warning. See [Large Deployments](#large-deployments).|

**Mutually exclusive:**
- `--dry-run` and `--apply`
- `--set-teams-auto`, `--set-teams-file` and `--set-teams-hybrid`
- `--fix-repos` and `--import-repo`

-----

## Teams

The resolved team value (mode, then `--team-prefix`) is used for workflow injection, `--create-teams` and `--link-teams-to-workspaces`.

**`teams_map.csv`:**
- Columns are `org,teams`.
- The dry run only creates the file **if it does not exist**, so your edits are never overwritten. Delete it to regenerate it after the org list changes.
- It is a lookup table, not a scope filter: only orgs in the current run are processed.

```csv
org,teams
acme-dev,acme-developers
acme-ops,
```

**Workflow injection:**
- Writes `teams: "<value>"` into the `veracode/uploadandscan-action` step of `veracode-policy-scan.yml` and `veracode-sandbox-scan.yml`.
- Existing values are **updated** to the resolved value on every apply.
- Skipped for orgs with no resolved value (a blank row in file mode).

**Comma-separated values:** workflow injection and IaC RBAC pass all names through. `--create-teams` and `--link-teams-to-workspaces` treat the whole value as **one** team name. Use a single team per org if you use those flags.

### Platform Team Creation (`--create-teams`)

Searches `/api/authn/v2/teams` for an exact name match and creates the team if missing. Result: `created`, `already_exists` or `error`. Run it in the same apply as the `--set-teams-*` flag so the team exists before scans reference it.

### Link Teams to Workspaces (`--link-teams-to-workspaces`)

Grants the team visibility into the org's agent-based SCA workspace results. This is the API equivalent of **Manage Workspace > Teams > Add Teams**.

- Finds the workspace by **org name** and the team by the **resolved team value**. With `--team-prefix`, the team (`gh-acme-dev`) and the workspace (`acme-dev`) have different names, which is expected.
- Creates neither. A missing workspace is reported as `workspace_not_found` (run `--set-secrets` first); a missing team as `team_not_found`.
- In the same run as `--create-teams` and `--set-secrets`, it reuses their IDs without extra lookups.
- Summary line: `Team<->Workspace: 142 linked, 11 already linked, 3 failed (of 156 orgs)`.

### IaC/Secrets RBAC

The upstream `veracode-iac-secrets-scan.yml` uses `veracode/container_iac_secrets_scanning`, which cannot link results to an application profile. Without that link, IaC and container results are visible only to Security Leads.

With a `--set-teams-*` flag (and without `--skip-iac-rbac`), the script replaces that step in each org's `veracode` repo with a Veracode CLI step:

```bash
veracode scan --source ./ --type directory ... \
  --app-name "<profile name>" --create-app --teams "<teams>"
```

|Option|Value|
|---|---|
|`--app-name`|The profile the static and SCA scans use (`profile_name`, default `<org>/<repo>`).|
|`--create-app`|Creates the profile on the first scan. If the profile exists, links the results to it.|
|`--teams`|Resolved team value with spaces around commas removed. Stored in the step as `VERACODE_TEAMS: "<teams>"` and updated on every apply.|

**Kept from the action:**
- The latest CLI is installed from `tools.veracode.com` on every run, so runners need access to it.
- The IaC policy is applied.
- `break_build_policy_findings` and `break_build_on_error` are honored.
- `results.json`, `results.txt` and the SBOMs are uploaded as the `Veracode Container IaC Secrets Scanning Results` artifact. Upload errors never fail the job.

**Requires Veracode CLI 2.55.0+.** The step fails with an explicit error on older versions.

**Idempotent:**
- Converted files carry a `# veracode-iac-rbac` marker; later runs only update `VERACODE_TEAMS`.
- If the action step is not found (customized workflow), the file is left unchanged and the log says so.
- A `--fix-repos` re-import restores the action, and the same run converts it again.

**Veracode prerequisites** (from Veracode's *Role-based access control for container and IaC Security* doc):
- The teams exist (`--create-teams`).
- The service account behind the org's `VERACODE_API_ID` secret:
  - has the Upload and Scan API or Upload API - Submit Only role and the `createApplicationProfile` permission;
  - is a member of the teams it assigns.
- Results appear under **Container & IaC Analysis**, not in the application profile view.

> **Pilot first:** convert one org with `--orgs-file`, run the IaC scan, and confirm that the team sees the findings before rolling out.

-----

## veracode.yml

`--import-repo` (and `--fix-repos` without `--update-veracode-yml`) pushes the `veracode.yml` next to the script. Build gating per section in that file:

|Section|`break_build_policy_findings`|`break_build_invalid_policy`|`break_build_on_error`|
|---|---|---|---|
|`veracode_static_scan` (policy `Veracode Recommended Medium + SCA`)|`false`|`false`|`false`|
|`veracode_sca_scan`|-|-|**`true`**|
|`veracode_iac_secrets_scan`|**`true`**|-|`false`|

> IaC policy findings and SCA scan errors **do break builds** with this file. Edit it before `--import-repo` if onboarding should not gate at all.

To change the configuration across all orgs later (policy, triggers, enable static gating):

```bash
# Upstream veracode.yml (from raw.githubusercontent.com)
python script.py --apply --enterprise YOUR-ENTERPRISE --update-veracode-yml

# Custom file
python script.py --apply --enterprise YOUR-ENTERPRISE --update-veracode-yml /path/to/veracode.yml
```

The current file is kept as `default-veracode.yml`. Orgs without an imported repo are skipped and counted in the summary.

-----

## Fix Existing Repos

`--fix-repos` covers already-imported repos only. Use `--import-repo` for orgs whose `veracode` repo is missing or empty.

|Check|Repair (with `--apply`)|
|---|---|
|Default branch|Sets `main`.|
|`veracode.yml`|Adds it if missing (from `--update-veracode-yml` if given, otherwise the local `veracode.yml`). With `--update-veracode-yml`, also replaces an existing file (backup in `default-veracode.yml`).|
|Teams (with a `--set-teams-*` flag)|Injects/updates `teams:` and converts the IaC workflow (unless `--skip-iac-rbac`).|
|Broken import (no `main`, or both policy and sandbox workflows missing)|Re-imports from upstream (needs `git`), then runs the checks above.|

```bash
python script.py --dry-run --fix-repos --enterprise YOUR-ENTERPRISE    # audit
python script.py --apply --fix-repos --enterprise YOUR-ENTERPRISE \
  --set-teams-auto --update-veracode-yml /path/to/veracode.yml       # repair
```

-----

## Discovery

The org list is resolved in this order:
1. **`--enterprise`**: GraphQL, filtered by `--orgs-file` if given.
2. **`--orgs-file`**: used as the org list.
3. **Neither**: `/user/orgs` (all orgs the token can see).

**GraphQL timeouts** (GitHub returns `502`/`504` after 10 s):
- A timed-out page is retried from the same cursor with the page size halved (100, 50, 25, 12, 6, 5).
- After 8 consecutive failures the run stops with an explicit error.
- Orgs hidden from the token are skipped with a warning.
- On GHES the endpoint `https://HOST/api/graphql` is derived from `--api-base`.

**Completeness check:** the script compares the orgs it received with the enterprise's `totalCount`. A match prints `[OK] Discovery verified complete: N orgs == totalCount N`. Otherwise it warns and continues. Possible causes:
- `totalCount` missing or changed during the run
- visible + hidden orgs not equal to `totalCount`
- duplicate orgs
- orgs hidden by SAML SSO

Before an apply, review `out/orgs.txt` and pass it with `--orgs-file` (without `--enterprise`) if the warning appears.

-----

## Actions Allowlist Check

On every run the script reads `/orgs/{org}/actions/permissions` and warns (never blocks) when the required actions are not allowed:

|Org policy|Result|
|---|---|
|`all`|OK|
|`local_only`|Flagged: Veracode actions are blocked.|
|`selected`|Each required pattern is checked against `patterns_allowed`. `actions/*` passes when `github_owned_allowed` is true.|

Flagged orgs go to `actions_allowlist_issues.csv`. Without `admin:org` the status is `no_permission`. Fix in `Settings > Actions > General`.

-----

## Large Deployments

```bash
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets \
  --link-teams-to-workspaces --workers 5

# After an interruption: same command plus --continue
```

**Checkpoint and resume:**
- `out/checkpoint.json` is written after each org.
- `--continue` skips completed orgs (including from parallel runs) and restarts an interrupted org from the beginning.
- `--skip-to ORG` starts at an org without a checkpoint.

**Workers:**

|Workers|Use|
|---|---|
|`1`|Default, sequential, easiest logs.|
|`3`|Safe start.|
|`5`|Large enterprises (100+ orgs). More workers mostly wait on the shared write budget.|
|`10`|Practical maximum.|

**Rate limits:** the binding limit is GitHub's content-creation budget. A full apply averages about 6-7 writes per org, about 70 orgs/hour at any worker count. A global limiter shared by all workers keeps every window below GitHub's limits:

|Window|GitHub limit|Script target|
|---|---|---|
|Primary requests|5,000/hour|4,000/hour|
|Content-creating writes|80/min, 500/hour|60/min, 400/hour|
|REST secondary points|900/min|720/min|
|GraphQL secondary points|2,000/min|1,600/min|
|Concurrent requests|100|50|
|Veracode REST|500/min per IP|200/min|

Veracode calls (`api.veracode.com`) do not count against the GitHub budget. With several workers, log lines arrive out of order. The `[N/TOTAL]` prefix shows the submission order, and the report has one entry per org.

-----

## Output Files

All files are written to `--out` (default `out/`).

|File|Content|
|---|---|
|`orgs.txt`|Discovered orgs. Rewritten on dry runs; on apply only if missing.|
|`teams_map.csv`|`org,teams` template. Only created if missing.|
|`audit_report_<timestamp>.json`|Per-org results (see below).|
|`missing_veracode_repo.csv`|Orgs without the `veracode` repo.|
|`missing_workflow_app.csv`|Orgs without the workflow app.|
|`manual_install_links.csv`|App install URL per org that needs it.|
|`actions_allowlist_issues.csv`|Orgs whose Actions policy blocks required actions, with the missing patterns.|
|`checkpoint.json`|Resume state for `--continue`.|

The audit report is written as JSON Lines during the run (crash-safe) and converted to a JSON array at the end. Example entry:

```json
{
  "org": "acme-dev",
  "veracode_repo": {"present": true, "status": "repo_created_and_imported", "import_method": "git_cli_auto",
                    "default_branch_action": "set_to_main", "veracode_yml_injected": "created"},
  "veracode_team_platform": {"team_name": "gh-acme-dev", "team_id": "7336556f-...", "action": "created"},
  "teams_injection": {"success": true, "action": "teams_updated_3_files", "value": "gh-acme-dev",
                      "files": {"veracode-sandbox-scan.yml": "teams_updated", "veracode-policy-scan.yml": "teams_updated",
                                "veracode-iac-secrets-scan.yml": "converted"}},
  "workflow_app": {"installed": true, "status": "already_installed", "installation_id": 12345678},
  "actions_allowlist": {"status": "selected_missing", "missing": ["veracode/veracode-sca@*"],
                        "detail": "1 required action(s) not allowlisted"},
  "veracode_yml_update": {"success": true, "action": "updated_with_backup"},
  "secrets": {"status": "set", "results": {"VERACODE_API_ID": "set", "VERACODE_API_KEY": "set", "VERACODE_AGENT_TOKEN": "set"}},
  "veracode_team_workspace_link": {"workspace": "acme-dev", "team_name": "gh-acme-dev", "action": "linked"}
}
```

|Field|Values|
|---|---|
|`veracode_repo.status`|`repo_exists`, `repo_exists_post_import_incomplete` (self-healed this run), `repo_created_and_imported`, `repo_created_import_incomplete` (`main` not visible yet), `repo_created_manual_import_required`, `missing`|
|`veracode_repo.default_branch_action`|`already_main`, `set_to_main`, `branch_not_found`, `failed`|
|`teams_injection.action`|`teams_updated_<N>_files`, `teams_already_current`, `no_workflow_files_found`, `repo_not_ready`, `error:<msg>`|
|`teams_injection.files.<file>`|`converted` (IaC only), `teams_updated`, `already_current`, `action_step_not_found`, `not_found`, `failed:<status>`, `error:<msg>`|
|`veracode_team_platform.action`|`created`, `already_exists`, `error`|
|`veracode_team_workspace_link.action`|`linked`, `already_linked`, `workspace_not_found`, `team_not_found`, `error`|
|`veracode_yml_update.action`|`updated_with_backup`, `created`, `repo_not_found`, `repo_empty`, `put_failed:<status>`|
|`actions_allowlist.status`|`all_allowed`, `selected_ok`, `local_only`, `selected_missing`, `no_permission`, `error`|
|`secrets.status` (dry run)|`all_exist`, `all_missing`, `partial`, `no_permission`|
|`fix_repos.reimport_action`|`not_needed`, `would_reimport`, `reimported`, `git_not_available`, `reimport_main_not_visible`, `failed:<msg>`|

-----

## GitHub Enterprise Server

```bash
python script.py --apply --enterprise your-enterprise-slug \
  --api-base https://github.company.com/api/v3 \
  --web-base https://github.company.com \
  --import-repo --set-teams-file out/teams_map.csv --create-teams \
  --set-secrets --link-teams-to-workspaces
```

**Outbound access needed from the machine running the script:**
- `github.com` for `--import-repo`, which clones the upstream template. Without it, mirror the template internally or create the repos manually.
- `raw.githubusercontent.com` for `--update-veracode-yml` without `FILE`.
- `api.veracode.com` for `--create-teams`, `--set-secrets` and `--link-teams-to-workspaces`.

-----

## Troubleshooting

|Symptom|Fix|
|---|---|
|`ERROR: Set GITHUB_TOKEN environment variable.`|Export the token, or point `--token-env` at the variable that holds it.|
|`GitHub token is invalid or expired` / `lacks required permissions`|Check the [token scopes](#github-token) and SSO authorization.|
|`--set-secrets requires pynacl`|`pip install pynacl`|
|`--set-secrets requires VERACODE_SA_API_ID and VERACODE_SA_API_KEY`|Export the service account pair.|
|`--link-teams-to-workspaces requires a teams mode`|Add a `--set-teams-*` flag.|
|No teams created although `--create-teams` was set|Add a `--set-teams-*` flag; without one `--create-teams` is ignored.|
|Discovery completeness warning|Review `out/orgs.txt` and run with `--orgs-file`.|
|`workspace_not_found`|Run `--set-secrets` first, or create the workspace (named after the org).|
|`409 conflict after retry` / `protected branch`|A branch protection rule on `veracode/main` blocks direct pushes. Apply the change through a PR or relax the rule.|
|`action_step_not_found` for the IaC workflow|The workflow was customized. Convert it manually or re-import with `--fix-repos`.|
|IaC scan fails: `Veracode CLI ... Version 2.55.0 or later is required`|The runner got an old CLI. Check runner access to `tools.veracode.com`.|
|Team cannot see IaC results|Check the team is assigned to the profile and the user is in the team. Results are under **Container & IaC Analysis**.|

-----

## Security Notes

- Default mode is read-only. Every change needs `--apply` and a typed `yes` (or `--continue`).
- Admin Veracode credentials are only used for API calls and never stored in GitHub.
- Service account credentials are encrypted with the org's Actions public key (libsodium sealed box) before being written as secrets.
- Agent tokens are unique per org and regenerated on each `--set-secrets` run.
- Linking a team to a workspace grants that team read access to the workspace's SCA results. No credentials are written.
- All credentials come from environment variables.

For issues, include `out/audit_report_<timestamp>.json`, the platform (GitHub.com, GHEC or GHES) and the command used.
