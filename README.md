# Veracode Bulk GitHub Workflow Integration

Deploys Veracode security scanning across GitHub Enterprise organizations at scale. Handles repository creation, workflow configuration, team assignments, Veracode platform team provisioning, team-to-workspace linking, app installation, and secrets management with audit trails, checkpoint/resume support, and parallel execution.

-----

## How It Works

For each organization, the script can:

1. Create the `veracode` integration repository and mirror-import the Veracode workflow template
1. Inject a customized `veracode.yml` onboarding configuration
1. Create teams on the Veracode platform via the Identity API (if they do not already exist)
1. Inject `teams:` parameter into workflow files, and switch the IaC/Secrets workflow to the Veracode CLI with role-based access control (app profile + teams)
1. Create a Veracode SCA workspace, generate a unique agent token, and set GitHub Actions secrets
1. Link each org's team to its SCA workspace so the team can see scan results (`--link-teams-to-workspaces`)

All operations are idempotent, safe to re-run. If a repo import completes after the script times out, the next run detects the incomplete state via the absence of `default-veracode.yml` and automatically applies the missing post-import steps.

During import, the script verifies that `main` is set as the default branch immediately after the branch becomes visible. This prevents issues where GitHub sets a different default (e.g. `master`) when the source repo uses a different primary branch name.

> **App installation is manual.** The script checks whether `veracode-workflow-app` is installed per org and generates `manual_install_links.csv` with a direct install URL for each org that needs it. Automated installation via the GitHub API is not supported for third-party apps.

-----

## Prerequisites

Before relying on scan results, confirm the following. The script prints these as a reminder on every run and auto-checks the items marked below.

**Auto-checked per org (warn-only):** the GitHub Actions allowlist permits the Veracode actions the integration needs. Problem orgs are written to `actions_allowlist_issues.csv`. See [Actions Allowlist Check](#actions-allowlist-check).

**Confirm manually:**

- GitHub: organization owner or admin permissions to install third-party apps.
- Veracode Platform: the Administrator or Security Lead role.
- Veracode Platform: valid API credentials (static scans) and/or a valid SCA agent token (agent-based SCA scans).
- The Veracode GitHub Workflow Integration is **not supported** in the United States Federal Region.

-----

## Modes

|Mode   |Flag       |Behavior                                                           |
|-------|-----------|-------------------------------------------------------------------|
|Dry-run|*(default)*|Read-only. Reports current state and generates helper output files.|
|Apply  |`--apply`  |Makes changes. Requires one or more action flags.                  |

-----

## Quickstart

### Phase 1 - Dry-run

```bash
export GITHUB_TOKEN="..."

python script.py --enterprise YOUR-ENTERPRISE
```

Discovers all orgs, checks current state, and writes output files to `./out/`:

- `orgs.txt` - one org per line
- `teams_map.csv` - fill in the `teams` column before apply
- `missing_veracode_repo.csv`, `missing_workflow_app.csv`, `manual_install_links.csv`, `actions_allowlist_issues.csv`

### Phase 2 - Apply

```bash
export GITHUB_TOKEN="..."
export VERACODE_API_ID="admin_api_id"
export VERACODE_API_KEY="admin_api_key"
export VERACODE_SA_API_ID="service_account_api_id"
export VERACODE_SA_API_KEY="service_account_api_key"

python script.py --apply \
  --enterprise YOUR-ENTERPRISE \
  --import-repo \
  --set-teams-file out/teams_map.csv \
  --create-teams \
  --set-secrets \
  --link-teams-to-workspaces
```

### Phase 3 - Fix existing repos (compensatory pass)

For already-imported repos that may have landed with the wrong default branch, missing `veracode.yml`, or teams not injected, use `--fix-repos` to audit and remediate without re-importing. See [Fix Existing Repos](#fix-existing-repos).

```bash
# Audit only
python script.py --dry-run --fix-repos --enterprise YOUR-ENTERPRISE

# Remediate
python script.py --apply --fix-repos --enterprise YOUR-ENTERPRISE \
  --set-teams-auto --update-veracode-yml /path/to/veracode.yml
```

-----

## Requirements

```bash
pip install requests
pip install veracode-api-signing
pip install pynacl    # required for --set-secrets
git --version         # required for --import-repo
```

Python 3.8+

-----

## Credentials

### Veracode Credentials

Two credential pairs serve different purposes:

|Variable             |Purpose                                                                                            |Account Type                                          |
|---------------------|---------------------------------------------------------------------------------------------------|------------------------------------------------------|
|`VERACODE_API_ID`    |Admin - used by the script to call Veracode APIs (create workspaces, generate tokens, create teams, link teams to workspaces)|**Human user account** with the **Administrator** role|
|`VERACODE_API_KEY`   |Admin                                                                                              |Same as above                                         |
|`VERACODE_SA_API_ID` |Service account - stored as `VERACODE_API_ID` in each org's Actions secrets                        |API service account                                   |
|`VERACODE_SA_API_KEY`|Service account - stored as `VERACODE_API_KEY` in each org's Actions secrets                       |API service account                                   |

**Important:** The admin credentials (`VERACODE_API_ID` / `VERACODE_API_KEY`) must belong to a **human user account** with the **Administrator** role on the Veracode platform. API service accounts do not have sufficient permissions for the Identity API operations used by `--create-teams` and `--set-secrets`. The Identity API requires either a human user with the Administrator role or an API service account with the Admin API role, but workspace and agent token operations require a human administrator.

Admin credentials are never stored in any org. Service account credentials are what gets deployed to orgs and used by workflows at scan time.

### Which flags need which credentials

|Flag                          |Requires `VERACODE_API_ID/KEY`|Requires `VERACODE_SA_API_ID/KEY`|
|------------------------------|------------------------------|---------------------------------|
|`--create-teams`              |Yes                           |No                               |
|`--set-secrets`               |Yes                           |Yes                              |
|`--link-teams-to-workspaces`  |Yes                           |No                               |
|`--import-repo`               |No                            |No                               |
|`--set-teams-*`               |No                            |No                               |
|`--update-veracode-yml`       |No                            |No                               |
|`--fix-repos`                 |No                            |No                               |

-----

## GitHub Token Permissions

Use a **personal access token (classic)**. The scopes below are classic PAT scopes.

### Minimum scopes

|Run type                                   |Scopes                                                        |
|-------------------------------------------|--------------------------------------------------------------|
|Dry-run                                    |`admin:org`, `repo`, + `read:enterprise` if using `--enterprise`|
|Apply, any combination of flags            |`admin:org`, `repo`, `workflow`, + `read:enterprise` if using `--enterprise`|

**Full rollout with all flags:** `admin:org`, `repo`, `workflow`, `read:enterprise`

`read:org` is not needed separately: `admin:org` includes it.

### Why each scope is needed

|Scope            |Used for                                                                                          |Endpoints                                                                                                   |
|-----------------|--------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
|`read:enterprise`|Org discovery with `--enterprise`                                                                 |GraphQL `enterprise { organizations }`                                                                      |
|`admin:org`      |Secret status and `--set-secrets`; Actions allowlist check; app installation check; org details  |`/orgs/{org}/actions/secrets/*`, `/orgs/{org}/actions/permissions*`, `/orgs/{org}/installations`, `/orgs/{org}`|
|`repo`           |Reading and creating the private `veracode` repo, writing `veracode.yml`, setting the default branch, `git push --mirror` |`/orgs/{org}/repos`, `/repos/{org}/veracode/*`                                                              |
|`workflow`       |Writing files under `.github/workflows` (teams injection, import, `--fix-repos`); GitHub rejects the mirror push of workflow files without it |`/repos/{org}/veracode/contents/.github/workflows/*`, `git push --mirror`                                   |

### Other requirements

- **SAML SSO:** if orgs enforce SAML SSO, authorize the token for each one (`Settings > Developer settings > Personal access tokens > Configure SSO`). Orgs the token is not authorized for are hidden during discovery and reported in the discovery completeness warning.
- **Role:** the token's user must be an **owner** of each org. GitHub requires org owner for the app installation list and full org details, and in practice org secrets and Actions policy need admin rights too.

-----

## Command-Line Reference

### Action Flags *(require `--apply`)*

|Flag                          |Description                                                                                                                                                                                                                                                                                                                                                                                |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`--import-repo`               |Create and populate the `veracode` repository. Sets `main` as the default branch immediately after import. Cannot be combined with `--fix-repos` in the same run.                                                                                                                                                                                                                          |
|`--set-teams-auto`            |Inject `teams: "<org-name>"` for every org                                                                                                                                                                                                                                                                                                                                                 |
|`--set-teams-file FILE`       |Inject per-org team values from `teams_map.csv`. Blank rows are skipped.                                                                                                                                                                                                                                                                                                                   |
|`--set-teams-hybrid FILE`     |Same as `--set-teams-file` but blank rows fall back to the org name                                                                                                                                                                                                                                                                                                                        |
|`--team-prefix PREFIX`        |Prepend `PREFIX` to every resolved teams value. Applied after `--set-teams-auto/file/hybrid`. Example: `--team-prefix "gh-"` turns `acme-dev` into `gh-acme-dev`. Orgs with no resolved teams value (blank file row on the `--set-teams-file FILE` option) are not affected.                                                                                                               |
|`--skip-iac-rbac`             |Leave the IaC/Secrets workflow untouched. By default, `--set-teams-*` (and `--fix-repos` with a teams mode) convert it to the Veracode CLI with RBAC. See [IaC/Secrets RBAC](#iacsecrets-rbac).|
|`--create-teams`              |Create teams on the Veracode platform via the Identity API if they do not already exist. Uses the resolved teams value from `--set-teams-auto/file/hybrid` (after prefix). Requires `VERACODE_API_ID` and `VERACODE_API_KEY`. Must be combined with one of the `--set-teams-*` flags. See [Platform Team Creation](#platform-team-creation).                                               |
|`--set-secrets`               |Set `VERACODE_API_ID`, `VERACODE_API_KEY`, `VERACODE_AGENT_TOKEN` per org. Always overwrites all three - safe to re-run for annual credential rotation. The SCA agent token is regenerated via `token:regenerate` on each run, invalidating the previous one.                                                                                                                              |
|`--link-teams-to-workspaces`  |Associate each org's team with its SCA workspace so the team can see scan results. Resolves the workspace by org name and the team by the resolved teams value (after prefix); creates neither. Requires Admin `VERACODE_API_ID` and `VERACODE_API_KEY` and one of the `--set-teams-*` flags. Composes with `--create-teams` and `--set-secrets`. See [Link Teams to Workspaces](#link-teams-to-workspaces).|
|`--update-veracode-yml [FILE]`|Push a `veracode.yml` to the `veracode` repo in every org. By default fetches `veracode.yml` directly from the upstream integration repo (`github.com/veracode/github-actions-integration`). Pass a local `FILE` path to use a custom file instead. The current file is backed up as `default-veracode.yml` first. Orgs with a missing or not-yet-imported repo are skipped with a warning.|
|`--fix-repos`                 |Compensatory pass for already-imported repos. See [Fix Existing Repos](#fix-existing-repos). Cannot be combined with `--import-repo` in the same run.                                                                                                                                                                                                                                      |

### Configuration

|Flag               |Default                 |Description                                                                                                                                                 |
|-------------------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`--enterprise SLUG`|-                       |GitHub Enterprise slug for org discovery                                                                                                                    |
|`--orgs-file FILE` |-                       |Plain text file, one org per line, `#` for comments. Used directly as the org scope when provided alone; used as a filter when combined with `--enterprise`.|
|`--api-base URL`   |`https://api.github.com`|Override for GHES                                                                                                                                           |
|`--web-base URL`   |`https://github.com`    |Override for GHES                                                                                                                                           |
|`--out DIR`        |`./out`                 |Output directory                                                                                                                                            |
|`--skip-to ORG`    |-                       |Skip all orgs before this one                                                                                                                               |
|`--continue`       |-                       |Resume from last checkpoint                                                                                                                                 |
|`--workers N`      |`1`                     |Number of parallel worker threads. See [Parallel Execution](#parallel-execution).                                                                           |

-----

## Actions Allowlist Check

The integration only runs if your org's GitHub Actions policy permits the actions the workflows call. On every run the script checks each org's policy (`/orgs/{org}/actions/permissions`) and warns, without blocking, when required actions are not allowed:

- **`all`** - everything permitted, passes.
- **`local_only`** - third-party Veracode actions are blocked; flagged.
- **`selected`** - the required patterns are verified against `patterns_allowed` (GitHub-owned `actions/*` are covered by the `github_owned_allowed` flag). Any missing pattern is flagged.

Flagged orgs and their missing patterns are written to `actions_allowlist_issues.csv`. Without `admin:org` the policy cannot be read and orgs are reported as `no_permission`. To fix an org, set its Actions policy to allow all actions, or add the required patterns to the selected-actions allowlist (`Settings > Actions > General`).

-----

## Fix Existing Repos

`--fix-repos` operates on already-imported repos only (skips orgs where the `veracode` repo is missing or empty - use `--import-repo` for those). For each qualifying org it checks and remediates:

1. **Default branch** - sets `main` as default if it is not already
1. **`veracode.yml`** - adds or updates the file if missing (uses `--update-veracode-yml FILE` if provided, otherwise falls back to the local `veracode.yml` next to the script)
1. **Teams injection** - injects or updates `teams:` in workflow files if a `--set-teams-*` flag is active, and converts the IaC/Secrets workflow to the Veracode CLI with RBAC (unless `--skip-iac-rbac`)

If `main` does not exist, or both workflow files are missing on `main`, the repo is treated as a broken import and is **re-imported from upstream** (in apply mode), after which the default branch is set and the steps above run. Compatible with `--dry-run` to audit without making changes. Cannot be combined with `--import-repo` in the same run.

`default_branch_action` values in the audit report: `already_main`, `set_to_main`, `branch_not_found`, `failed`. `reimport_action` values: `not_needed`, `would_reimport` (dry-run), `reimported`, `git_not_available`, `reimport_main_not_visible`, `failed:<message>`.

-----

## Platform Team Creation

The `--create-teams` flag provisions teams on the Veracode platform before injecting the `teams:` parameter into workflow files. This ensures that the team referenced in scan workflows actually exists on the platform when scans run.

The script uses the Veracode Identity REST API (`/api/authn/v2/teams`) to:

1. Search all teams in the org for an exact name match
1. Create the team if it does not exist
1. Record the result (created, already_exists, or error) in the audit report

The operation is idempotent. Re-running with the same team names is safe and will report `already_exists` for teams that were previously created.

### Credential requirements

`--create-teams` requires the `VERACODE_API_ID` and `VERACODE_API_KEY` environment variables. These credentials must belong to a **human user account** with the **Administrator** role on the Veracode platform. The Identity API team creation endpoint requires this level of access.

### Usage

`--create-teams` must be combined with one of the `--set-teams-*` flags so the script knows which team name to create for each org.

```bash
# Create teams using the org name
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-auto --create-teams

# Create teams from CSV, with prefix
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-file out/teams_map.csv --team-prefix "gh-" --create-teams

# Full rollout: repo + platform teams + workflow injection + secrets + workspace link
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo \
  --set-teams-auto --create-teams \
  --set-secrets \
  --link-teams-to-workspaces
```

-----

## Link Teams to Workspaces

The `--link-teams-to-workspaces` flag associates each org's Veracode team with its agent-based SCA workspace. By default, scan results in an agent-based workspace are visible only to members of that workspace; adding a team grants that team visibility into the results. This is the SCA REST API equivalent of the platform's **Software Composition Analysis > Agent-Based Scan > Manage Workspace > Teams > Add Teams** action.

The flag creates neither the workspace nor the team. It resolves:

- the **workspace** by org name (the same name `--set-secrets` uses when creating it)
- the **team** by the resolved teams value, after `--team-prefix` (the same name `--create-teams` uses)

then issues an idempotent association. Re-running is safe and reports `already_linked` for teams already on the workspace.

### Credential requirements

Requires `VERACODE_API_ID` and `VERACODE_API_KEY` (human user account with the Administrator role). It does not use the service account credentials. Must be combined with one of the `--set-teams-*` flags so the script knows which team name to resolve per org. Running it with no teams mode active is rejected at startup.

### How it composes

- **In the full chain** (`--create-teams` and `--set-secrets` in the same run), the team and workspace IDs created earlier in the run are reused directly, so the link step makes no extra lookups.
- **Run alone**, the link step resolves both IDs by name. The workspace must already exist, from a prior `--set-secrets` run or manual creation, otherwise the org is reported as `workspace_not_found`. A missing team is reported as `team_not_found`.

The link step calls the Veracode SCA API only, so it does not count against GitHub's content-creation rate limit. See [Parallel Execution](#parallel-execution).

### Usage

```bash
# Full chain: create team, create workspace + secrets, then link them
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-auto --create-teams --set-secrets --link-teams-to-workspaces

# Link only, against workspaces and teams that already exist
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-file out/teams_map.csv --team-prefix "gh-" --link-teams-to-workspaces
```

`veracode_team_workspace_link.action` values: `linked`, `already_linked`, `workspace_not_found`, `team_not_found`, `error`.

The execution summary prints a `Team<->Workspace` line when the flag is active:

```
Team<->Workspace: 142 linked, 11 already linked, 3 failed (of 156 orgs)
```

> **Note:** The team name and the workspace name are resolved independently, the team from the resolved teams value (after prefix) and the workspace from the org name. If you use `--team-prefix`, the team is `gh-acme-dev` while the workspace remains `acme-dev`; the link step handles this correctly because it looks each up by its own name.

-----

## Team Injection

The `teams` parameter maps to Veracode Platform teams that receive scan results. It is injected into both `veracode-policy-scan.yml` and `veracode-sandbox-scan.yml`:

```yaml
- uses: veracode/uploadandscan-action@v0.1.6
  with:
    teams: "security,devops"
```

Three modes are available:

- **`--set-teams-auto`** - uses the org name for every org, no configuration needed
- **`--set-teams-file`** - reads from `teams_map.csv`, skips blank rows
- **`--set-teams-hybrid`** - reads from `teams_map.csv`, falls back to org name for blank rows

Use `--team-prefix PREFIX` with any mode to prepend a fixed string to every resolved value. The prefix is applied after mode resolution, so it works identically across all three modes. Orgs that produce no teams value (blank row in file mode) are skipped and the prefix is not applied to them.

```bash
# Results in teams: "gh-acme-dev"
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-auto --team-prefix "gh-"

# Results in teams: "security-<value-from-csv>"
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --set-teams-file out/teams_map.csv --team-prefix "security-"
```

`teams_map.csv` is generated automatically on every dry-run. Fill in the `teams` column (comma-separated names accepted) and pass it back on apply. Files that already have `teams:` are left unchanged.

The teams map is a lookup table, not a scope filter. Only orgs that are being processed (determined by `--enterprise`, `--orgs-file`, or `/user/orgs`) will be touched. If your orgs file has 1 org and your teams map has 100 entries, only the 1 org gets processed using its matching entry from the map if one exists.

> **Tip:** Combine `--set-teams-*` with `--create-teams` to ensure the team exists on the Veracode platform before it is referenced in workflow files. Without `--create-teams`, you are responsible for creating teams on the platform manually or through other automation before scans run.

> **Tip:** Add `--link-teams-to-workspaces` alongside `--create-teams` and `--set-secrets` to grant the team visibility into its SCA workspace results in the same run. Without it, agent-based scan results stay visible only to existing workspace members until you add teams manually. See [Link Teams to Workspaces](#link-teams-to-workspaces).

> **Note on comma-separated values:** A `teams` value may contain multiple comma-separated names for workflow injection. `--create-teams` and `--link-teams-to-workspaces` treat the whole value as a single team name (matching the existing team-creation behavior); they do not split it into separate teams. Use single team names per org if you rely on platform team creation or workspace linking.

### IaC/Secrets RBAC

The upstream `veracode-iac-secrets-scan.yml` runs the `veracode/container_iac_secrets_scanning` action, which cannot link results to an application profile. Without that link, container and IaC results are visible only to Security Leads.

When a `--set-teams-*` mode is active (and `--skip-iac-rbac` is not set), the script replaces that action step in each org's `veracode` repo with a Veracode CLI step that runs:

```bash
veracode scan --source ./ --type directory ... \
  --app-name "<profile name>" --create-app --teams "<teams>"
```

- `--app-name` is the same application profile the static and SCA scans use (`profile_name`, default `<org>/<repo>`), so IaC findings are linked to the same profile.
- `--teams` is the resolved teams value (after `--team-prefix`), with spaces around commas removed as the CLI requires. It is stored in the step as `VERACODE_TEAMS: "<teams>"` and kept in sync on re-runs.
- `--create-app` creates the profile on the first scan if it does not exist yet.

Everything else matches the action: the latest CLI is installed from `tools.veracode.com` on every run, the IaC policy is downloaded and applied, `break_build_policy_findings` and `break_build_on_error` are honored, and `results.json`, `results.txt` and the SBOM files are uploaded as the `Veracode Container IaC Secrets Scanning Results` artifact. The step stops with a clear error if the installed CLI is older than 2.55.0, the first version with RBAC for container and IaC scans.

The conversion is idempotent. The script recognizes converted files by the `# veracode-iac-rbac` marker and then only updates `VERACODE_TEAMS`. If the action step is not found (for example, a customized workflow), the file is left unchanged and the run log says so. A re-import from upstream (`--fix-repos`) restores the action; the same run converts it again.

Prerequisites on the Veracode side (see Veracode's *Role-based access control for container and IaC Security* page):

- The teams must exist on the platform (`--create-teams`).
- The API credentials in the org's `VERACODE_API_ID`/`VERACODE_API_KEY` secrets need the Upload and Scan API or Upload API - Submit Only role and the `createApplicationProfile` permission. To create a profile assigned to teams, the account must be a member of those teams.
- Container and IaC results appear under **Container & IaC Analysis** in the Veracode Platform, not in the application profile section.

> **Pilot first:** run the conversion on one org with `--orgs-file`, trigger an IaC scan twice (first run creates the profile, second run uses the existing one), and confirm that the team can see the findings before rolling out widely.

-----

## veracode.yml Configuration

The injected `veracode.yml` is pre-configured for onboarding with build gating disabled:

```yaml
analysis_on_platform: true
break_build_policy_findings: false
break_build_invalid_policy: false
break_build_on_error: false
policy: 'Veracode Recommended Medium + SCA'
issues:
  trigger: true
  commands:
    - "Veracode All Scans"
```

Once onboarding is complete, re-enable gating by setting `break_build_policy_findings: true` and `break_build_invalid_policy: true`.

### Bulk veracode.yml Update

To push a new `veracode.yml` to all orgs after initial onboarding, for example to update the policy name, change scan triggers, or enable build gating across the fleet:

```bash
# Fetch veracode.yml from the upstream integration repo (default)
python script.py --apply --enterprise YOUR-ENTERPRISE --update-veracode-yml

# Use a custom local file instead
python script.py --apply --enterprise YOUR-ENTERPRISE --update-veracode-yml /path/to/veracode.yml
```

With no file argument the script fetches `veracode.yml` directly from `github.com/veracode/github-actions-integration` at runtime, so it always pulls the latest upstream version without needing a local copy. Pass a local file path when you want to deploy a customized configuration.

The current `veracode.yml` in each repo is preserved as `default-veracode.yml` before being overwritten. Orgs whose `veracode` repo is missing or not yet imported are skipped with a warning and counted separately in the summary.

`--update-veracode-yml` is optional and independent of the other flags. It only appears in the mode header, per-org log line, and execution summary when it is actively used.

-----

## Credential Rotation

`--set-secrets` always overwrites all three secrets unconditionally, so re-running it with new credentials is all that is needed for annual rotation:

```bash
export GITHUB_TOKEN="..."
export VERACODE_API_ID="admin_api_id"
export VERACODE_API_KEY="admin_api_key"
export VERACODE_SA_API_ID="new_service_account_api_id"
export VERACODE_SA_API_KEY="new_service_account_api_key"

python script.py --apply --enterprise YOUR-ENTERPRISE --set-secrets
```

The SCA agent token (`VERACODE_AGENT_TOKEN`) is also rotated as part of this - the script calls `token:regenerate` on the existing agent for each org, which invalidates the old token and returns a fresh one.

-----

## Organization Discovery

The script resolves orgs in this order:

1. **`--enterprise SLUG`** - GraphQL enterprise API (requires `read:enterprise`). If `--orgs-file` is also provided, the file is used to filter the enterprise org list down to only the listed orgs.
1. **`--orgs-file FILE`** - explicit list used directly as the org scope, one org per line.
1. **No flags** - falls back to `/user/orgs` (all orgs accessible to the token).

### Large enterprises and GraphQL timeouts

GitHub terminates any GraphQL request that takes more than 10 seconds and returns `502`/`504` ("We couldn't respond to your request in time"), and timeouts cost extra rate-limit points. Enterprise discovery is cursor-paginated and handles this:

- A timed-out page is retried **from the same cursor** with the page size halved (100, 50, 25, 12, 6, 5), so already-fetched orgs are never lost.
- Up to 8 consecutive attempts per page with backoff; after that the run stops with an explicit error (not the "wrong slug" message). Use `--orgs-file` to bypass discovery if GitHub stays degraded.
- Orgs GitHub hides from the token (typically SAML SSO not authorized for the PAT) are skipped with a warning instead of failing discovery.
- On GHES the GraphQL endpoint is `https://HOST/api/graphql`, derived automatically from `--api-base https://HOST/api/v3`.

### Discovery completeness check

After paginating, the script compares what it received with GitHub's own `organizations.totalCount` for the enterprise. If everything matches it prints `[OK] Discovery verified complete: N orgs == totalCount N`. Otherwise it prints a warning and continues with the orgs it found. The warning lists the cause:

- `totalCount` missing, or changed between the first and last page (orgs added or removed mid-run)
- visible + hidden orgs does not equal `totalCount`
- an org appeared twice (the list shifted during pagination)
- orgs hidden from the token (usually SAML SSO not authorized for the PAT); these are not processed

If you see this warning before an apply run, re-run discovery or review `out/orgs.txt` and pass it with `--orgs-file` (without `--enterprise`).

-----

## Output Files

|File                           |Description                                                                 |
|-------------------------------|----------------------------------------------------------------------------|
|`orgs.txt`                     |All discovered orgs, one per line                                           |
|`teams_map.csv`                |Org list with blank `teams` column - fill in and pass to `--set-teams-file` |
|`audit_report_<timestamp>.json`|Per-org result log, written incrementally (crash-safe)                      |
|`missing_veracode_repo.csv`    |Orgs missing the `veracode` repository                                      |
|`missing_workflow_app.csv`     |Orgs missing the workflow app                                               |
|`manual_install_links.csv`     |App install URLs for orgs that require manual installation                  |
|`actions_allowlist_issues.csv` |Orgs whose Actions policy blocks required actions, with the missing patterns|

### Audit Report Example

```json
{
  "org": "acme-dev",
  "veracode_repo": {
    "present": true,
    "status": "repo_created_and_imported",
    "import_method": "git_cli_auto",
    "default_branch_action": "set_to_main",
    "veracode_yml_injected": "created"
  },
  "veracode_team_platform": {
    "team_name": "gh-acme-dev",
    "team_id": "7336556f-9ef2-4a1c-b536-be8608822db6",
    "action": "created"
  },
  "teams_injection": {
    "success": true,
    "action": "teams_updated_3_files",
    "value": "gh-acme-dev",
    "files": {
      "veracode-sandbox-scan.yml": "teams_updated",
      "veracode-policy-scan.yml": "teams_updated",
      "veracode-iac-secrets-scan.yml": "converted"
    }
  },
  "workflow_app": {
    "installed": true,
    "status": "already_installed",
    "installation_id": 12345678
  },
  "actions_allowlist": {
    "status": "selected_missing",
    "missing": ["veracode/veracode-sca@*"],
    "detail": "1 required action(s) not allowlisted"
  },
  "veracode_yml_update": {
    "success": true,
    "action": "updated_with_backup"
  },
  "secrets": {
    "status": "set",
    "results": {
      "VERACODE_API_ID": "set",
      "VERACODE_API_KEY": "set",
      "VERACODE_AGENT_TOKEN": "set"
    }
  },
  "veracode_team_workspace_link": {
    "workspace": "acme-dev",
    "team_name": "gh-acme-dev",
    "action": "linked"
  }
}
```

`veracode_team_platform.action` values: `already_exists`, `created`, `error`.

`veracode_team_workspace_link.action` values: `linked`, `already_linked`, `workspace_not_found`, `team_not_found`, `error`.

`veracode_yml_update.action` values: `updated_with_backup`, `created`, `repo_not_found`, `repo_empty`, `put_failed:<status_code>`.

`veracode_repo.status` values: `repo_exists`, `repo_exists_post_import_incomplete` (imported but post-import steps never ran - self-healed on this run), `repo_created_and_imported`, `repo_created_import_incomplete` (push succeeded but main branch not found yet), `repo_created_manual_import_required`, `missing`.

`veracode_repo.default_branch_action` values: `already_main`, `set_to_main`, `branch_not_found`, `failed`.

`actions_allowlist.status` values: `all_allowed`, `selected_ok`, `local_only`, `selected_missing`, `no_permission`, `error`.

`secrets.status` values in dry-run: `all_exist`, `all_missing`, `partial`, `no_permission` (token lacks `admin:org` scope).

-----

## Platform Notes

### GitHub Enterprise Cloud (GHEC)

All features supported.

```bash
python script.py --apply --import-repo --set-teams-auto --create-teams \
  --set-secrets --link-teams-to-workspaces \
  --enterprise your-enterprise-slug
```

### GitHub Enterprise Server (GHES)

```bash
python script.py --apply --import-repo --set-teams-file out/teams_map.csv --create-teams \
  --set-secrets --link-teams-to-workspaces \
  --enterprise your-enterprise-slug \
  --api-base https://github.company.com/api/v3 \
  --web-base https://github.company.com
```

Differences from GHEC:

- **Outbound access to github.com required for `--import-repo`** - the script clones from `github.com/veracode/github-actions-integration` and pushes to your GHES instance. If outbound access is blocked, mirror the template repo internally first or pre-populate the `veracode` repos manually.
- **Outbound access to `api.veracode.com` required** for `--create-teams`, `--set-secrets`, and `--link-teams-to-workspaces`, regardless of the GHES endpoint. These steps always call the Veracode platform, not your GHES instance.

-----

## Large Deployments

For deployments across many orgs, use `--continue` to resume after interruption:

```bash
# Initial run
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets --link-teams-to-workspaces

# Resume after interruption
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets --link-teams-to-workspaces --continue
```

Checkpoint state is saved to `out/checkpoint.json` after each org completes. If the script is interrupted mid-org, `--continue` restarts from that org so nothing is skipped. All operations are idempotent so re-running a completed org is safe. The `--continue` flag also skips the confirmation prompt - confirmation was already given on the initial run.

Use `--skip-to ORG` to jump to a specific org without needing a checkpoint file.

For large enterprises, combine `--workers` with `--continue` to maximize throughput with crash recovery. See [Parallel Execution](#parallel-execution).

-----

## Parallel Execution

By default the script processes one org at a time. Use `--workers N` to process multiple orgs concurrently using a thread pool. All API calls are I/O-bound, so threading provides real throughput gains with no additional processes or dependencies.

```bash
# Dry-run across 200 orgs using 5 parallel workers
python script.py --dry-run --enterprise YOUR-ENTERPRISE --workers 5

# Apply with 5 workers - fastest safe setting for most token budgets
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets \
  --link-teams-to-workspaces --workers 5
```

### Choosing a worker count

|Workers|Use case                                                                                                                                  |
|-------|------------------------------------------------------------------------------------------------------------------------------------------|
|`1`    |Default. Sequential. Easiest to read logs.                                                                                                |
|`3`    |Safe starting point for most deployments.                                                                                                 |
|`5`    |Recommended for large enterprises (100+ orgs). Above this, additional workers stall waiting on the shared write budget.                   |
|`10`   |Maximum recommended. The global rate limiter still keeps the run within GitHub's limits, but extra concurrency yields diminishing returns.|

The binding constraint is not raw request throughput but GitHub's **content-creation secondary limit**: 80 writes per minute and 500 writes per hour per token. A full apply run averages ~6-7 writes per org (workflow file PUTs, secrets, default branch PATCH, etc.), so peak sustained throughput is ~70 orgs/hour regardless of worker count. The script's global rate limiter paces all workers to stay safely below this ceiling. Veracode API calls (team creation, workspace and token operations, team-to-workspace linking) go to `api.veracode.com` and do not count against the GitHub write budget.

### Rate limit behavior with parallel workers

The script enforces a global, multi-dimensional rate limiter shared across all workers, each dimension capped at a safety margin below GitHub's documented limit. Limits per [GitHub's REST rate limit docs](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

|Window                            |GitHub limit          |Script's safe target|
|----------------------------------|----------------------|--------------------|
|Primary hourly requests           |5,000/hour            |**4,000/hour** (80%)|
|Content-creating writes per minute|80/min                |**60/min** (75%)    |
|Content-creating writes per hour  |500/hour              |**400/hour** (80%)  |
|REST secondary points per minute  |900/min per endpoint  |**720/min** (80%)   |
|GraphQL secondary points per minute|2,000/min            |**1,600/min** (80%) |
|Concurrent in-flight requests     |100 (REST + GraphQL)  |**50** (50%)        |
|Veracode REST requests per minute |500/min per IP        |**200/min**         |

### Checkpoint compatibility

`--workers` is fully compatible with `--continue`. The checkpoint file records all completed orgs as a list alongside the latest processed org. On resume, the org list is replayed from the checkpoint position regardless of the order workers originally completed them.

```bash
# Initial parallel run
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets \
  --link-teams-to-workspaces --workers 5

# Resume after interruption, keeping the same worker count
python script.py --apply --enterprise YOUR-ENTERPRISE \
  --import-repo --set-teams-auto --create-teams --set-secrets \
  --link-teams-to-workspaces --workers 5 --continue
```

### Log output with multiple workers

Per-org log lines are printed atomically but may arrive out of order relative to the org list (this is expected). The `[N/TOTAL]` progress prefix on each line shows the submission order. The audit report always contains one entry per org regardless of completion order.

-----

## Security Notes

- Veracode admin credentials are used only for API calls and never stored anywhere
- Admin credentials must belong to a human user account with the Administrator role
- Service account credentials are encrypted via GitHub's public key API before being written to secrets
- Agent tokens are unique per organization and regenerated on each `--set-secrets` run
- Linking a team to a workspace grants that team visibility into the workspace's SCA scan results; no credentials are written to the org as part of this step
- All credentials are passed via environment variables and never hardcoded in source
- Default mode is read-only; all changes require explicit `--apply`

-----

## Support

Supported platforms: GitHub.com, GitHub Enterprise Cloud, GitHub Enterprise Server

For issues, provide `out/audit_report_<timestamp>.json`, your platform type, and the command used.

> This is a community tool and is not officially supported by Veracode.
