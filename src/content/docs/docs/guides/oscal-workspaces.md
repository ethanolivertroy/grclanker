---
title: OSCAL Workspaces
description: Set up a compliance-trestle workspace, import a baseline, write control implementations in Markdown, and assemble a validated OSCAL system security plan.
---

The OSCAL tools drive [compliance-trestle](https://github.com/oscal-compass/compliance-trestle), the open-source `trestle` command line tool for [OSCAL](https://pages.nist.gov/OSCAL/) content. They work on a local folder of OSCAL JSON or YAML files, need no credentials, and upload nothing. Two tools check and set up the workspace, three manage models, and two turn a profile into editable Markdown and back into an OSCAL system security plan (SSP).

This guide follows one path from start to finish: install trestle, create a workspace, import the NIST SP 800-53 Rev5 moderate baseline, write the implementation for one control, then assemble and validate the SSP. The examples were run with compliance-trestle 5.2.0.

## Run it

Start `grclanker` and ask in plain words. The agent calls the matching tools:

```text
Is trestle installed, and is ./oscal-workspace a trestle workspace?
Create an OSCAL workspace in ./oscal-workspace.
Import the NIST SP 800-53 Rev5 moderate baseline into the workspace as nist-moderate.
Generate SSP markdown from the nist-moderate profile into ssp-md.
Assemble ssp-md into an SSP named acme-ssp, then validate it.
```

The [audit](/docs/workflows/audit/) and [assess](/docs/workflows/assess/) workflows call the same tools when the deliverable has to be OSCAL.

## Tools

| Tool | Behavior |
| --- | --- |
| `oscal_check_trestle` | Reports whether trestle runs, its version and path, and whether a directory is a trestle workspace, with a count of models by type. |
| `oscal_init_workspace` | Creates a trestle workspace. Running it on an existing workspace changes nothing. |
| `oscal_import_model` | Copies an OSCAL file or URL into the workspace under a name you choose and reports the model type it found. |
| `oscal_create_model` | Writes a starter model of any OSCAL type, such as an SSP or a POA&M. |
| `oscal_validate_model` | Validates one file, one named model, every model of a type, or the whole workspace. |
| `oscal_generate_ssp_markdown` | Writes one editable Markdown file per control from a profile and optional component definitions. |
| `oscal_assemble_ssp` | Reads that Markdown back and writes an OSCAL SSP into the workspace. |

Every tool except `oscal_check_trestle` and `oscal_init_workspace` needs an initialized workspace. Without one, it stops and asks you to run `oscal_init_workspace` first.

## Install trestle

The tools run the `trestle` executable and look for it in this order:

1. The path in `GRCLANKER_TRESTLE_BIN`
2. The path in `TRESTLE_BIN`
3. `trestle` on your `PATH`

Install compliance-trestle with pip. A virtual environment keeps it apart from the system Python:

```bash
python3 -m venv "$HOME/.venvs/trestle"
"$HOME/.venvs/trestle/bin/pip" install compliance-trestle
export GRCLANKER_TRESTLE_BIN="$HOME/.venvs/trestle/bin/trestle"
```

Then ask for a check:

```text
oscal_check_trestle {}
```

The check reports the trestle version, the executable it found, and whether the directory is a workspace, then suggests the next step. It looks at the directory you started `grclanker` in unless you pass `workspace_dir`.

## Create a workspace

```text
oscal_init_workspace {"workspace_dir":"./oscal-workspace","mode":"local"}
```

`workspace_dir` defaults to `./oscal-workspace`. Relative paths resolve from the directory you started `grclanker` in. The mode decides which folders trestle creates:

| `mode` | Creates |
| --- | --- |
| `local` | The `.trestle` marker folder and one source folder per model type. This is the default. |
| `full` | The same source folders, plus a `dist` folder that mirrors them for published output. |
| `govdocs` | Only the `.trestle` marker folder, for trestle's governed-documents features. |

Each model gets its own folder inside its type's folder, for example `system-security-plans/acme-ssp/system-security-plan.json`:

| Model type | Alias | Folder |
| --- | --- | --- |
| `catalog` | None | `catalogs` |
| `profile` | None | `profiles` |
| `component-definition` | `compdef`, `component` | `component-definitions` |
| `system-security-plan` | `ssp` | `system-security-plans` |
| `assessment-plan` | `sap` | `assessment-plans` |
| `assessment-results` | `sar` | `assessment-results` |
| `plan-of-action-and-milestones` | `poam` | `plan-of-action-and-milestones` |

Model type arguments ignore case and punctuation, so `POA&M` works as well as `poam`.

## Import a baseline

`oscal_import_model` copies an OSCAL file into the workspace. `file` takes an `https` URL or a local path, and `output` is the name the model gets. Trestle reads the model type from the content and files the model in the matching folder.

Import the NIST SP 800-53 Rev5 catalog first, then the moderate baseline profile that selects controls from it. Both come from NIST's [oscal-content](https://github.com/usnistgov/oscal-content) repository:

```text
oscal_import_model {"workspace_dir":"./oscal-workspace","file":"https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json","output":"nist-800-53-rev5"}
oscal_import_model {"workspace_dir":"./oscal-workspace","file":"https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json","output":"nist-moderate"}
```

For a local file, use an absolute path. Trestle runs inside the workspace, so a relative `file` path resolves from there, and trestle refuses to import a file that sits inside the workspace. Importing to a name that already exists fails rather than overwriting. Set `regenerate_uuids` to `true` when you import a second copy of content that is already in the workspace, so the UUIDs do not collide.

### Point the profile at the local catalog

The NIST profile finds its catalog through a relative link into NIST's repository layout. That path does not exist in your workspace, so Markdown generation fails with:

```text
Cache get failure for ../../../../nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json: [Errno 2] No such file or directory
```

Point the profile's import at the catalog you imported. Trestle resolves `trestle://` links from the workspace root:

```bash
cd oscal-workspace
jq '.profile.imports[0].href = "trestle://catalogs/nist-800-53-rev5/catalog.json"' \
  profiles/nist-moderate/profile.json > profile.tmp \
  && mv profile.tmp profiles/nist-moderate/profile.json
```

Any profile that imports its catalog through a relative path needs the same change. A profile that imports its catalog from an `https` URL works without it.

## Generate SSP Markdown

```text
oscal_generate_ssp_markdown {"workspace_dir":"./oscal-workspace","profile":"nist-moderate","output":"ssp-md"}
```

`profile` is the name of a profile in the workspace, or an href trestle can resolve. `output` names a folder inside the workspace. Trestle writes one Markdown file per control, with a folder for each control family. The moderate baseline produces 287 files in 18 folders, from `ac` to `sr`. Control enhancements get their own files, such as `ac/ac-2.1.md`.

Optional arguments:

| Argument | Effect |
| --- | --- |
| `component_definitions` | Adds implementation sections for the components in the named component definitions, which must already be in the workspace. |
| `leveraged_ssp` | Writes an `inheritance` folder showing what the system can inherit from a leveraged SSP. The control file count leaves that folder out. |
| `yaml_header` | Adds the contents of a YAML file to the header of every control file. A relative path resolves from the workspace. |
| `overwrite_header_values` | Lets `yaml_header` values replace values already in existing files. |
| `include_all_parts` | Writes every control part for the main This System component, not only the parts with rules. |
| `force_overwrite` | Replaces existing files with fresh templates and discards your edits. |

## Write control implementations

Open a control file, such as `ssp-md/ac/ac-2.md`. The control statement, assessment objectives, and guidance come from the profile and are there for reference. You write in two places: the parameter values in the YAML header, and the implementation section at the end of the file.

### Set parameter values

The header lists each organization-defined parameter under `x-trestle-set-params`. To set a value in the SSP, add an `ssp-values` list under the parameter. This sets the account review frequency in AC-2 item j:

```yaml
x-trestle-set-params:
  ac-02_odp.10:
    alt-identifier: ac-2_prm_10
    profile-values:
      - <REPLACE_ME>
    profile-param-value-origin: <REPLACE_ME>
    ssp-values:
      - at least quarterly
```

`profile-values` shows values the profile sets. The NIST baseline leaves them to the organization, so it shows `<REPLACE_ME>`.

### Write the narrative and status

Each file ends with an implementation section. Replace the comment under `### This System` with your narrative, and set the status line to `implemented`, `partial`, `planned`, `alternative`, or `not-applicable`. New files start at `planned`:

```markdown
### This System

Okta is the system of record for workforce accounts. Joiner, mover, and leaver events from the HR system drive provisioning, and account managers review every account at least quarterly.

#### Implementation Status: implemented
```

When a file lists rules under `### Rules:`, that list is read-only. Changes to it are not carried into the SSP.

### Regenerate without losing work

Rerun `oscal_generate_ssp_markdown` with the same `output` when the profile changes. Without `force_overwrite`, trestle keeps your narratives, statuses, and `ssp-values`. With `force_overwrite` set to `true`, every file goes back to its template and that work is gone, so commit or copy the folder first.

## Assemble the SSP

```text
oscal_assemble_ssp {"workspace_dir":"./oscal-workspace","markdown":"ssp-md","output":"acme-ssp"}
```

This writes `system-security-plans/acme-ssp/system-security-plan.json` with one implemented requirement per control, 287 for the moderate baseline. Each requirement carries its narrative and status, and every `ssp-values` list becomes a set parameter.

The first assembly fills the SSP title, version, system name, and system description with `REPLACE_ME`. Edit them in the JSON by hand, or with jq:

```bash
cd oscal-workspace/system-security-plans/acme-ssp
jq '.["system-security-plan"].metadata.title = "Acme Platform System Security Plan"
  | .["system-security-plan"]["system-characteristics"]["system-name"] = "Acme Platform"' \
  system-security-plan.json > ssp.tmp && mv ssp.tmp system-security-plan.json
```

Assembling into the same `output` again updates the control implementations and keeps those edits. Pass `version` to set the SSP's metadata version:

```text
oscal_assemble_ssp {"workspace_dir":"./oscal-workspace","markdown":"ssp-md","output":"acme-ssp","version":"0.1.0"}
```

More options:

- `source_ssp_name` starts from another SSP in the workspace and writes the result to `output`, leaving the source unchanged. Use it to cut a new SSP from a base you maintain.
- `component_definitions` merges the named component definitions. Pass the same list you gave the generator.
- `regenerate_uuids` gives the assembled SSP new UUIDs.

## Validate

```text
oscal_validate_model {"workspace_dir":"./oscal-workspace","model_type":"ssp","name":"acme-ssp"}
```

Pass one target. If you pass more than one, the first match in this table wins:

| Argument | Validates |
| --- | --- |
| `all` set to `true` | Every model in the workspace |
| `file` | One file or model folder, with relative paths resolved from the workspace |
| `model_type` and `name` | One named model |
| `model_type` alone | Every model of that type |

`quiet` defaults to `true`, which hides trestle's success messages. A failure returns trestle's own message, which names the file and the failing field, such as `metadata.title: required field is missing`.

Validation checks structure against the OSCAL schema. It does not check completeness: an SSP full of `REPLACE_ME` placeholders and `planned` statuses still passes. Search the SSP for `REPLACE_ME` before you share it.

## Start other models

`oscal_create_model` writes a starter model to fill in, such as a POA&M:

```text
oscal_create_model {"workspace_dir":"./oscal-workspace","model_type":"poam","name":"acme-poam"}
```

The file lands at `plan-of-action-and-milestones/acme-poam/plan-of-action-and-milestones.json`. It starts with a generic title, version `0.0.0`, and `REPLACE_ME` in required text fields. `format` takes `json`, the default, or `yaml`. Set `include_optional_fields` to `true` for a longer skeleton with every optional OSCAL field.

## Troubleshooting

- **"Trestle is not installed or not on PATH."** Install compliance-trestle, or set `GRCLANKER_TRESTLE_BIN` to the full path of the executable. `oscal_check_trestle` shows which executable it found.
- **"Workspace ... is not a trestle workspace yet" or "Workspace directory ... does not exist."** The directory is missing or has no `.trestle` folder. Run `oscal_init_workspace`, or point `workspace_dir` at the right folder. Relative paths resolve from the directory you started `grclanker` in.
- **"Cache get failure for ../../../../nist.gov/..."** The profile still points at NIST's repository layout. Apply the fix in [Point the profile at the local catalog](#point-the-profile-at-the-local-catalog).
- **"Imported file ... cannot be from current trestle project."** A relative `file` path resolved inside the workspace. Use an absolute path to a file outside the workspace.
- **"Cannot import because file to be imported here ... already exists."** A model with that name is already in the workspace. Choose another `output` name, or delete the old model folder.
- **"Unsupported OSCAL model type."** Use a type or alias from the table in [Create a workspace](#create-a-workspace).
- **"Choose a validation target."** Pass `file`, `model_type`, or `all` set to `true`.
- **Edits disappeared after regenerating.** `force_overwrite` was on. Restore the folder from version control or a copy, and leave the option off.

## Related

- [FedRAMP Readiness](/docs/guides/fedramp-readiness/) plans the artifacts a FedRAMP package needs.
- [SCF Crosswalks](/docs/guides/scf-crosswalks/) maps NIST SP 800-53 controls to other frameworks.
- [Configuration](/docs/getting-started/configuration/#environment-variables) lists `GRCLANKER_TRESTLE_BIN` with the other environment variables.
- The [compliance-trestle documentation](https://oscal-compass.dev/compliance-trestle/latest/) covers trestle's authoring workflow in depth.
