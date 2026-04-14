---
title: grclanker Docs
description: Start with the bundle installer, run setup, pick local-first or hosted, then use grclanker against real GRC work and repo specs.
---

`grclanker` is an experimental open source AI GRC companion built on top of Pi.

The current release starts with CMVP, KEV, EPSS, official FedRAMP GitHub-grounded 20x and Rev5 lookups, FedRAMP readiness, ADS package planning, starter-bundle generation, portable public trust-center site generation, posture mapping, Vanta audit export, SCF lookups, trestle-backed OSCAL helpers, and spec-driven build inputs, but that is the opening surface, not the ceiling. The real flow is short:

1. Install the companion.
2. Run `grclanker setup`.
3. Choose local-first or hosted.
4. Start using the current workflows and point the companion at repo specs when you want it to build.

## Start Here

- [Installation](/docs/getting-started/installation/) is the main operator page. It covers the bundle installer, skills-only install, pinned versions, package-manager fallback, and the immediate post-install setup path.
- [Setup](/docs/getting-started/setup/) goes deeper on the local-first Ollama + Gemma 4 path and the hosted alternative.
- [Configuration](/docs/getting-started/configuration/) documents `~/.grclanker/agent/settings.json`, `models.json`, and runtime state.
- [Compute Backends](/docs/getting-started/compute-backends/) documents `host`, `sandbox-runtime`, Docker, and Parallels configuration plus validation commands.
- [Quick Start](/docs/getting-started/quick-start/) is still available if you just want the shortest install → setup → first useful question sequence.

## Default Recommendation

If you want the path that best matches the current product direction:

1. Install with the one-line bundle.
2. Run `grclanker setup`.
3. Choose `local-first`.
4. Point the companion at Ollama on `http://localhost:11434/v1`.
5. Use `gemma4` as the first local model unless you already know you want a different local backend.

## Current Release Surface

- `/investigate` for crypto status, KEV exposure, EPSS likelihood, and ransomware linkage.
- `/audit` for framework mapping and control classification.
- `/assess` for posture readouts, risk order, and confidence notes.
- `/validate` for narrow FIPS validation questions.
- Official FedRAMP FRMR-backed lookups and generated docs under [`/docs/fedramp/`](/docs/fedramp/).
- `fedramp_assess_readiness` when you want an operator-facing brief for a FedRAMP process or KSI instead of raw lookup data.
- `fedramp_plan_process_artifacts` and `fedramp_plan_ads_package` when you need a concrete trust-center and evidence rollout plan instead of another lookup.
- `fedramp_generate_ads_bundle` when you want grclanker to scaffold an ADS starter package you can actually start filling in.
- `fedramp_generate_ads_site` when you want a portable public trust-center site bundle customers can deploy in their own AWS, Azure, or GCP environment.
- Repo specs as build inputs under [`/specs`](/specs) and [`/docs/specs/using-specs-as-inputs/`](/docs/specs/using-specs-as-inputs/).

## Important Release Note

`0.0.1` is experimental on purpose. The bundle installer and local-first runtime path are real. The feature surface, setup flow, and docs structure will keep moving quickly.

macOS and Linux are the recommended platforms right now. Windows is best-effort and not a priority for the first experimental release.
