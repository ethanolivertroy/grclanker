[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Arguments = @()
)

$ErrorActionPreference = "Stop"

$RepoOwner = if ($env:GRCLANKER_REPO_OWNER) { $env:GRCLANKER_REPO_OWNER } else { "ethanolivertroy" }
$RepoName = if ($env:GRCLANKER_REPO_NAME) { $env:GRCLANKER_REPO_NAME } else { "grclanker" }
$DefaultReleaseVersion = if ($env:GRCLANKER_RELEASE_VERSION) { $env:GRCLANKER_RELEASE_VERSION } else { "0.0.1" }
$Ref = if ($env:GRCLANKER_REF) { $env:GRCLANKER_REF } else { "v$DefaultReleaseVersion" }
$Version = if ($env:GRCLANKER_VERSION) { $env:GRCLANKER_VERSION } else { $null }
$SkillUrlOverride = $env:GRCLANKER_SKILL_URL
$Scope = "user"

for ($i = 0; $i -lt $Arguments.Count; $i += 1) {
  $arg = $Arguments[$i]

  switch -Exact ($arg) {
    "--repo" { $Scope = "repo"; continue }
    "--user" { $Scope = "user"; continue }
    "-Scope" {
      if ($i + 1 -ge $Arguments.Count) {
        throw "Missing value for -Scope. Use User or Repo."
      }
      $i += 1
      $Scope = $Arguments[$i].ToLowerInvariant()
      continue
    }
    "--scope" {
      if ($i + 1 -ge $Arguments.Count) {
        throw "Missing value for --scope. Use user or repo."
      }
      $i += 1
      $Scope = $Arguments[$i].ToLowerInvariant()
      continue
    }
    "-Version" {
      if ($i + 1 -ge $Arguments.Count) {
        throw "Missing value for -Version."
      }
      $i += 1
      $Version = $Arguments[$i]
      continue
    }
    "--version" {
      if ($i + 1 -ge $Arguments.Count) {
        throw "Missing value for --version."
      }
      $i += 1
      $Version = $Arguments[$i]
      continue
    }
    default {
      if (-not $Version) {
        $Version = $arg
        continue
      }

      throw "Usage: install-skills.ps1 [-Version <version>] [-Scope User|Repo] or install-skills.ps1 [latest|<version>] [--user|--repo]"
    }
  }
}

if ($Scope -ne "user" -and $Scope -ne "repo") {
  throw "Invalid scope '$Scope'. Use User or Repo."
}

if ($Version -and $Version -ne "latest") {
  $Ref = "v" + ($Version -replace "^v", "")
}

if ($Scope -eq "repo") {
  $TargetDir = Join-Path (Get-Location) ".agents\skills\grclanker"
} else {
  $TargetDir = Join-Path $HOME ".codex\skills\grclanker"
}

if ($SkillUrlOverride) {
  $RawUrl = $SkillUrlOverride
} else {
  $RawUrl = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Ref/skills/grclanker/SKILL.md"
}

New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
Invoke-WebRequest -Uri $RawUrl -OutFile (Join-Path $TargetDir "SKILL.md")

Write-Host ""
Write-Host "Installed grclanker skill into $TargetDir" -ForegroundColor Green
Write-Host "Use it when you need CMVP, KEV, EPSS, or framework-mapped GRC analysis."
Write-Host ""
