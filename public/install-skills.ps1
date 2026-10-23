[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Arguments = @()
)

$ErrorActionPreference = "Stop"
# Invoke-WebRequest otherwise draws a progress bar that can stall noninteractive hosts.
$ProgressPreference = "SilentlyContinue"

$RepoOwner = if ($env:GRCLANKER_REPO_OWNER) { $env:GRCLANKER_REPO_OWNER } else { "ethanolivertroy" }
$RepoName = if ($env:GRCLANKER_REPO_NAME) { $env:GRCLANKER_REPO_NAME } else { "grclanker" }
$Ref = if ($env:GRCLANKER_REF) { $env:GRCLANKER_REF } else { "main" }
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

# No published checksum covers SKILL.md, and the default ref is a moving branch,
# so check that the download is the grclanker skill before replacing anything.
function Test-GrclankerSkill([string]$Path) {
  $Lines = @(Get-Content -LiteralPath $Path)
  if ($Lines.Count -eq 0 -or $Lines[0] -cne "---") {
    return $false
  }
  $Named = $false
  for ($i = 1; $i -lt $Lines.Count; $i += 1) {
    if ($Lines[$i] -ceq "---") {
      return $Named
    }
    if ($Lines[$i] -ceq "name: grclanker") {
      $Named = $true
    }
  }
  return $false
}

$CreatedTargetDir = -not (Test-Path -LiteralPath $TargetDir)
# .NET does not understand PowerShell drive paths, so give it the provider path.
$TargetRoot = (New-Item -ItemType Directory -Force -Path $TargetDir).FullName
$SkillPath = Join-Path $TargetRoot "SKILL.md"

# File.Replace cannot replace a directory, so refuse before downloading.
if (Test-Path -LiteralPath $SkillPath -PathType Container) {
  throw "$SkillPath is a directory, so nothing was changed."
}

# Download beside the installed skill, since File.Replace needs both files on one volume.
do {
  $Download = Join-Path $TargetRoot (".SKILL.md." + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
} while (Test-Path -LiteralPath $Download)

$Installed = $false
try {
  try {
    $Response = Invoke-WebRequest -Uri $RawUrl -OutFile $Download -PassThru -UseBasicParsing
  } catch {
    throw "Could not download $RawUrl, so nothing was changed. $($_.Exception.Message)"
  }
  # Windows PowerShell 5.1 keeps a download that was cut off and reports no error.
  $ExpectedLength = "$($Response.Headers['Content-Length'])"
  $DownloadLength = (Get-Item -Force -LiteralPath $Download).Length
  if ($ExpectedLength -match '^\d+$' -and $DownloadLength -ne [long]$ExpectedLength) {
    throw "Could not download $RawUrl, so nothing was changed. Got $DownloadLength of $ExpectedLength bytes."
  }
  if (-not (Test-GrclankerSkill $Download)) {
    throw "$RawUrl did not return a grclanker SKILL.md, so nothing was changed."
  }
  if (Test-Path -LiteralPath $SkillPath) {
    [System.IO.File]::Replace($Download, $SkillPath, [NullString]::Value)
  } else {
    [System.IO.File]::Move($Download, $SkillPath)
  }
  $Installed = $true
} finally {
  if (Test-Path -LiteralPath $Download) {
    Remove-Item -Force -LiteralPath $Download -ErrorAction SilentlyContinue
  }
  # A failed first install should not leave an empty skill directory behind.
  if (-not $Installed -and $CreatedTargetDir -and -not (Get-ChildItem -LiteralPath $TargetRoot -Force)) {
    Remove-Item -Force -LiteralPath $TargetRoot -ErrorAction SilentlyContinue
  }
}

# Remove downloads that an interrupted earlier run left behind.
foreach ($Leftover in @(Get-ChildItem -LiteralPath $TargetRoot -Force -File | Where-Object { $_.Name -cmatch '^\.SKILL\.md\.[0-9a-f]{8}$' })) {
  try {
    Remove-Item -Force -LiteralPath $Leftover.FullName
  } catch {
    Write-Warning "Could not remove $($Leftover.FullName): $($_.Exception.Message)"
  }
}

Write-Host ""
Write-Host "Installed grclanker skill into $TargetDir" -ForegroundColor Green
Write-Host "Use it when you need CMVP, KEV, EPSS, or framework-mapped GRC analysis."
Write-Host ""
