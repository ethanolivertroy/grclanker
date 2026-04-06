param(
  [string]$Version
)

$ErrorActionPreference = "Stop"

$RepoOwner = if ($env:GRCLANKER_REPO_OWNER) { $env:GRCLANKER_REPO_OWNER } else { "ethanolivertroy" }
$RepoName = if ($env:GRCLANKER_REPO_NAME) { $env:GRCLANKER_REPO_NAME } else { "grclanker" }
$Version = if ($Version) { $Version } elseif ($env:GRCLANKER_VERSION) { $env:GRCLANKER_VERSION } else { "latest" }
$InstallDir = if ($env:GRCLANKER_INSTALL_DIR) { $env:GRCLANKER_INSTALL_DIR } else { Join-Path $HOME ".local\share\grclanker" }
$BinDir = if ($env:GRCLANKER_BIN_DIR) { $env:GRCLANKER_BIN_DIR } else { Join-Path $HOME ".local\bin" }
$AssetUrlOverride = $env:GRCLANKER_ASSET_URL
$ReleaseBaseUrl = $env:GRCLANKER_RELEASE_BASE_URL
$TargetOverride = $env:GRCLANKER_INSTALL_TARGET
$AssetSourcePath = $null

if ($args.Count -gt 1) {
  throw "Usage: install.ps1 [-Version <version>] or install.ps1 [latest|<version>]"
}

if ($args.Count -eq 1 -and -not $PSBoundParameters.ContainsKey("Version")) {
  $Version = $args[0]
}

function Write-Info([string]$Message) {
  Write-Host "  -> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
  Write-Host "  ok $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
  Write-Host "  !! $Message" -ForegroundColor Yellow
}

function Normalize-Version([string]$Value) {
  if ($Value.StartsWith("v")) {
    return $Value.Substring(1)
  }
  return $Value
}

function Get-LocalCliVersion {
  $candidates = @()

  if ($PSScriptRoot) {
    $candidates += (Join-Path (Split-Path $PSScriptRoot -Parent) "cli\package.json")
  }

  $candidates += (Join-Path (Get-Location) "cli\package.json")

  foreach ($candidate in $candidates) {
    if (-not (Test-Path $candidate)) {
      continue
    }

    $json = Get-Content -Raw -Path $candidate | ConvertFrom-Json
    if ($json.version) {
      return $json.version
    }
  }

  return $null
}

function Find-LocalAsset([string]$Target, [string]$ArchiveExt, [string]$VersionFilter = "latest") {
  $searchDirs = @()
  $preferredVersion = $null

  if ($PSScriptRoot) {
    $searchDirs += (Join-Path (Split-Path $PSScriptRoot -Parent) "cli\release")
  }

  $searchDirs += (Join-Path (Get-Location) "cli\release")

  foreach ($dir in $searchDirs) {
    if (-not (Test-Path $dir)) {
      continue
    }

    if ($VersionFilter -and $VersionFilter -ne "latest") {
      $candidate = Join-Path $dir "grclanker-$VersionFilter-$Target.$ArchiveExt"
      if (Test-Path $candidate) {
        return $candidate
      }
      continue
    }

    if (-not $preferredVersion) {
      $preferredVersion = Get-LocalCliVersion
    }

    if ($preferredVersion) {
      $preferredCandidate = Join-Path $dir "grclanker-$preferredVersion-$Target.$ArchiveExt"
      if (Test-Path $preferredCandidate) {
        return $preferredCandidate
      }
    }

    $candidate = Get-ChildItem -Path $dir -File -Filter "grclanker-*-$Target.$ArchiveExt" |
      Sort-Object Name |
      Select-Object -Last 1
    if ($candidate) {
      return $candidate.FullName
    }
  }

  return $null
}

function Resolve-LatestReleaseAsset([string]$Target, [string]$ArchiveExt) {
  $uri = "https://api.github.com/repos/$RepoOwner/$RepoName/releases?per_page=30"
  $releases = Invoke-RestMethod -Uri $uri

  foreach ($release in $releases) {
    $asset = $release.assets | Where-Object { $_.name -like "grclanker-*-$Target.$ArchiveExt" } | Select-Object -First 1
    if ($asset) {
      return @{
        Version = Normalize-Version $release.tag_name
        AssetName = $asset.name
        AssetUrl = $asset.browser_download_url
      }
    }
  }

  return $null
}

function Get-Target {
  if ($TargetOverride) {
    return $TargetOverride
  }

  if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    throw "install.ps1 is intended for Windows PowerShell or pwsh on Windows."
  }

  $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  switch ($arch) {
    "Arm64" { $arch = "arm64" }
    "X64" { $arch = "x64" }
    default { throw "Unsupported architecture: $arch" }
  }

  return "win32-$arch"
}

function Fallback-And-Fail([string]$Target) {
  Write-Host ""
  Write-Warn "Release bundle unavailable for $Target."
  Write-Host "  Fallbacks:"
  Write-Host "    npm install -g @grclanker/cli"
  Write-Host "    bun install -g @grclanker/cli"
  throw "Install aborted."
}

function Verify-Checksum([string]$ArchivePath, [string]$AssetName, [string]$Tag, [string]$AssetSourcePath, [string]$AssetUrl) {
  $ChecksumsPath = Join-Path $TempRoot "SHA256SUMS.txt"
  $ChecksumsUrl = $null

  if ($AssetUrlOverride) {
    Write-Warn "Skipping checksum verification — custom GRCLANKER_ASSET_URL in use"
    return $false
  }

  if ($AssetSourcePath) {
    $LocalDir = Split-Path $AssetSourcePath -Parent
    $LocalChecksums = Join-Path $LocalDir "SHA256SUMS.txt"
    if (Test-Path $LocalChecksums) {
      Copy-Item -LiteralPath $LocalChecksums -Destination $ChecksumsPath -Force
    } else {
      Write-Warn "No SHA256SUMS.txt found alongside local artifact — skipping verification"
      return $false
    }
  } elseif ($ReleaseBaseUrl) {
    $ChecksumsUrl = ($ReleaseBaseUrl.TrimEnd("/")) + "/SHA256SUMS.txt"
  } else {
    $ChecksumsUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$Tag/SHA256SUMS.txt"
  }

  if ($ChecksumsUrl) {
    try {
      Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath | Out-Null
    } catch {
      Write-Warn "Could not fetch SHA256SUMS.txt — skipping checksum verification"
      return $false
    }
  }

  $Entry = Get-Content -Path $ChecksumsPath | Where-Object {
    $_ -match "\s+$([regex]::Escape($AssetName))$"
  } | Select-Object -First 1

  if (-not $Entry) {
    Write-Warn "No checksum entry for $AssetName in SHA256SUMS.txt — skipping verification"
    return $false
  }

  $ExpectedHash = ($Entry -split "\s+")[0].ToLowerInvariant()
  $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ActualHash -ne $ExpectedHash) {
    throw "Checksum mismatch for $AssetName — expected $ExpectedHash, got $ActualHash. The download may be corrupted or tampered with."
  }

  return $true
}

Write-Host ""
Write-Host "  https://ethantroy.dev // https://hackidle.com" -ForegroundColor Cyan
Write-Host ""

$Target = Get-Target
$ArchiveExt = "zip"
$LocalAssetPath = $null

if ($Version -ne "latest") {
  $Version = Normalize-Version $Version
  $LocalAssetPath = Find-LocalAsset -Target $Target -ArchiveExt $ArchiveExt -VersionFilter $Version
  if ($LocalAssetPath) {
    $Tag = "v$Version"
    $AssetName = Split-Path $LocalAssetPath -Leaf
    $AssetSourcePath = $LocalAssetPath
  }
}

if (-not $AssetUrlOverride -and -not $ReleaseBaseUrl -and -not $AssetUrl -and $Version -eq "latest") {
  $LocalAssetPath = Find-LocalAsset -Target $Target -ArchiveExt $ArchiveExt
  if ($LocalAssetPath) {
    $AssetName = Split-Path $LocalAssetPath -Leaf
    $Version = ($AssetName -replace "^grclanker-", "") -replace "-$Target\.$ArchiveExt$", ""
    $Tag = "v$Version"
    $AssetSourcePath = $LocalAssetPath
    Write-Ok "Using local release artifact $AssetName"
  } else {
    Write-Info "Resolving latest release"
    $Release = Resolve-LatestReleaseAsset -Target $Target -ArchiveExt $ArchiveExt
    if (-not $Release) {
      Fallback-And-Fail $Target
    }

    $Version = $Release.Version
    $Tag = "v$Version"
    $AssetName = $Release.AssetName
    $AssetUrl = $Release.AssetUrl
  }
}

$Version = Normalize-Version $Version
$Tag = if ($Version) { "v$Version" } else { $null }

if ($AssetUrlOverride) {
  $AssetUrl = $AssetUrlOverride
  if (-not $AssetName) {
    $AssetName = Split-Path $AssetUrlOverride -Leaf
  }
} elseif ($ReleaseBaseUrl) {
  if (-not $Version) {
    throw "GRCLANKER_RELEASE_BASE_URL requires an explicit version. Set GRCLANKER_VERSION or pass -Version <version>."
  }
  if (-not $AssetName) {
    $AssetName = "grclanker-$Version-$Target.zip"
  }
  $AssetUrl = ($ReleaseBaseUrl.TrimEnd("/")) + "/$AssetName"
} elseif (-not $AssetUrl -and -not $AssetSourcePath) {
  $AssetName = "grclanker-$Version-$Target.zip"
  $AssetUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$Tag/$AssetName"
}

$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("grclanker-install-" + [System.Guid]::NewGuid().ToString("N"))
$ArchivePath = Join-Path $TempRoot $AssetName
$BinPath = Join-Path $BinDir "grclanker.cmd"

New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
try {
  if ($AssetSourcePath) {
    Write-Info "Copying local release artifact $AssetName"
    Copy-Item -LiteralPath $AssetSourcePath -Destination $ArchivePath -Force
  } else {
    Write-Info "Downloading $AssetName"
    try {
      Invoke-WebRequest -Uri $AssetUrl -OutFile $ArchivePath
    } catch {
      Fallback-And-Fail $Target
    }
  }
  Write-Ok "Downloaded"

  $verified = Verify-Checksum -ArchivePath $ArchivePath -AssetName $AssetName -Tag $Tag -AssetSourcePath $AssetSourcePath -AssetUrl $AssetUrl
  if ($verified) {
    Write-Ok "Integrity verified"
  }

  if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
  }

  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Expand-Archive -Path $ArchivePath -DestinationPath $InstallDir -Force
  Write-Ok "Installed bundle into $InstallDir"

  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  $LauncherShim = @(
    "@echo off",
    "setlocal",
    "set ""GRCLANKER_INSTALL_DIR=$InstallDir""",
    """%GRCLANKER_INSTALL_DIR%\node\node.exe"" ""%GRCLANKER_INSTALL_DIR%\app\bin\grclanker.js"" %*",
    ""
  ) -join "`r`n"
  Set-Content -Path $BinPath -Value $LauncherShim -Encoding Ascii
  Write-Ok "Installed launcher into $BinPath"

  if (-not (($env:Path -split ";") -contains $BinDir)) {
    Write-Warn "Your PATH does not include $BinDir"
    Write-Warn "Add this to your user PATH before running grclanker."
  }

  Write-Host ""
  Write-Host "  Ready. Run grclanker to start." -ForegroundColor Green
  Write-Host ""
} finally {
  if (Test-Path $TempRoot) {
    Remove-Item -Recurse -Force $TempRoot
  }
}
