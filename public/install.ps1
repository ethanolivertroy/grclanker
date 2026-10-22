param(
  [string]$Version
)

$ErrorActionPreference = "Stop"
# Invoke-WebRequest otherwise draws a progress bar that can stall noninteractive hosts.
$ProgressPreference = "SilentlyContinue"

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

    $candidate = $null
    $candidateVersion = $null
    foreach ($file in (Get-ChildItem -Path $dir -File -Filter "grclanker-*-$Target.$ArchiveExt")) {
      $version = Get-ArchiveVersion -Name $file.Name -Target $Target -ArchiveExt $ArchiveExt
      if (-not $version) {
        continue
      }
      if (-not $candidate -or (Test-VersionNewer -Left $version -Right $candidateVersion)) {
        $candidate = $file.FullName
        $candidateVersion = $version
      }
    }
    if ($candidate) {
      return $candidate
    }
  }

  return $null
}

# "latest" means the newest full release that carries a bundle for this target.
# Prereleases (vX.Y.Z-rc.N) and asset-less releases such as specs-v2 are skipped.
function Resolve-LatestReleaseAsset([string]$Target, [string]$ArchiveExt) {
  $release = Resolve-LatestReleaseAssetFromApi -Target $Target -ArchiveExt $ArchiveExt
  if ($release) {
    return $release
  }
  return Resolve-LatestReleaseAssetFromRedirect -Target $Target -ArchiveExt $ArchiveExt
}

function Resolve-LatestReleaseAssetFromApi([string]$Target, [string]$ArchiveExt) {
  $uri = "https://api.github.com/repos/$RepoOwner/$RepoName/releases?per_page=30"
  try {
    $releases = Invoke-RestMethod -Uri $uri
  } catch {
    return $null
  }

  foreach ($release in $releases) {
    if ($release.draft -or $release.prerelease) {
      continue
    }
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

# The unauthenticated GitHub API allows 60 requests an hour per IP, which shared
# networks exhaust. The /releases/latest page redirect is not rate limited and
# points at the release the release-bundles workflow marked latest.
function Resolve-LatestReleaseAssetFromRedirect([string]$Target, [string]$ArchiveExt) {
  try {
    $response = Invoke-WebRequest -Uri "https://github.com/$RepoOwner/$RepoName/releases/latest" -Method Head -UseBasicParsing
  } catch {
    return $null
  }

  # Windows PowerShell 5.1 exposes the final URL as ResponseUri; PowerShell 7 as RequestMessage.RequestUri.
  $base = $response.BaseResponse
  $latestUrl = if ($base.ResponseUri) { $base.ResponseUri.AbsoluteUri } elseif ($base.RequestMessage) { $base.RequestMessage.RequestUri.AbsoluteUri } else { "" }
  if ($latestUrl -notmatch "/releases/tag/(v[^/?#]+)$") {
    return $null
  }

  $tag = $Matches[1]
  $version = Normalize-Version $tag
  $assetName = "grclanker-$version-$Target.$ArchiveExt"
  return @{
    Version = $version
    AssetName = $assetName
    AssetUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$tag/$assetName"
  }
}

function Get-ArchiveVersion([string]$Name, [string]$Target, [string]$ArchiveExt) {
  $prefix = "grclanker-"
  $suffix = "-$Target.$ArchiveExt"
  if (-not $Name.StartsWith($prefix) -or -not $Name.EndsWith($suffix)) {
    return $null
  }
  return $Name.Substring($prefix.Length, $Name.Length - $prefix.Length - $suffix.Length)
}

function Get-VersionCore([string]$Version) {
  $dash = $Version.IndexOf("-")
  if ($dash -ge 0) {
    return $Version.Substring(0, $dash)
  }
  return $Version
}

function Get-VersionPrerelease([string]$Version) {
  $dash = $Version.IndexOf("-")
  if ($dash -ge 0) {
    return $Version.Substring($dash + 1)
  }
  return ""
}

# BSD and Windows name sorts put 0.1.10 before 0.1.2. Compare the numeric version.
function Test-VersionNewer([string]$Left, [string]$Right) {
  $leftParts = (Get-VersionCore $Left).Split(".")
  $rightParts = (Get-VersionCore $Right).Split(".")
  for ($i = 0; $i -lt 3; $i++) {
    $l = 0
    $r = 0
    if ($i -lt $leftParts.Length) { [void][int]::TryParse($leftParts[$i], [ref]$l) }
    if ($i -lt $rightParts.Length) { [void][int]::TryParse($rightParts[$i], [ref]$r) }
    if ($l -ne $r) { return $l -gt $r }
  }

  $leftPre = Get-VersionPrerelease $Left
  $rightPre = Get-VersionPrerelease $Right
  if (-not $leftPre -and -not $rightPre) { return $false }
  if (-not $leftPre) { return $true }
  if (-not $rightPre) { return $false }

  $leftIds = $leftPre.Split(".")
  $rightIds = $rightPre.Split(".")
  $count = [Math]::Max($leftIds.Length, $rightIds.Length)
  for ($i = 0; $i -lt $count; $i++) {
    $a = if ($i -lt $leftIds.Length) { $leftIds[$i] } else { "" }
    $b = if ($i -lt $rightIds.Length) { $rightIds[$i] } else { "" }
    if ($a -eq $b) { continue }
    if (-not $a) { return $false }
    if (-not $b) { return $true }
    $aNum = 0
    $bNum = 0
    $aIsNum = [int]::TryParse($a, [ref]$aNum)
    $bIsNum = [int]::TryParse($b, [ref]$bNum)
    if ($aIsNum -and $bIsNum) { return $aNum -gt $bNum }
    return [string]::CompareOrdinal($a, $b) -gt 0
  }
  return $false
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
  Write-Host "  Build from source instead (Node.js 22.19+):"
  Write-Host "    git clone https://github.com/$RepoOwner/$RepoName.git"
  Write-Host "    cd $RepoName"
  Write-Host "    npm --prefix cli ci"
  Write-Host "    npm --prefix cli run build"
  Write-Host "    node cli/bin/grclanker.js"
  Write-Host "  Guide: https://grclanker.com/docs/getting-started/installation/"
  throw "Install aborted."
}

function Assert-ZipEntriesSafe([string]$ArchivePath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    foreach ($entry in $zip.Entries) {
      $name = ($entry.FullName -replace "\\", "/")
      if ($name.StartsWith("/") -or $name -match "^[A-Za-z]:" -or $name -match "(^|/)\.\.(/|$)") {
        throw "Refusing to extract unsafe archive entry: $name"
      }
    }
  } finally {
    $zip.Dispose()
  }
}

# Expand-Archive runs PowerShell code for every entry, which takes minutes for a
# full bundle under Windows PowerShell 5.1.
function Expand-Bundle([string]$ArchivePath, [string]$DestinationPath) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $DestinationPath)
}

function Assert-HttpUrl([string]$Url, [string]$Label) {
  if ($Url -notmatch "^https?://") {
    throw "$Label must be an http or https URL. Got: $Url"
  }
}

function Verify-Checksum([string]$ArchivePath, [string]$AssetName, [string]$Tag, [string]$AssetSourcePath, [string]$AssetUrl) {
  $ChecksumsPath = Join-Path $TempRoot "SHA256SUMS.txt"
  $ChecksumsUrl = $null

  if ($AssetUrlOverride) {
    Write-Warn "Skipping checksum verification: custom GRCLANKER_ASSET_URL in use"
    return $false
  }

  $Strict = $false
  if ($AssetSourcePath) {
    $LocalDir = Split-Path $AssetSourcePath -Parent
    $LocalChecksums = Join-Path $LocalDir "SHA256SUMS.txt"
    if (Test-Path $LocalChecksums) {
      Copy-Item -LiteralPath $LocalChecksums -Destination $ChecksumsPath -Force
      # A checksum file that is present has to cover this archive. Only a
      # missing file is an unverified local artifact.
      $Strict = $true
    } else {
      Write-Warn "No SHA256SUMS.txt found alongside local artifact, skipping verification"
      return $false
    }
  } elseif ($ReleaseBaseUrl) {
    $ChecksumsUrl = ($ReleaseBaseUrl.TrimEnd("/")) + "/SHA256SUMS.txt"
    $Strict = $true
  } else {
    $ChecksumsUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$Tag/SHA256SUMS.txt"
    $Strict = $true
  }

  if ($ChecksumsUrl) {
    Assert-HttpUrl $ChecksumsUrl "Checksum URL"
    try {
      Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath | Out-Null
    } catch {
      throw "Could not fetch SHA256SUMS.txt from $ChecksumsUrl. Refusing to install $AssetName without a checksum."
    }
  }

  $Entry = Get-Content -Path $ChecksumsPath | ForEach-Object { $_.TrimEnd("`r") } | Where-Object {
    $_ -match "\s+$([regex]::Escape($AssetName))$"
  } | Select-Object -First 1

  if (-not $Entry) {
    if ($Strict) {
      throw "No checksum entry for $AssetName in SHA256SUMS.txt. Refusing to install without a checksum."
    }
    Write-Warn "No checksum entry for $AssetName in SHA256SUMS.txt, skipping verification"
    return $false
  }

  $ExpectedHash = ($Entry -split "\s+")[0].ToLowerInvariant()
  if ($ExpectedHash -notmatch "^[0-9a-f]{64}$") {
    throw "Checksum entry for $AssetName is not a SHA-256 hex digest."
  }
  $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($ActualHash -ne $ExpectedHash) {
    throw "Checksum mismatch for ${AssetName}: expected $ExpectedHash, got $ActualHash. The download may be corrupted or tampered with."
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
    Assert-HttpUrl $AssetUrl "Asset URL"
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

  # Reject a hostile archive before replacing anything already installed.
  Assert-ZipEntriesSafe -ArchivePath $ArchivePath

  # Move the previous install aside so a failed extraction can put it back.
  $PreviousInstall = $null
  if (Test-Path -LiteralPath $InstallDir) {
    $InstallPath = (Resolve-Path -LiteralPath $InstallDir).ProviderPath.TrimEnd([char[]]"\/")
    # A short suffix keeps the deepest bundle paths under the 260-character Windows limit.
    # A leftover with the same name would make Move-Item move the install inside it, so pick an unused name.
    do {
      $PreviousInstall = "$InstallPath.old-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    } while (Test-Path -LiteralPath $PreviousInstall)
    Move-Item -LiteralPath $InstallPath -Destination $PreviousInstall
  }

  $Extracted = $false
  try {
    # .NET resolves a relative path against the process directory, not the PowerShell location.
    $InstallRoot = (New-Item -ItemType Directory -Force -Path $InstallDir).FullName
    Expand-Bundle -ArchivePath $ArchivePath -DestinationPath $InstallRoot
    $Extracted = $true
  } finally {
    if ($PreviousInstall -and -not $Extracted) {
      try {
        if (Test-Path -LiteralPath $InstallPath) {
          Remove-Item -Recurse -Force -LiteralPath $InstallPath
        }
        Move-Item -LiteralPath $PreviousInstall -Destination $InstallPath
        Write-Warn "Extraction failed, so the previous install was restored."
      } catch {
        Write-Warn "Could not restore the previous install from ${PreviousInstall}: $($_.Exception.Message)"
      }
    }
  }
  Write-Ok "Installed bundle into $InstallDir"

  # The new install is complete, so this run's aside can go, along with any an
  # interrupted earlier run left behind. Windows names ignore case, but the
  # installer only generates lowercase suffixes.
  $InstallRoot = $InstallRoot.TrimEnd([char[]]"\/")
  $AsideName = "^(?i:" + [regex]::Escape((Split-Path -Leaf $InstallRoot)) + ")\.old-[0-9a-f]{8}$"
  foreach ($Aside in @(Get-ChildItem -LiteralPath (Split-Path -Parent $InstallRoot) -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -cmatch $AsideName })) {
    try {
      Remove-Item -Recurse -Force -LiteralPath $Aside.FullName
    } catch {
      Write-Warn "Could not remove the previous install at $($Aside.FullName): $($_.Exception.Message)"
    }
  }

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
  Write-Host "  Ready. Run grclanker setup to start." -ForegroundColor Green
  Write-Host ""
} finally {
  if (Test-Path $TempRoot) {
    Remove-Item -Recurse -Force $TempRoot
  }
}
