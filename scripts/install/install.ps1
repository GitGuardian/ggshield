# ggshield installer for Windows.
#
# Installs the standalone ggshield build per-user (ZIP, no admin), then
# best-effort authenticates and installs any requested plugins.
#
#   irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | iex
#
# With options:
#   & ([scriptblock]::Create((irm <url>))) -Instance https://dashboard.example.com -Yes
#
# -Method msi installs the system-wide MSI instead (requires admin).
# Other methods (Chocolatey) are documented in scripts/install/README.md.
# Cleanup: uninstall.ps1. Compatible with Windows PowerShell 5.1 (no pwsh).

[CmdletBinding()]
param(
    [switch]$Yes,
    [string]$Instance = $env:GITGUARDIAN_INSTANCE,
    [string]$Version = $env:GGSHIELD_VERSION,
    [ValidateSet('zip', 'msi')]
    [string]$Method = 'zip',
    [switch]$InstallOnly,
    [string[]]$Plugin = @()
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GithubRepo = 'GitGuardian/ggshield'
$DefaultInstance = 'https://dashboard.gitguardian.com'
$EuInstance = 'https://dashboard.eu1.gitguardian.com'
$ZipDir = Join-Path $env:LOCALAPPDATA 'Programs\ggshield'
$StateDir = Join-Path $env:LOCALAPPDATA 'ggshield-install'

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Blue }
function Warn($msg) { Write-Host "warning: $msg" -ForegroundColor Yellow }
function Die($msg) { throw "error: $msg" }

# Run a native command, discarding output. With $ErrorActionPreference=Stop,
# redirecting native stderr would otherwise throw (PowerShell 5.1 gotcha).
function Invoke-Native {
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $args[0] @($args | Select-Object -Skip 1) 2>&1 | Out-Null }
    finally { $ErrorActionPreference = $eap }
    return $LASTEXITCODE
}

function Update-SessionPath {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
    [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + $env:Path
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Version {
    if ($script:Version) {
        $script:Version = $script:Version.TrimStart('v')
        return
    }
    Say 'Resolving latest ggshield version'
    $release = Invoke-RestMethod "https://api.github.com/repos/$GithubRepo/releases/latest"
    $script:Version = $release.tag_name.TrimStart('v')
}

# GitHub computes a sha256 digest for every release asset
function Get-AssetDigest($assetName) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$GithubRepo/releases/tags/v$script:Version"
    $asset = $release.assets | Where-Object { $_.name -eq $assetName }
    if ($asset -and $asset.digest) { return $asset.digest -replace '^sha256:', '' }
    return $null
}

# sha256 is mandatory and fails closed; gh provenance is opt-in (Test-Attestation).
function Test-Download($file, $assetName) {
    $expected = Get-AssetDigest $assetName
    if (-not $expected) {
        Die "could not retrieve the expected sha256 digest for $assetName from the GitHub API; refusing to install unverified"
    }
    Say 'Verifying sha256 checksum'
    $actual = (Get-FileHash -Algorithm SHA256 -Path $file).Hash
    if ($actual -ne $expected) { Die "checksum mismatch for $assetName" }

    Test-Attestation $file $assetName
}

# 1/true/yes/on (any case, surrounding whitespace ignored) enable it; unset/empty/
# 0/false/no/off disable; warn on anything else and treat as off.
function Test-RequireAttestation {
    $raw = "$env:GGSHIELD_REQUIRE_ATTESTATION"
    $v = $raw.Trim().ToLowerInvariant()
    if ([string]::IsNullOrEmpty($v)) { return $false }
    if ($v -in @('1', 'true', 'yes', 'on')) { return $true }
    if ($v -in @('0', 'false', 'no', 'off')) { return $false }
    Warn "unrecognized GGSHIELD_REQUIRE_ATTESTATION value '$raw'; treating as off (use 1 to require)"
    return $false
}

# Build-provenance verification is opt-in and OFF by default; see install.sh for
# the rationale (ambient gh, and a public lookup still needs an authenticated gh,
# so running it automatically is fragile — END-609). When opted in, fail closed if
# gh is missing, too old, unauthenticated, or the provenance does not verify.
function Test-Attestation($file, $assetName) {
    if (-not (Test-RequireAttestation)) {
        Say 'Skipping build provenance check (set GGSHIELD_REQUIRE_ATTESTATION=1 to require it). To verify a downloaded asset yourself:'
        Write-Host "    gh attestation verify <asset> --repo $GithubRepo"
        return
    }
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        Die 'GGSHIELD_REQUIRE_ATTESTATION is set but gh is not installed (need gh >= 2.56.0)'
    }
    if ((Invoke-Native gh attestation --help) -ne 0) {
        Die "GGSHIELD_REQUIRE_ATTESTATION is set but this gh is too old for 'gh attestation' (need >= 2.56.0)"
    }
    if ((Invoke-Native gh auth status) -ne 0) {
        Die "GGSHIELD_REQUIRE_ATTESTATION is set but gh is not authenticated; run 'gh auth login'"
    }
    Say 'Verifying build provenance attestation'
    if ((Invoke-Native gh attestation verify $file --repo $GithubRepo) -ne 0) {
        Die "build provenance verification failed for ${assetName}: it does not match $GithubRepo"
    }
}

function Get-ReleaseAsset($assetName) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $assetName
    Say "Downloading $assetName"
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://github.com/$GithubRepo/releases/download/v$script:Version/$assetName" `
        -OutFile $tmp
    Test-Download $tmp $assetName
    return $tmp
}

# Path to a system-wide MSI ggshield.exe (from its recorded install location),
# or $null. A system MSI sits on the Machine PATH, which Windows searches
# before the user PATH where the zip installs.
function Get-MsiGgshieldExe {
    $p = Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'ggshield*' -and $_.InstallLocation } |
        Select-Object -First 1
    if ($p) {
        $exe = Join-Path $p.InstallLocation 'ggshield.exe'
        if (Test-Path $exe) { return $exe }
    }
    return $null
}

function Install-WithMsi {
    if (-not (Test-Admin)) { Die '-Method msi requires an elevated (administrator) PowerShell' }
    Resolve-Version
    $msi = Get-ReleaseAsset "ggshield-$script:Version-x86_64-pc-windows-msvc.msi"
    Say 'Installing the MSI'
    $proc = Start-Process msiexec -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Die "msiexec failed with exit code $($proc.ExitCode)" }
    Remove-Item $msi -ErrorAction SilentlyContinue
    $exe = Get-MsiGgshieldExe
    if ($exe) { $script:GgshieldExe = $exe }
}

function Install-WithZip {
    Resolve-Version
    $zip = Get-ReleaseAsset "ggshield-$script:Version-x86_64-pc-windows-msvc.zip"
    Say "Installing to $ZipDir"
    if (Test-Path $ZipDir) { Remove-Item $ZipDir -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $ZipDir -Force
    Remove-Item $zip -ErrorAction SilentlyContinue

    $exe = Get-ChildItem $ZipDir -Recurse -Filter ggshield.exe | Select-Object -First 1
    if (-not $exe) { Die "no ggshield.exe found in $ZipDir" }
    $binDir = $exe.DirectoryName
    # operate on the exact binary we installed, not whatever PATH resolves to
    # (a system-wide ggshield on the Machine PATH would otherwise shadow this)
    $script:GgshieldExe = $exe.FullName

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $binDir) {
        Say "Adding $binDir to your user PATH"
        [Environment]::SetEnvironmentVariable('Path', "$binDir;$userPath", 'User')
    }
    $env:Path = "$binDir;$env:Path"
}

function Write-State {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    @{ method = $script:Method; version = $script:Version; zipDir = $ZipDir } |
        ConvertTo-Json | Set-Content (Join-Path $StateDir 'state.json')
}

# Hints for steps that did NOT complete — only shown when something is left to
# do (auth failed/skipped, a plugin failed, or -InstallOnly).
function Write-AuthHint {
    $inst = if ($Instance) { $Instance } else { $DefaultInstance }
    Write-Host "    ggshield auth login --instance $inst"
    if (-not $Instance) { Write-Host "    # EU workspace: ggshield auth login --instance $EuInstance" }
    Write-Host '    # no browser available: add --method oob'
}

function Write-PluginHint {
    if ($Plugin) { Write-Host "    ggshield plugin install $($Plugin -join ' ')" }
}

# Best-effort: a failed login warns but never fails the installer. Sets
# $script:AuthSucceeded so the caller can skip plugins when auth did not work.
function Invoke-BestEffortAuth {
    $script:AuthSucceeded = $false
    $inst = if ($Instance) { $Instance } else { $DefaultInstance }
    if (-not $env:GITGUARDIAN_API_KEY -and $Yes) {
        Warn 'non-interactive run (-Yes) without GITGUARDIAN_API_KEY: skipping auth'
        return
    }
    $loginArgs = @('auth', 'login')
    if ($Instance) { $loginArgs += @('--instance', $Instance) }
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($env:GITGUARDIAN_API_KEY) {
            Say "Authenticating with GITGUARDIAN_API_KEY against $inst"
            $loginArgs += @('--method', 'token')
            $env:GITGUARDIAN_API_KEY | & $script:GgshieldExe @loginArgs
        }
        else {
            Say "Authenticating against $inst"
            & $script:GgshieldExe @loginArgs
        }
    }
    finally { $ErrorActionPreference = $eap }
    if ($LASTEXITCODE -eq 0) { $script:AuthSucceeded = $true }
    else { Warn "authentication failed (instance: $inst)" }
}

function Invoke-PostInstall {
    Update-SessionPath
    # operate on the binary we just installed; only fall back to PATH if an
    # install function did not record it
    if (-not $script:GgshieldExe -or -not (Test-Path $script:GgshieldExe)) {
        $gg = Get-Command ggshield -ErrorAction SilentlyContinue
        if (-not $gg) { Die 'ggshield not found on PATH after install (open a new terminal and retry)' }
        $script:GgshieldExe = $gg.Source
    }
    $installedVersion = & $script:GgshieldExe --version
    if ($LASTEXITCODE -ne 0) { Die "the installed ggshield ($script:GgshieldExe) failed to run (exit code $LASTEXITCODE)" }
    Say "Installed: $installedVersion"

    # a pre-existing ggshield earlier on PATH (e.g. a system MSI on the Machine
    # PATH) shadows a per-user zip install — warn so the version isn't confusing
    $resolved = (Get-Command ggshield -ErrorAction SilentlyContinue).Source
    if ($resolved -and $resolved -ne $script:GgshieldExe) {
        Warn "another ggshield on your PATH ($resolved) shadows the one just installed ($script:GgshieldExe)"
        # a system-wide install (Program Files / ProgramData) sits on the
        # Machine PATH, which Windows searches before the per-user PATH — a new
        # terminal won't help and a per-user install can't override it
        $sysRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }
        $isSystem = $false
        foreach ($r in $sysRoots) {
            if ($resolved.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase)) { $isSystem = $true }
        }
        if ($isSystem) {
            Warn 'that is a system-wide install. Re-run as administrator with -Method msi to replace it, or uninstall it first (uninstall.ps1).'
        }
        else {
            Warn 'remove it or fix your PATH order'
        }
    }

    if ($InstallOnly) {
        Say 'ggshield is installed. To finish setup:'
        Write-AuthHint
        Write-PluginHint
        return
    }

    # Plugins need a working authentication, so only attempt them once auth
    # succeeds; otherwise skip.
    $pluginsPending = $false
    Invoke-BestEffortAuth
    if ($script:AuthSucceeded) {
        foreach ($p in $Plugin) {
            Say "Installing the $p plugin"
            if ((Invoke-Native $script:GgshieldExe plugin install $p) -ne 0) {
                Warn "could not install the $p plugin (continuing)"
                $pluginsPending = $true
            }
        }
    }
    elseif ($Plugin) {
        Warn 'skipping plugin install until ggshield is authenticated'
        $pluginsPending = $true
    }

    # Only nag about next steps when something actually remains.
    if ($script:AuthSucceeded -and -not $pluginsPending) {
        Say 'ggshield is ready.'
        return
    }
    Say 'To finish setup:'
    if (-not $script:AuthSucceeded) { Write-AuthHint }
    if ($pluginsPending) { Write-PluginHint }
}

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Die "unsupported architecture: $env:PROCESSOR_ARCHITECTURE (only x86_64 builds are published)"
}

Say "Windows/x86_64 - install method: $Method"
switch ($Method) {
    'msi' { Install-WithMsi }
    'zip' { Install-WithZip }
}

Write-State
Invoke-PostInstall
