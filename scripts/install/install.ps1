# ggshield installer for Windows.
#
# Installs ggshield using the best method available on this machine,
# authenticates, and optionally installs plugins (-Plugin NAME).
#
#   irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | iex
#
# With options:
#   & ([scriptblock]::Create((irm <url>))) -Instance https://dashboard.example.com -Yes
#
# See scripts/install/README.md. Cleanup: uninstall.ps1.
#
# Compatible with Windows PowerShell 5.1 (no pwsh required).

[CmdletBinding()]
param(
    [switch]$Yes,
    [string]$Instance = $env:GGSHIELD_INSTANCE,
    [string]$Version = $env:GGSHIELD_VERSION,
    [ValidateSet('auto', 'choco', 'msi', 'zip')]
    [string]$Method = 'auto',
    [switch]$InstallOnly,
    [string[]]$Plugin = @()
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GithubRepo = 'GitGuardian/ggshield'
$ZipDir = Join-Path $env:LOCALAPPDATA 'Programs\ggshield'
$StateDir = Join-Path $env:LOCALAPPDATA 'ggshield-install'

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Blue }
function Warn($msg) { Write-Host "warning: $msg" -ForegroundColor Yellow }
function Die($msg) { throw "error: $msg" }

function Confirm-Step($prompt) {
    if ($Yes) { return $true }
    $reply = Read-Host "$prompt [Y/n]"
    return $reply -notmatch '^[nN]'
}

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

function Test-Download($file, $assetName) {
    $expected = Get-AssetDigest $assetName
    if (-not $expected) {
        Warn 'could not retrieve the expected sha256 digest from the GitHub API'
        if (-not (Confirm-Step 'Continue without checksum verification?')) { Die 'aborted' }
    }
    else {
        Say 'Verifying sha256 checksum'
        $actual = (Get-FileHash -Algorithm SHA256 -Path $file).Hash
        if ($actual -ne $expected) { Die "checksum mismatch for $assetName" }
    }

    # opportunistic build provenance check; older gh has no `attestation`
    if ((Get-Command gh -ErrorAction SilentlyContinue) -and
        (Invoke-Native gh attestation --help) -eq 0 -and
        (Invoke-Native gh auth status) -eq 0) {
        Say 'Verifying build provenance attestation'
        if ((Invoke-Native gh attestation verify $file --repo $GithubRepo) -ne 0) {
            Die "artifact attestation verification failed for $assetName"
        }
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

function Install-WithChoco {
    Say 'Installing ggshield with Chocolatey'
    $chocoArgs = @('install', 'ggshield', '-y')
    if ($script:Version) { $chocoArgs += "--version=$script:Version" }
    & choco @chocoArgs
    if ($LASTEXITCODE -ne 0) { Die 'choco install failed' }
}

function Install-WithMsi {
    if (-not (Test-Admin)) { Die '-Method msi requires an elevated (administrator) PowerShell' }
    Resolve-Version
    $msi = Get-ReleaseAsset "ggshield-$script:Version-x86_64-pc-windows-msvc.msi"
    Say 'Installing the MSI'
    $proc = Start-Process msiexec -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Die "msiexec failed with exit code $($proc.ExitCode)" }
    Remove-Item $msi -ErrorAction SilentlyContinue
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

function Invoke-PostInstall {
    Update-SessionPath
    $gg = Get-Command ggshield -ErrorAction SilentlyContinue
    if (-not $gg) { Die 'ggshield not found on PATH after install (open a new terminal and retry)' }
    Say "Installed: $(& ggshield --version)"

    if ($InstallOnly) {
        Say 'Done (-InstallOnly). Next: ggshield auth login'
        return
    }

    $loginArgs = @('auth', 'login')
    if ($Instance) { $loginArgs += @('--instance', $Instance) }
    if ($env:GITGUARDIAN_API_KEY) {
        # token login (key read from stdin) persists the key for later
        # shells and validates it against the selected instance
        Say 'Authenticating with the API key from GITGUARDIAN_API_KEY'
        $loginArgs += @('--method', 'token')
        $env:GITGUARDIAN_API_KEY | & ggshield @loginArgs
    }
    else {
        Say 'Authenticating'
        & ggshield @loginArgs
    }
    if ($LASTEXITCODE -ne 0) { Die 'authentication failed' }

    if (-not $Plugin) {
        Say 'Done. To list available plugins: ggshield plugin status'
        return
    }

    foreach ($p in $Plugin) {
        Say "Installing the $p plugin"
        & ggshield plugin install $p
        if ($LASTEXITCODE -ne 0) { Die "installation of plugin '$p' failed" }
    }
}

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Die "unsupported architecture: $env:PROCESSOR_ARCHITECTURE (only x86_64 builds are published)"
}

# Routing: msi (elevated) > zip (per-user) > choco last. The Chocolatey
# channel can lag upstream, so it is only a final fallback; use
# -Method choco to pick it explicitly.
if ($Method -eq 'auto') {
    if (Test-Admin) { $Method = 'msi' }
    elseif ($env:LOCALAPPDATA) { $Method = 'zip' }
    elseif (Get-Command choco -ErrorAction SilentlyContinue) { $Method = 'choco' }
    else { $Method = 'zip' }
}
Say "Windows/x86_64 - install method: $Method"

switch ($Method) {
    'choco' { Install-WithChoco }
    'msi' { Install-WithMsi }
    'zip' { Install-WithZip }
}

Write-State
Invoke-PostInstall
