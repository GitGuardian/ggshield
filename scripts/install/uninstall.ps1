# Uninstall ggshield and its data on Windows: uninstall the plugins, log out,
# remove caches/config, then remove ggshield itself using the method recorded
# by install.ps1 (or detected).
#
#   irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.ps1 | iex
#
# Compatible with Windows PowerShell 5.1 (no pwsh required).

[CmdletBinding()]
param(
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$ZipDir = Join-Path $env:LOCALAPPDATA 'Programs\ggshield'
$StateDir = Join-Path $env:LOCALAPPDATA 'ggshield-install'
$StateFile = Join-Path $StateDir 'state.json'

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Blue }
function Warn($msg) { Write-Host "warning: $msg" -ForegroundColor Yellow }
function Die($msg) { throw "error: $msg" }

function Confirm-Step($prompt) {
    if ($Yes) { return $true }
    $reply = Read-Host "$prompt [Y/n]"
    return $reply -notmatch '^[nN]'
}

function Get-MsiProduct {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'ggshield*' } |
        Select-Object -First 1
}

# A machine may carry several installs: detect and remove them all
function Get-InstallMethods {
    $methods = @()
    if (Test-Path $StateFile) {
        try { $methods += (Get-Content $StateFile -Raw | ConvertFrom-Json).method }
        catch { Warn "could not read $StateFile" }
    }
    $chocoLib = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { 'C:\ProgramData\chocolatey' }
    if ((Get-Command choco -ErrorAction SilentlyContinue) -and
        (Test-Path (Join-Path $chocoLib 'lib\ggshield'))) { $methods += 'choco' }
    if (Get-MsiProduct) { $methods += 'msi' }
    if (Get-Command uv -ErrorAction SilentlyContinue) {
        $eap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $uvTools = & uv tool list 2>&1
        $ErrorActionPreference = $eap
        if ($LASTEXITCODE -eq 0 -and ($uvTools | Select-String '^ggshield ')) { $methods += 'uv' }
    }
    if ((Get-Command python -ErrorAction SilentlyContinue) -and
        ((Invoke-Native python -m pip show ggshield) -eq 0)) { $methods += 'pip' }
    if (Test-Path $ZipDir) { $methods += 'zip' }
    $methods = @($methods | Select-Object -Unique)
    if (-not $methods) { $methods = @('none') }
    return $methods
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

function Invoke-GgshieldCleanup {
    if (-not (Get-Command ggshield -ErrorAction SilentlyContinue)) { return }
    # there is no `plugin uninstall --all`: enumerate and remove one by one
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $plugins = & ggshield plugin list 2>&1 |
        ForEach-Object { if ("$_" -match '^\s{2}([^:\s]+):') { $Matches[1] } }
    $ErrorActionPreference = $eap
    foreach ($p in $plugins) {
        if (-not (Confirm-Step "Uninstall the $p plugin?")) { continue }
        if ((Invoke-Native ggshield plugin uninstall --yes $p) -ne 0) {
            Warn "could not uninstall the $p plugin"
        }
    }
    if (Confirm-Step 'Log out from GitGuardian?') {
        if ((Invoke-Native ggshield auth logout) -ne 0) {
            Warn 'could not log out (maybe not logged in)'
        }
    }
}

function Remove-Package($method) {
    switch ($method) {
        'choco' {
            Say 'Removing ggshield with Chocolatey'
            & choco uninstall ggshield -y
        }
        'msi' {
            $product = Get-MsiProduct
            if (-not $product) { Warn 'ggshield MSI product not found, skipping'; return }
            Say 'Removing the ggshield MSI'
            $proc = Start-Process msiexec -ArgumentList '/x', $product.PSChildName, '/qn', '/norestart' -Wait -PassThru
            if ($proc.ExitCode -ne 0) { Warn "msiexec failed with exit code $($proc.ExitCode)" }
        }
        'uv' {
            Say 'Removing ggshield with uv'
            & uv tool uninstall ggshield
        }
        'pip' {
            Say 'Removing ggshield with pip'
            if ((Invoke-Native python -m pip uninstall -y ggshield) -ne 0) {
                Warn 'pip uninstall failed'
            }
        }
        'zip' {
            Say 'Removing standalone install'
            if (Test-Path $ZipDir) { Remove-Item $ZipDir -Recurse -Force }
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            $cleaned = ($userPath -split ';' | Where-Object { $_ -and $_ -notlike "$ZipDir*" }) -join ';'
            if ($cleaned -ne $userPath) {
                Say 'Removing ggshield from your user PATH'
                [Environment]::SetEnvironmentVariable('Path', $cleaned, 'User')
            }
        }
        'none' {
            Warn 'no ggshield installation detected, removing leftovers only'
        }
    }
}

function Remove-UserData {
    # platformdirs(appname="ggshield", appauthor="GitGuardian") on Windows
    $paths = @(
        (Join-Path $env:USERPROFILE '.gitguardian.yaml'),
        (Join-Path $env:LOCALAPPDATA 'GitGuardian\ggshield')
    )
    $found = $paths | Where-Object { Test-Path $_ }
    if (-not $found) {
        Say 'No ggshield config/cache/data found'
        return
    }
    if (-not (Confirm-Step 'Remove ggshield configuration, cache and data (including plugins)?')) { return }
    foreach ($p in $found) {
        Say "Removing $p"
        Remove-Item $p -Recurse -Force
    }
}

# best-effort version lookup, only used to enrich the prompts
function Get-MethodVersion($method) {
    try {
        switch ($method) {
            'msi' { return (Get-MsiProduct).DisplayVersion }
            'choco' {
                $chocoLib = if ($env:ChocolateyInstall) { $env:ChocolateyInstall } else { 'C:\ProgramData\chocolatey' }
                $nuspec = Get-Content (Join-Path $chocoLib 'lib\ggshield\ggshield.nuspec') -Raw -ErrorAction SilentlyContinue
                if ($nuspec -match '<version>([^<]+)</version>') { return $Matches[1] }
            }
            'uv' {
                $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                $line = & uv tool list 2>&1 | Select-String '^ggshield v?([\d.]+)'
                $ErrorActionPreference = $eap
                if ($line) { return $line.Matches[0].Groups[1].Value }
            }
            'pip' {
                $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                $line = & python -m pip show ggshield 2>&1 | Select-String '^Version: (.+)'
                $ErrorActionPreference = $eap
                if ($line) { return $line.Matches[0].Groups[1].Value }
            }
            'zip' {
                if (Test-Path $StateFile) {
                    return (Get-Content $StateFile -Raw | ConvertFrom-Json).version
                }
            }
        }
    }
    catch { return $null }
}

$methods = Get-InstallMethods
Say "Detected install method(s): $($methods -join ', ')"

Invoke-GgshieldCleanup
foreach ($m in $methods) {
    if ($m -ne 'none') {
        $v = Get-MethodVersion $m
        $label = if ($v) { "$m $v" } else { $m }
        if (-not (Confirm-Step "Remove the ggshield installation ($label)?")) { continue }
    }
    Remove-Package $m
}
Remove-UserData
if (Test-Path $StateDir) { Remove-Item $StateDir -Recurse -Force }

if (Get-Command ggshield -ErrorAction SilentlyContinue) {
    Warn "a 'ggshield' command is still on your PATH: $((Get-Command ggshield).Source)"
}
else {
    Say 'ggshield is fully removed'
}
