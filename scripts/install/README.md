# ggshield install scripts

One-line scripts to install ggshield on your machine (for developers and
non-developers), authenticate, optionally install plugins (`--plugin
<name>`), and cleanly uninstall it later.

## Install

Linux / macOS:

```sh
curl --proto '=https' --tlsv1.2 -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | iex
```

Prefer inspecting before running:

```sh
curl --proto '=https' --tlsv1.2 -sSfL -o install.sh \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh
less install.sh
bash install.sh
```

The script detects the OS and architecture (including Rosetta 2 and musl) and
picks the best installation method available:

| Platform                                  | Method                                                               |
| ----------------------------------------- | -------------------------------------------------------------------- |
| macOS with Homebrew                       | `brew install ggshield`                                              |
| macOS without Homebrew                    | standalone tarball in `~/.local/bin` (no sudo)                       |
| Linux with apt/dnf/yum/zypper + sudo      | GitGuardian Cloudsmith deb/rpm repository                            |
| Linux without sudo (x86_64 / arm64 glibc) | standalone tarball in `~/.local/bin`                                 |
| Linux musl                                | `pipx`                                                               |
| Windows elevated                          | standalone `.msi`                                                    |
| Windows non-elevated                      | standalone `.zip` in `%LOCALAPPDATA%\Programs\ggshield`              |
| Windows, last resort                      | Chocolatey (`-Method choco` to force) — the channel can lag upstream |

Standalone downloads are checksum-verified against the digest GitHub publishes
for each asset, and — when `gh` is available — against the release's [build
provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

arm64 Linux builds are recent: on older releases that lack them, the script
uses `pipx` instead.

### Options

```text
-y, --yes           never prompt, accept defaults (for CI)
    --instance URL  GitGuardian instance to authenticate against
    --version X.Y.Z ggshield version to install (default: latest)
    --method M      auto|brew|repo|tarball|pipx (default: auto)
    --install-only  install ggshield, skip auth and plugins
    --plugin NAME   install this ggshield plugin (repeatable)
```

Pass options through the pipe with `bash -s --`:

```sh
curl --proto '=https' --tlsv1.2 -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh |
  bash -s -- --instance https://dashboard.gitguardian.mycorp.local --plugin <plugin_name>
```

`install.ps1` takes the equivalent options (`-Yes`, `-Instance URL`, `-Version X.Y.Z`,
`-Method auto|choco|msi|zip`, `-InstallOnly`, `-Plugin name[,name]`):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1))) `
  -Instance https://dashboard.gitguardian.mycorp.local -Plugin <plugin_name> -Yes
```

### Instance

ggshield authenticates against the US workspace
(`https://dashboard.gitguardian.com`) by default. Use `--instance`
(`-Instance` on Windows) to target another one — for the EU workspace:

```sh
curl --proto '=https' --tlsv1.2 -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh |
  bash -s -- --instance https://dashboard.eu1.gitguardian.com
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1))) `
  -Instance https://dashboard.eu1.gitguardian.com
```

A self-hosted instance works the same way, e.g.
`--instance https://dashboard.gitguardian.example.com`.

### Environment variables

| Variable              | Effect                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------- |
| `GGSHIELD_VERSION`    | same as `--version`                                                                      |
| `GITGUARDIAN_API_KEY` | authenticate with this API key instead of the browser login; works with `--instance`     |
| `GGSHIELD_BIN_DIR`    | symlink directory for tarball installs (default `~/.local/bin`)                          |
| `GGSHIELD_OPT_DIR`    | extraction directory for tarball installs (default `~/.local/share/ggshield-standalone`) |

## Uninstall

Linux / macOS:

```sh
curl --proto '=https' --tlsv1.2 -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.ps1 | iex
```

Every removal is confirmed individually by default; pass `-y` / `-Yes` to
accept everything (required for non-interactive runs).

It removes the installed plugins, logs out, deletes ggshield's configuration,
cache and data, and removes every ggshield installation it detects — whether
put there by this script or another way (system package, Homebrew, pipx, uv,
pip, mise, the macOS package, Chocolatey, MSI or a standalone build). It can
also clear the uv download cache, the pre-commit cache and any scheduled
scans.

### Not handled

Installations the scripts neither perform nor remove — clean these manually:

| Channel                                                   | Cleanup                                          |
| --------------------------------------------------------- | ------------------------------------------------ |
| aqua                                                      | remove from `aqua.yaml`, `aqua gc`               |
| Nix / home-manager / NixOS                                | `nix profile remove`, or edit your configuration |
| Docker / Podman images                                    | `docker rmi gitguardian/ggshield`                |
| CI-scoped installs (GitHub Action, GitLab template, etc.) | per-job, nothing persists on this machine        |
| From-source checkouts (`pip install -e .`)                | remove the venv/checkout                         |
