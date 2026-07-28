# ggshield install scripts

One-line scripts to install the standalone ggshield build on your machine (for
developers and non-developers), authenticate, optionally install plugins, and
cleanly uninstall it later. No admin/sudo required.

## Install

Linux / macOS:

```sh
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1 | iex
```

The `irm | iex` form runs the script content directly, so it is not subject to
the execution policy. If you instead download and run the `.ps1` file, Windows
requires `powershell -ExecutionPolicy Bypass -File .\install.ps1`.

Prefer inspecting before running:

```sh
curl -sSfL -o install.sh \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh
less install.sh
bash install.sh
```

The script installs the standalone build (detecting OS/arch, including Rosetta 2) to:

- **Linux / macOS** → `~/.local/share/ggshield-standalone`, symlinked into
  `~/.local/bin` (no sudo).
- **Windows** → `%LOCALAPPDATA%\Programs\ggshield`, added to your user PATH (no
  admin). `-Method msi` installs the system-wide MSI instead (requires admin).

On Linux/macOS, `~/.local/bin` is not on everyone's `PATH` (notably macOS, and
Debian/Ubuntu add it only when the directory already existed at login). When it
isn't, the script offers to fix it — detecting your shell (bash, zsh, fish, and,
independent of `$SHELL`, Nushell and PowerShell on Linux when installed) and
updating its profile, prompted with a default of yes (silent under `-y`).
Decline, or pass `--no-modify-path`, and it falls back to printing the exact
line to add yourself, with a reminder to **restart your terminal** afterwards.
Set `GGSHIELD_BIN_DIR` to a directory already on your `PATH` to skip this
entirely. `uninstall.sh` reverses any profile edit it made.

The download is **checksum-verified** against the digest GitHub publishes for
each asset (the install aborts if it cannot be verified). [Build provenance
attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
verification is **opt-in**: set `GGSHIELD_REQUIRE_ATTESTATION=1` to also verify
it with `gh` (>= 2.56.0, authenticated) and fail the install if it cannot be
verified. By default the script does not invoke `gh`; it prints the manual
`gh attestation verify` command instead.

Alpine/musl is not supported (the standalone build is glibc-only) — use the
Docker image `gitguardian/ggshield` or `pipx install ggshield`.

### Options

```text
-y, --yes           never prompt (for CI)
    --instance URL  GitGuardian instance (default: https://dashboard.gitguardian.com)
    --version X.Y.Z ggshield version to install (default: latest)
    --install-only  install ggshield only, skip auth and plugins
    --plugin NAME   install this ggshield plugin (repeatable)
    --no-modify-path
                    don't offer to add the install dir to PATH; only print
                    instructions
```

Pass options through the pipe with `bash -s --`:

```sh
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh |
  bash -s -- --plugin <plugin_name>
```

`install.ps1` takes the equivalent options (`-Yes`, `-Instance URL`,
`-Version X.Y.Z`, `-Method zip|msi`, `-InstallOnly`, `-Plugin name[,name]`):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1))) `
  -Plugin <plugin_name> -Yes
```

Authentication and plugin installation are **best-effort**: if they fail (wrong
instance, cancelled login, no network), the script warns and prints the retry
commands, but the install itself still succeeds.

### Instance

ggshield authenticates against the US workspace
(`https://dashboard.gitguardian.com`) by default. Use `--instance` (`-Instance`
on Windows) to target another one — for the EU workspace:

```sh
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.sh |
  bash -s -- --instance https://dashboard.eu1.gitguardian.com
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/install.ps1))) `
  -Instance https://dashboard.eu1.gitguardian.com
```

A self-hosted instance works the same way, e.g.
`--instance https://dashboard.gitguardian.example.com`. On a remote/headless
machine where the browser flow can't complete, add `--method oob` to the
printed `ggshield auth login` command.

### Environment variables

| Variable                       | Effect                                                                                                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GGSHIELD_VERSION`             | same as `--version`                                                                                                                                       |
| `GITGUARDIAN_INSTANCE`         | instance to authenticate against (same as `--instance`)                                                                                                   |
| `GITGUARDIAN_API_KEY`          | authenticate with this API key instead of the browser login                                                                                               |
| `GGSHIELD_BIN_DIR`             | symlink dir (default `~/.local/bin`)                                                                                                                      |
| `GGSHIELD_OPT_DIR`             | extraction dir (default `~/.local/share/ggshield-standalone`)                                                                                             |
| `GGSHIELD_REQUIRE_ATTESTATION` | set to `1` to require `gh` build-provenance verification (needs `gh` >= 2.56.0, authenticated); fails the install if it cannot be verified (default: off) |

## Other install methods

These scripts install the standalone build. If you'd rather use a package
manager (managed upgrades, system integration), install ggshield directly:

| Method                 | Command                                                                                                                     |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Homebrew (macOS/Linux) | `brew install ggshield`                                                                                                     |
| Debian / Ubuntu (apt)  | `curl -1sLf https://dl.cloudsmith.io/public/gitguardian/ggshield/setup.deb.sh \| sudo -E bash && sudo apt install ggshield` |
| Fedora / RHEL (dnf)    | `curl -1sLf https://dl.cloudsmith.io/public/gitguardian/ggshield/setup.rpm.sh \| sudo -E bash && sudo dnf install ggshield` |
| pipx                   | `pipx install ggshield`                                                                                                     |
| Windows (Chocolatey)   | `choco install ggshield`                                                                                                    |
| Docker                 | `docker run --rm gitguardian/ggshield ggshield --version`                                                                   |

The Cloudsmith `setup.*.sh` bootstrap runs **as root** and is not independently
checksum-verified (the standard Cloudsmith flow) — inspect it first if that
trust boundary matters.

## Uninstall

Linux / macOS:

```sh
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.ps1 | iex
```

By default this removes **only the install these scripts created** (the
standalone tree + its PATH entry, or the MSI when installed with `-Method msi`).
It does not touch ggshield installed another way — remove those with the
matching tool (`brew uninstall` / `apt remove` / `pipx uninstall` /
`choco uninstall` / `msiexec /x`).

Removing ggshield's configuration, cache and data is opt-in:

| Linux / macOS | Windows  | Removes                                                           |
| ------------- | -------- | ----------------------------------------------------------------- |
| `--purge`     | `-Purge` | config, cache and data (`~/.gitguardian.yaml`, plugins, scan DBs) |

Pass flags through the pipe with `bash -s --`:

```sh
curl -sSfL \
  https://raw.githubusercontent.com/GitGuardian/ggshield/main/scripts/install/uninstall.sh |
  bash -s -- --purge -y
```

The uninstaller prompts before removing anything. In a **non-interactive
context** (CI, cron, an MDM/`launchd`/`systemd` rollback, a container with no
terminal) it cannot prompt, so it exits without removing anything; pass
`-y`/`--yes` (`-Yes` on Windows) to proceed unattended.
