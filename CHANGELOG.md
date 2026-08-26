# Changelog

<a id='changelog-1.54.0'></a>

## 1.54.0 — 2026-08-26

- `pip`/`pipx` installs now ship the native Rust `ggshield` on common platforms
  (Linux x86-64/aarch64 for glibc and musl, macOS universal2, Windows x86-64); the Python implementation is installed
  alongside as `ggshield-py`. Platforms without a native wheel fall back to the
  pure-Python wheel, where `ggshield` is the Python entry point — as does
  Homebrew, which builds from the source distribution.

### Added

- Add secret-scanning hook support for Mistral Vibe 2.21 and later. Global and
  project installation preserves existing `hooks.toml` content and configures
  Vibe's `pre_tool` and `post_tool` events.

- A native `ggshield-hook` binary implements `ggshield secret scan ai-hook`,
  removing the interpreter startup cost the hook paid twice per tool call. It
  resolves the instance's scan limits from the same places ggshield does
  (`GG_MAX_DOC_SIZE` / `GG_MAX_DOCS`, the on-disk auth-check cache, then
  `/v1/metadata`), so a document or a batch the instance would reject is split or
  skipped instead of failing the scan. It caches what it learns from
  `/v1/metadata` for five minutes, so a hook path where only the native binary
  runs does not pay that round trip on every scan.

- The native hook now honours the `GITGUARDIAN_INSTANCE`, `GITGUARDIAN_API_URL`
  and `GITGUARDIAN_API_KEY` settings a `.env` file provides, instead of declining
  to scan when it found one. It reads the file from the same places ggshield does
  (`GITGUARDIAN_DOTENV_PATH`, then the working directory, then the repository
  root), and gives it the same precedence: a value in the `.env` overrides the
  same variable already exported in the environment. A self-hosted instance
  configured through a `.env` is therefore scanned against, rather than left
  unscanned. Two caveats: an unbraced `$` in a value is expanded as a variable
  reference (so `GITGUARDIAN_API_KEY=abc$def` resolves to `abc` — quote it as
  `'abc$def'` to keep the `$`), and a `GITGUARDIAN_*` line the parser rejects
  still leaves the action unscanned, with a message naming the variable.

- AI discovery now reports, per agent, the email of the assistant subscription that agent is signed into, so a personal
  subscription can be told apart from a company one. Read locally from Claude Code, Codex and Cursor. Mistral Vibe and
  VSCode keep no account on disk and report nothing.

- `GGSHIELD_NO_NOTIFICATION` suppresses the AI hook's desktop notification. The
  secret is still detected and the tool call still blocked; only the banner is
  withheld.

### Changed

- Release binaries are now built with Python 3.14 instead of 3.10, ahead of Python 3.10's
  end-of-life. This also updates the SQLite bundled in the released binaries, fixing
  `CVE-2025-6965` and `CVE-2025-7709`.

- AI hooks no longer call the API twice for the same document. An unambiguously clean
  scan result is cached locally for 15 minutes, keyed on the exact document sent and on
  the instance and token it was sent with, so a file read costs one API round trip
  instead of two (`PreToolUse` and `PostToolUse` scan the same file).

- `ggshield` starts faster: each command now imports only the modules it needs, and
  plugin discovery runs only when a plugin command is actually resolved. This speeds
  up every invocation, in particular the ones that run automatically on every git
  commit (`secret scan pre-commit`) and on every AI agent tool call
  (`secret scan ai-hook`).

- `ggshield secret scan ai-hook` is now much faster on MCP tool calls: the local
  discovery walk is cached for an hour instead of running on every call, and the
  secret scan and the MCP activity call now run concurrently instead of one after
  the other. Measured against a mock API at the production p50 latency, an MCP
  `PreToolUse` event goes from 1183 ms to 387 ms (p50). Other events are
  unaffected. As a consequence, an MCP tool call is now reported to GitGuardian
  even when the secret scan blocks it.

- AI hooks now scan all the payloads of an event in a single API call instead of one
  call each. A prompt mentioning three files used to cost four round trips; measured
  against a mock API at the production p50 latency, such a `UserPromptSubmit` goes from
  1561 ms to 395 ms (p50). Single-payload events are unchanged.

- In the standalone packages (`.pkg`, `.deb`, `.rpm`, `.msi`, Chocolatey, archives), `ggshield`
  is now a small native dispatcher: it runs `ggshield secret scan ai-hook` and hands every other
  command to the bundled Python implementation. There is still a single `ggshield` command, and
  every command behaves as before.

- AI hooks now resolve the file paths of `Read` tool calls and prompt `@`-mentions to an
  absolute path against the event's working directory. A file mentioned in a prompt and the
  same file later read by a tool now share one verdict-cache key, so it is scanned once
  instead of twice. As a result, the file path reported in block messages (and sent for
  scanning) is now absolute for prompt-mentioned files.

- The native hook accepts a `.gitguardian.yaml` key spelled with `-` or with `_`,
  but no longer resolves a config that sets the _same_ key in both spellings the
  way the Python implementation does: the last spelling in the file wins. Using
  one spelling per key, which every documented example does, is unaffected.

- When the AI hook blocks, its message now shows the `secret.ignored_matches`
  entry that would silence it, one line per detected secret. The message censors
  every match, so the entry could not previously be written by hand from what it
  showed. The value shown is the ignore sha, a digest rather than the secret,
  and is the same one `ggshield secret ignore --last-found` writes.

- `ggshield plugin install` and `ggshield plugin update` no longer send an
  installation report to the GitGuardian instance. The endpoint it targeted was
  never implemented, so the call always failed and was silently discarded.

- The GitGuardian logo shipped with ggshield is the refreshed one: the Chocolatey
  package icon uses the solid black mark, and the macOS desktop notification icon
  uses the app icon on its own dark ground.

- ggshield now requires `py-gitguardian` 1.34.0, which carries the
  `AgentInfo.subscription_email` field the AI discovery report sends.

### Fixed

- On macOS, `ggshield` no longer triggers the Xcode Command Line Tools install prompt
  when the tools are not installed.

- On macOS, `ggshield` no longer pops a "Keychain Not Found" dialog when checking
  whether the keyring is usable. The check now only reads from the credential
  store instead of writing a probe entry, which also stops it from silently
  falling back to file-based token storage on machines where the keychain can be
  read but not written.

- `ggshield secret scan ai-hook` no longer skips the scan when a Bash command starting with
  `cat` or `Get-Content` is not a plain file read (a heredoc, a redirection...).
  Such commands are now always scanned as text.

- `ggshield secret scan ai-hook` now scans only the lines an agent actually reads, instead of
  the whole file. A file over the API's 1 MiB document limit was skipped outright — allowed
  without being scanned at all — even when the agent only read a few hundred lines of it;
  that slice now scans normally. Ranges are read from Claude Code (`offset`/`limit`) and
  VS Code (`startLine`/`endLine`); a read without a range still scans the whole file.

- The AI discovery is now submitted to GitGuardian only when the local AI/MCP
  configuration actually changed, as it was always meant to be. A type mismatch
  between a freshly discovered MCP configuration and one read back from the local
  cache made the comparison always report a change, so every MCP tool call
  uploaded a full discovery payload.

- When a secret is found in a file mentioned in a prompt (`@path`), AI hooks now name
  that file in the block message instead of reporting it as a secret "in your prompt".
  The previous wording pointed at the wrong content and asked the user to edit a prompt
  that did not contain the secret.

- On macOS, the token stored by `ggshield auth login` is now created with a
  Keychain ACL trusting every ggshield binary, so the native hook can read it
  without prompting. Previously only the writing binary was trusted and each
  login reset the ACL, making "Always Allow" wear off.

- On macOS, `ggshield` no longer asks for Keychain access again after every upgrade. The
  code-signing identifier embedded a per-build hash, so the "Always Allow" grant recorded
  for one release stopped matching the next one; it is now pinned to
  `com.gitguardian.ggshield`. One grant made from a release built with this fix onwards
  keeps working across upgrades.

- The AI hooks no longer create incidents on your dashboard when `secret.source_uuid` is set
  in your configuration (a setting shared with CI scanning): a hook event is not a source
  scan, and every prompt and every file the agent read was creating an incident. They also
  now always scan with `all_secrets`, so they can block on a secret that is already known to
  GitGuardian instead of letting it through.

- `tomli` was added to the dev dependency group, without a marker, so dev environments always have it regardless of the
  Python interpreter, and ty can resolve the fallback branch it insists on analyzing

- `secret scan ai-hook` now honours `secret.ignored_paths` from
  `.gitguardian.yaml`, as every other `secret scan` command already did. A file
  excluded there is no longer read, sent, or blocked on when an agent reads it.
  Previously the setting was silently inert on this path. `ignored_matches` and
  `ignored_detectors` were never affected. This also brings the default
  exclusions to the hook: reads under `node_modules/`, `.venv/`, `vendor/`,
  `.git/` and the other `IGNORED_DEFAULT_WILDCARDS` entries are no longer
  scanned. Those defaults are matched against the path _relative to the project_
  and with symlinks resolved, so a checkout that itself lives under a directory
  named `vendor/`, `node_modules/` or `.venv/` is still scanned normally, and a
  symlink parked in a vendored tree cannot hide a file living outside it.

- On macOS, `ggshield auth login` no longer writes the token straight to the
  Apple Keychain when `PYTHON_KEYRING_BACKEND` selects another backend: the write
  now follows the backend the token is read back from. Previously login reported
  success while nothing could authenticate afterwards.
- `keyring` now requires 25.0 or later, the first version carrying the
  `create_cf` binding the Keychain ACL is built with. On 24.x the ACL silently
  never applied.

- AI discovery no longer reports MCP server configurations for agents that are not
  installed. A project `.mcp.json` is read by several agents, and Copilot also declared a
  hardcoded GitHub MCP server, so machines without those agents reported configurations
  they could not run.

- On macOS and Windows, `ggshield` now finds VSCode's user directory, so its global MCP
  servers and its known workspaces are discovered there too.

- The `cryptography` shipped in the released binaries is now 50.0.0, fixing
  `CVE-2026-69247`, a Bleichenbacher oracle in PKCS#7 `EnvelopedData` decryption.
  ggshield does not use that code path.

- The AI hook installed from the macOS standalone package now points at
  `/usr/local/bin/ggshield` instead of the versioned `/opt/gitguardian/ggshield-<version>/`
  directory an upgrade removes, so it keeps scanning after an upgrade.

- `ggshield machine setup` now repoints an AI hook command whose ggshield binary is gone,
  or is reachable through a more stable path, instead of leaving the broken command in
  place.

- On macOS, `ggshield machine setup` now asks the Keychain for access as the binary
  that actually runs the AI hook. Keychain grants are per binary, so the hook used to
  raise its own authorization dialog inside an agent-spawned process, where the agent's
  timeout could kill it before "Always Allow" was recorded and the dialog came back on
  every prompt.

- `ggshield` no longer reads the OS credential store on startup. The token is now
  fetched when a command actually needs it, so commands that do not use one (such as
  `ggshield config list`, `ggshield plugin list` and `ggshield install`) no longer
  trigger a macOS Keychain password prompt.

- `ggshield secret scan ai-hook` no longer leaves a whole event unscanned when the file path
  it guessed from a Bash command or an `@`-mention cannot be read. Such a candidate is
  dropped instead of being sent to the scanner, where the read error aborted the event and
  allowed the action with a "could not scan" warning, so the command or prompt text of that
  same event is now always scanned. A candidate longer than the filesystem's limits (a
  heredoc mistaken for a file name) is also recognized as text without a filesystem call.

<a id='changelog-1.53.0'></a>

## 1.53.0 — 2026-07-28

### Added

- `ggshield ai discover --activity` now also collects raw AI-agent activity
  (transcript lines / database rows) from Claude Code, Codex, Cursor, Copilot
  CLI and VSCode and ships it to GitGuardian, which scans the content and strips
  secrets server-side. This is an experimental feature.

- ggshield now officially supports Python 3.13: it is covered by the CI test matrix, advertised through the trove classifiers, and `pip install ggshield` works on a Python 3.13 interpreter.

- AI discovery now sends whether hooks are installed globally, per agent.

- `ggshield machine setup` sets up all of this machine's ggshield protections in one idempotent command: the AI hook for every detected AI coding assistant, the global git pre-commit/pre-push hooks, and a honeytoken. Each protection is on by default; drop one with `--no-ai-hooks` / `--no-git-hooks` / `--no-honeytokens`. Narrow which assistants get the AI hook with `--agent` / `--exclude-agent`. Replaces running `ggshield install -t <assistant>` once per agent.

- `ggshield machine setup` now installs git hooks **machine-wide** (for every user) when run as root or with the new `--system` flag, instead of only for the invoking user. This makes MDM/fleet deployments work as expected: a single root-run `machine setup` sets git's system `core.hooksPath`, so every user on the machine is covered. Without root (and without `--system`) it keeps installing per-user as before.

- `ggshield machine doctor` checks that this machine's ggshield protections are correctly set up: the AI hooks and git hooks are installed, the GitGuardian token is reachable and carries the scopes the configured protections need (`scan`, plus `honeytokens:write` and — when the `machine_scan` plugin is installed — `endpoints:send`, both of which require a Business or Enterprise plan), and that the plugin's native scanner loads. It is read-only, prints a specific fix for each failed check, and exits non-zero if any check fails, so it can gate an MDM rollout.

- Scan requests now include `Machine-Id` and `Machine-Username` headers

- AI scan requests now include the agent name in the headers sent to the scan route.

- `ggshield machine doctor` now detects when a higher-precedence git `core.hooksPath` (a repo-local or user-global one, e.g. Husky or lefthook) shadows the ggshield git hook. Git uses only the most-specific `core.hooksPath`, so such an override silently bypasses ggshield's system/global hook — doctor reports it as a failed "Git hook precedence" check (per repo) instead of giving a false sense of coverage.
- `ggshield machine setup` warns at install time when a `core.hooksPath` override takes precedence in the current context, so its git hook would be shadowed there.

- New `--filename-only` flag for `ggshield secret scan`: when set, only the file name (not its full path) is sent to GitGuardian, so incidents record just the filename (e.g. `config.py` instead of `src/app/config.py`). Recursive scanning still works.

- Plugins can now be installed machine-wide. Running `ggshield plugin install` or `ggshield plugin enable` as root writes to a shared system location so every user on the machine can load the plugin; non-root installs stay per-user as before. A user can still disable an admin-enabled plugin for themselves.

- `install.sh` now offers to add the install dir to your `PATH` itself when it's missing, instead of only printing instructions: it detects bash, zsh, fish, and (independent of `$SHELL`) Nushell and PowerShell on Linux when installed, and updates the matching shell profile. Prompted with a default of yes, silent under `-y`, skippable with the new `--no-modify-path`. `uninstall.sh` reverses the edit.

### Changed

- Documented the install script at the top of the README's Installation section, with the `curl | bash` (Linux/macOS) and `irm | iex` / `curl` (Windows) one-liners and a pointer to `scripts/install/README.md` for the full options and uninstall.

- The documented `curl | bash` install/uninstall one-liners no longer pass the redundant `--proto '=https'` and `--tlsv1.2` flags: the URLs are already `https://` and GitHub serves only TLS 1.2+, so they added nothing (`-sSfL`, including `-f`, is kept).

- The README marks the install script as the recommended install method and shows an example that authenticates against the EU workspace or a self-hosted instance.

- `ggshield auth login` now requests the `ai-discover:send` scope by default, enabling upload of AI discovery data to GitGuardian without requiring `--scopes ai-discover:send` explicitly.

- Documented the Windows MSI installer in the README's Windows installation section, with the release-page download and `msiexec` install command.

- The Linux/macOS install script now prints shell-specific guidance, as a visible warning, when `ggshield` won't be callable yet: either `~/.local/bin` is not on your `PATH`, or an older `ggshield` install shadows the new one. In both cases it gives the exact line to add for your shell (zsh/bash/fish/other) plus a reminder to restart your terminal, shown at the end of the run instead of a generic note buried mid-install.

- The install-scripts README documents `-y`/`--yes` and `bash -s -- --purge -y` for unattended uninstall.

- Relaxed the upper version bounds of several dependencies (`click`, `oauthlib`, `python-dotenv`, `pyyaml`, `requests` and `marshmallow-dataclass`) from the next minor release to the next major. This lets ggshield be installed alongside projects that require newer versions of these packages (for example `click` 8.2+) and lets users pull in dependency security fixes without waiting for a new ggshield release.

- `ggshield machine doctor` now also verifies the token carries the
  `ai-discover:send` scope, so a passing doctor run guarantees AI agent
  discovery telemetry can be uploaded.

- AI hook block messages now clearly state whether the secret already reached the agent, and add a "How to remediate" section with numbered steps and a `ggshield secret ignore --last-found` reminder for false positives. Known secrets link back to their GitGuardian incident. The block reason is now chosen from the event (UserPromptSubmit / PreToolUse / PostToolUse) before the tool, so a `PostToolUse` Read or MCP call is correctly reported as an actual leak instead of the "not executed yet" wording used before the tool call.

- Updated `pygitguardian` to 1.33.1, now pulled from PyPI instead of a pinned git commit.

### Deprecated

- `ggshield install -t <assistant>` (installing the AI hook per assistant) is deprecated in favor of `ggshield machine setup`, which configures all detected assistants at once. The command still works but now prints a deprecation notice. `ggshield install` remains the way to install git hooks (`-t pre-commit` / `-t pre-push`).

### Fixed

- Windows uninstaller: the `Remove the standalone ggshield at …?` confirmation now shows the install path. PowerShell treated the `?` in `$ZipDir?` as part of the variable name, so the path (and the `?`) were dropped from the prompt.

- `ggshield auth login` now reports a clear error when the token-exchange step receives a non-JSON HTTP response, instead of crashing with an opaque `AssertionError` and a raw traceback.

- A self-hosted instance deployed under a `gitguardian.com` / `gitguardian.tech` domain is no longer misdetected as SaaS. Its API URL now correctly gets the `/exposed` prefix, so `ggshield auth login` and other API calls reach the backend instead of the static frontend.

- README install and usage commands no longer include the leading `$` shell prompt, so copying them (via the GitHub or IDE copy button) yields a runnable command instead of `$ brew install ggshield`.

- A GitGuardian-hosted (SaaS) instance whose dashboard/API hostname carries a `dashboard-` / `api-` prefix is now correctly detected as SaaS. Its API URL is built by swapping the host instead of getting a spurious `/exposed` prefix, so API calls reach the backend instead of the static frontend.

- `ggshield api-status`, `ggshield auth login` and any command that reads token scopes now report a clear error when the GitGuardian API answers with a non-JSON body, instead of crashing with a raw `JSONDecodeError` traceback. This typically happens when the instance URL is wrong and the dashboard serves its HTML on a `2xx`.

- The install scripts no longer fail when an outdated or unauthenticated `gh` cannot verify the build provenance attestation (the cause of installs aborting with `unsupported tlog public key type: PKIX_ED25519` on a `gh` older than 2.56.0). Build-provenance verification is now opt-in on both `install.sh` and `install.ps1`: the install relies on the mandatory sha256 checksum by default and prints the manual `gh attestation verify` command. Set `GGSHIELD_REQUIRE_ATTESTATION=1` (or `true`/`yes`/`on`) to require it — that runs the check and fails the install if `gh` is missing, older than 2.56.0, unauthenticated, or the provenance does not verify.

- `uninstall.sh` no longer crashes and removes nothing when run with no controlling terminal (CI, cron, MDM/launchd/systemd rollback, containers). The confirmation prompt now detects an unusable `/dev/tty` and exits asking for `-y`, instead of aborting on an unbound variable under `set -u`.
- The standalone installer no longer silently ignores `--plugin` when combined with `--install-only`; it warns that the plugin was not installed (because `--install-only` skips authentication) and prints the command to run later.

- An enabled plugin that fails to load (for example when a native dependency is missing) is no longer silently ignored. `ggshield` now prints a warning naming the plugin and the reason its commands are unavailable, and `ggshield plugin list` reports the failure status.

- `ggshield config migrate` now reports a clear, actionable error when no configuration file is found (for example when run from the wrong directory), instead of crashing with a raw traceback. The deprecation message pointing to this command now also includes the path to the file and shows how to migrate it from anywhere with `--config-path`.

- ggshield now exits with a clear, actionable message when it is started on a Python interpreter older than 3.9 (for instance the system Python 3.6 shipped on RHEL 8 / CentOS 8), instead of crashing with a cryptic `ModuleNotFoundError` deep in startup.

- Fixed global hook silently skipping the local pre-commit hook in git worktrees. In linked worktrees, `.git` is a file pointer, not a directory, so the previous `[ -f .git/hooks/<hook-type> ]` check always failed. The hook now uses `git rev-parse --git-common-dir` to resolve the correct hooks path.

  **Existing installations must re-run `ggshield install --mode global --force`** to regenerate the hook script with the fix.

- `ggshield secret scan pypi` no longer relies on an external `pip` executable, so it no longer crashes when `pip` is missing or only available as `pip3`, and it can now download and scan packages whose required Python version differs from the one running ggshield.

- The machine identifier now reads and writes the shared `~/.ggshield/machine_id` cache that satori also uses, and the obsolete `~/.satori` fallback was removed. ggshield and satori now report a consistent machine identity, fixing honeytoken and discovery attribution when both tools run on the same machine.
- Placeholder SMBIOS UUIDs reported by unconfigured or cloned firmware (all-zeros, all-Fs, the AMI default) are no longer used as the machine identifier — machines with such firmware fall back to the shared cache instead of all colliding on one identity.
- The shared machine-id cache is now written with owner-only permissions and validated on the open file descriptor before being trusted, so the identifier stays stable under restrictive-umask setups and cannot be redirected through symlinks.

- AI hooks no longer crash under Codex. Codex sends `transcript_path` as a
  present-but-null field, which made agent detection raise a `TypeError` before
  Codex could be recognized, so every `PreToolUse`/`PostToolUse` hook exited 1.
  The detectors now treat a null `transcript_path` as absent, and the fail-open
  safety net catches any detection error so a hook can never break the agent.

- `ggshield ai discover` now finds MCP servers that Cursor, Claude Code and Codex plugins declare through a `mcpServers` manifest field holding an inline block, a path to a config file, or a list of either (e.g. the Datadog Cursor plugin), instead of silently skipping them.
- `ggshield ai discover` now reports the SSE transport for MCP servers declared with the `"type": "sse"` spelling used by Cursor, instead of HTTP.

- AI hook desktop notifications no longer crash the hook on macOS. The
  notification is now delivered through native `osascript` on macOS, so it
  works on Homebrew installs (which strip notifypy's bundled notifier) and on
  Apple Silicon (notifypy's bundled applet is Intel-only and Apple-deprecated).
  The whole notification step is also fully guarded, so a notifier failure can
  never prevent the `PostToolUse` block decision from being emitted.

- `ggshield install` for AI hooks no longer pins the hook to a non-existent
  binary path. When ggshield was invoked by bare name (`ggshield`, the normal
  pip/pipx/Homebrew case), `sys.argv[0]` is not rewritten by the shell, so the
  hook command was resolved against the current directory and pointed nowhere —
  the installed hooks then silently never ran. The running ggshield is now
  resolved against the install-time `PATH` (or `sys.executable` for the frozen
  standalone packages), so the hook command always points at a real binary.

- AI hooks now scan the arguments of MCP and unrecognized tool calls for
  secrets. Previously a `PreToolUse` event for such tools left the scanned
  content empty, so a secret passed as a tool argument was sent to the
  (potentially external) MCP server without being inspected. The serialized
  tool input is now scanned, so such a secret is blocked like one in a shell
  command.

- AI hooks no longer lose scans under parallel execution. Each hook reads the
  GitGuardian token from the OS keyring, and macOS rejects most _concurrent_
  reads of the login Keychain, so a fan-out of hooks (parallel agents or
  sub-agents, parallel tool calls) failed most reads with a spurious
  authentication error and silently skipped scanning. Keyring reads are now
  serialized with an advisory lock, so concurrent hooks all authenticate. No
  effect on file-based (non-keyring) setups or on Windows.

### Security

- Updated `urllib3` to 2.7.0 on Python 3.10+ to address CVE-2026-44431 (sensitive headers forwarded across origins on proxied redirects) and CVE-2026-44432 (decompression-bomb safeguards bypassed in the streaming API). Python 3.9 keeps urllib3 2.6.3, its last supported release.

- Bumped `cryptography` (48.0.1 on Python 3.10+, 46.0.7 on 3.9), `sigstore` (4.3.0 on 3.10+) and `pyOpenSSL` (26.2.0) to clear several advisories. cryptography 48.0.1 ships a patched OpenSSL (GHSA-537c-gmf6-5ccf) and fixes CVE-2026-26007, CVE-2026-34073 and CVE-2024-12797; the sigstore bump is required to unlock cryptography ≥ 48 and also resolves CVE-2026-24408; pyOpenSSL 26.2.0 resolves CVE-2026-27459 and CVE-2026-27448.

- Bumped `pyjwt` to 2.13.0 (clears CVE-2026-48526, CVE-2026-32597, CVE-2026-48522 and CVE-2026-48524) and `idna` to 3.18 (clears CVE-2026-45409). Both still support Python 3.9, so the fixes apply on every supported interpreter.

- Bumped `tuf` to 7.0.0 (clears GHSA-qp9x-wp8f-qgjj, platform-dependent delegation path matching). tuf 7 requires Python 3.10+, so installs on EOL Python 3.9 keep 6.0.0.

<a id='changelog-1.52.2'></a>

## 1.52.2 — 2026-06-17

### Added

- Install and uninstall scripts under `scripts/install/`: a one-line `curl | bash` (Linux/macOS) and `irm | iex` (Windows) installer for the standalone ggshield build that authenticates and optionally installs plugins, plus a matching uninstaller that removes the install it created.

### Changed

- Clarified the description of the `ggshield honeytoken plant` command.

- Widened the `marshmallow` dependency constraint to `>=3.18,<5`, so ggshield is now compatible with marshmallow 4. This unblocks environments (such as nixpkgs) that ship marshmallow 4.

### Fixed

- macOS: `ggshield machine scan` is no longer several times slower than on other platforms. The signed launcher now carries the `com.apple.security.cs.allow-jit` entitlement, so the scanner's PCRE2 JIT works under the hardened runtime instead of silently falling back to the interpreter.

<a id='changelog-1.52.1'></a>

## 1.52.1 — 2026-06-16

### Fixed

- `ggshield hmsl` Vault integration: list secrets correctly when a KV path has a leading slash, instead of failing against recent HashiCorp Vault versions that reject non-canonical paths.

- ggshield no longer crashes on startup when the optional `truststore` setup fails (for example on recent macOS versions where the OS version cannot be parsed). It now falls back to the bundled `certifi` certificates instead.

<a id='changelog-1.52.0'></a>

## 1.52.0 — 2026-06-15

### Added

- `ggshield ai discover --history` backfills historical MCP tool calls to GitGuardian (parsed from `~/.claude/projects/*/*.jsonl`). The API deduplicates events via idempotency keys, so reruns are safe.

- Improved MCP server name detection for more human-readable names.

- `ggshield honeytoken plant` reconciles this machine's honeytokens with
  GitGuardian and writes or removes the decoy AWS credential profiles on disk. Existing comments and file permissions are preserved.

- `ggshield install -t <agent>` now verifies after installing the hooks that ggshield can authenticate to GitGuardian, and warns with remediation steps if it cannot. On macOS, this also triggers the Keychain authorization prompt at a time the user can answer it, instead of inside a non-interactive agent-spawned hook.

- Standalone Linux artifacts are now also built for ARM (aarch64): tar.gz
  archive, .deb and .rpm packages.

### Changed

- Display an additional warning when the `.gitguardian.yaml` configuration file is missing the `version` field.

- `ggshield auth login` now requests broader default scopes (`scan`, `honeytokens:check`, `endpoints:send`). If any scope is not granted, a warning is printed but login still succeeds.

- `ggshield install -t <agent>` now pins the AI hook to the absolute path of the ggshield that ran the install, instead of a bare `ggshield`. The hook runs with a PATH that differs from the user's shell and across launch contexts, so on machines with several ggshield installations a bare command could resolve to a different binary than the one the user authenticated with. The stable launcher path is used (symlinks are not resolved) so it survives version upgrades; the bare command remains a fallback when the path cannot be determined.

- `ggshield plugin list` shows a verified plugin simply as `signed` instead of
  `signed (<signing-repository>)`. The signing identity is still recorded in the plugin
  manifest for auditing.

### Fixed

- AI hooks are debounced when an agent calls the same hook multiple times.

- OAuth local server now uses OS-assigned port (port 0) instead of the hardcoded range 29170-29998, eliminating port conflicts when running multiple ggshield instances or other tools.

- `ggshield plugin uninstall` no longer crashes with a raw `PermissionError` when plugin files cannot be removed. Read-only entries are now fixed automatically, and files owned by another user (e.g. residue from a legacy `sudo` install) produce a clear remediation message instead of a traceback.

- The AI hook (`ggshield secret scan ai-hook`) no longer crashes when it cannot authenticate or reach GitGuardian (e.g. when the API token is stored in the macOS Keychain and is not readable from an agent-spawned process). It now allows the action and warns the user through the agent that the action was NOT scanned, with remediation steps.

- AI hook: secrets in prompts submitted to GitHub Copilot CLI are now blocked before they reach the model. The prompt event was not recognized under Copilot CLI's native `userPromptSubmitted` name, and the inherited `{"continue": false}` output is ignored on the prompt event, so prompts containing secrets were let through. ggshield now maps the event and emits `{"decision": "block"}`, which Copilot CLI honors to cancel the prompt.

- Ignored secrets (for example secrets on context or deleted lines of a patch) no longer appear in plaintext when they show up in the context lines of another displayed secret.

- `ggshield plugin install` no longer fails with "failed to refresh TUF metadata" on
  locked-down or proxied networks (most often seen on Windows). Plugin signatures are
  now always verified against the sigstore trust root bundled with ggshield's
  dependencies rather than refreshing TUF metadata over the network. Plugin identity is
  still fully enforced; only trust-root freshness now tracks the pinned sigstore version.

<a id='changelog-1.51.0'></a>

## 1.51.0 — 2026-05-26

### Added

- `ggshield auth login --method oob` for browser-less environments (SSH sessions, headless servers). Prints the authorization URL, lets you open it on another device, and exchanges the code you paste back into the terminal. Uses the OAuth out-of-band sentinel (`urn:ietf:wg:oauth:2.0:oob`) — requires a server that supports it.

- Detection of MCP servers installed with Claude plugins or Claude.ai

- Add Codex support to `ggshield secret scan ai-hook` and `ggshield install -t codex`. (thanks to trickyfalcon)

- Detect MCP servers installed with Cursor plugins or Cursor extensions.

- Release binaries published to GitHub Releases now ship with [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds), providing signed SLSA build provenance. Users can verify a downloaded asset with `gh attestation verify <file> --repo GitGuardian/ggshield`, and tool managers such as mise (via the aqua backend) will verify automatically at install time.

- `ggshield plugin install` / `update` / `status` now discover and pull plugins from the GitGuardian instance the user is authenticated against, replacing the hard-coded GitHub release URL. Streaming download + sigstore bundle proxying happen via `/v1/endpoints/plugins/<reference>/{download,signature}`. Requires the matching backend feature.

- New `vscode` alias to "copilot" for hook installation.

- `ggshield api-status` now displays the workspace ID associated with the current token, in both text and JSON output.

### Changed

- Successful API key checks are now cached on disk for 5 minutes.

- `ggshield plugin list` now renders the install source from the manifest verbatim (`platform`, `local file`, `url`, `github release`, `github artifact`) instead of `local`/`pip`. Plugins installed without a manifest still fall back to `pip` (entry-point only) or `on-disk`.

- AI hooks naively try to detect file read by shell commands.

### Fixed

- Fixed plugin signature verification in PyInstaller-based packages by bundling sigstore's embedded TUF trust roots.

- Fixed `uv tool install ggshield` resolution by requiring sigstore 4, avoiding sigstore 3's transitive pre-release dependency on `betterproto`.

- The documentation of the `ai discover` command.

- Skip OS keyring access at startup when `GITGUARDIAN_API_KEY` is set in the environment (or in a `.env` file). This avoids redundant keychain unlock prompts on systems using multiple ggshield intances.

- Scans no longer fail on a single transient network glitch. ggshield retries connection errors (e.g. `ConnectionResetError`) and 502/503/504 responses with bounded exponential backoff (~15 s budget with jitter). `ggshield secret scan pre-receive` uses a minimal retry policy instead so it stays inside GitHub Enterprise Server's fixed 5 s pre-receive hook timeout.

- Fixed AI hooks support for Copilot CLI.

- (AI hooks): the command that leaked a secret is now shown in the notification message.

- MCP configuration parsing improved for VSCode, Copilot CLI and Codex.

- Plugin installs and updates now enable the canonical `ggshield.plugins` entry point instead of the wheel package name, migrating any pre-existing alias row (and preserving its `auto_update` setting), and local plugin wheels extract into the active runtime cache so mixed root/admin and user executions do not silently lose registered commands.

- ggshield now prunes stale extracted plugin wheel caches during plugin load and removes a plugin's extracted cache on uninstall, preventing old wheel versions from accumulating in the cache directory.

<a id='changelog-1.50.4'></a>

## 1.50.4 — 2026-05-07

### Fixed

- `ggshield plugin install --allow-unsigned` and `ggshield plugin update --allow-unsigned` now verify plugin signatures using the embedded / cached sigstore trust root instead of refreshing it over the network, so plugins can still be installed when the sigstore TUF endpoints are unreachable.

<a id='changelog-1.50.3'></a>

## 1.50.3 — 2026-04-30

### Fixed

- Skip OS keyring access at startup when `GITGUARDIAN_API_KEY` is set in the environment (or in a `.env` file). This avoids redundant keychain unlock prompts on systems using multiple ggshield instances.

<a id='changelog-1.50.2'></a>

## 1.50.2 — 2026-04-29

### Fixed

- Fixed `uv tool install ggshield` resolution by requiring sigstore 4, avoiding sigstore 3's transitive pre-release dependency on `betterproto`.

<a id='changelog-1.50.1'></a>

## 1.50.1 — 2026-04-29

### Fixed

- Fixed plugin signature verification in PyInstaller-based packages by bundling sigstore's embedded TUF trust roots.

<a id='changelog-1.50.0'></a>

## 1.50.0 — 2026-04-28

### Added

- ggshield is now available as a MSI package.

- Add sigstore signature verification for plugin wheels, enforcing identity-based trust via OIDC. Install and update operations are strict by default, while `--allow-unsigned` persists an explicit trust exception for the exact wheel hash so explicitly accepted unsigned plugins can still load at runtime.

- API tokens are now stored in the OS credential store (macOS Keychain, Windows Credential Locker, Linux Secret Service) via the `keyring` library instead of cleartext in `auth_config.yaml`. Existing cleartext tokens are migrated automatically the next time the configuration is saved. If no OS credential store is available or `GGSHIELD_NO_KEYRING=1`, file-based storage is used as a fall-back.

- Added a new `secret.fail_on_server_error` configuration option (default `True`), available as the `--fail-on-server-error/--no-fail-on-server-error` flag or `GITGUARDIAN_FAIL_ON_SERVER_ERROR` environment variable. When set to `False`, `secret scan pre-commit`, `secret scan pre-push`, `secret scan pre-receive`, and `secret scan ci` exit with code `0` and display a warning instead of blocking the git operation when the GitGuardian server is unreachable or returns a 5xx response. The default preserves the previous blocking behavior.

- New `ggshield ai discover` command.

- The AI hooks now also log/block MCP activity

### Changed

- **Breaking**: `secret scan pre-receive` no longer fail-opens by default when the GitGuardian server returns a 5xx response. Previously the push was allowed through with a warning; now it is blocked, matching the other git hooks. Set `secret.fail_on_server_error` to `False` (or pass `--no-fail-on-server-error`) to restore the previous fail-open behavior.

### Fixed

- Forward `signature_mode` through GitHub release and GitHub artifact download paths, ensuring signature verification is applied consistently across all install sources.

- Scans of large repositories no longer fail on a single transient network glitch. ggshield now retries connection errors (e.g. `ConnectionResetError`) and 502/503/504 responses with bounded exponential backoff.

- Global Copilot hooks are configured correctly in `~/.copilot`.

### Security

- Pin the default package index in `pyproject.toml` to public PyPI and add a rolling `exclude-newer = "3 days"` constraint, so the resolved `uv.lock` is reproducible for external contributors/CI and newly-published (potentially malicious) releases get a short quarantine window before they can land in the lock.

<a id='changelog-1.49.0'></a>

## 1.49.0 — 2026-03-31

### Removed

- Pre-receive hook on GitHub Enterprise Server v3.9 to v3.13 is no longer supported. v3.13 is EOL since [2025-06-19](https://docs.github.com/en/enterprise-server@3.13/admin/release-notes) and previous versions were discontinued earlier.

### Added

- Add `@file` support to `secret scan path` to load scan paths from a file.

- Add `ggshield secret scan ai-hook` command to scan AI coding tool hook payloads for secrets in real time.
- Add new types `claude-code|cursor|copilot` to the `ggshield install` command to install hooks into AI coding tool configurations.

- Pre-receive hook can now be set up on GitHub Enterprise Server from v3.14 to higher.

- `api-status`: display the scopes of the current authentication token.

### Fixed

- `secret scan ci`: fetch the target branch before computing the MR/PR commit range. In CI environments with cached repos or shallow clones, a stale target branch ref could cause ggshield to scan unrelated commits, leading to excessive API calls and secrets reported in files not modified by the MR.

- `hmsl vault-scan`: fixed a hang when the HashiCorp Vault server is unresponsive; requests now time out after 30 seconds and network errors are reported with a clear message.

- Fixed a path traversal security issue in tar archives used for git-based scans; member names with absolute paths or `..` components are now sanitized.

- Fixed an issue where an invalid option for a `secret scan` subcommand could be silently treated as a request to run the default command, producing a confusing error instead of the expected usage error.

<a id='changelog-1.48.0'></a>

## 1.48.0 — 2026-02-17

### Added

- Add enterprise plugin system for ggshield, allowing organizations to install and manage plugins from GitGuardian.

- `hmsl`: Secrets shorter than 6 characters are now filtered out before being sent to the HMSL API, reducing false positives from obvious non-secrets.

### Changed

- `hmsl`: Expand the list of excluded placeholder values (e.g., `changeme`, `placeholder`, `redacted`) that are not sent to the HMSL API.

- Relax `urllib3` dependency pin from `~=2.2.2` to `>=2.2.2,<3`, allowing compatibility with newer urllib3 versions (#1160).

### Fixed

- Prevent docker scan stdout from leaking into JSON output.

<a id='changelog-1.47.0'></a>

## 1.47.0 — 2026-01-27

### Added

- Display a warning if .cache_ggshield is not ignored in a git repository.

<a id='changelog-1.46.0'></a>

## 1.46.0 — 2025-12-29

### Added

- A HTTPAdapter with wider parameters has been setup to better address scanning multiple files at the same time.

- Add `GITGUARDIAN_GIT_REMOTE_FALLBACK_URL` environment variable that allows setting a fallback value for the repository remote.

- Tokens are obfuscated in `ggshield config list` output.

### Changed

- Clearer error message when token is missing: specify the command to run to generate a token (ggshield auth login).

### Fixed

- Install `ggshield` hooks inside `.husky/` when the repository uses Husky-managed hooks so local installs work out of the box. (#1143).

<a id='changelog-1.45.0'></a>

## 1.45.0 — 2025-11-14

### Fixed

- ggshield no longer crashes when scanning invalid symlinks, it emits a warning instead.

- Handle unmerged files in pre-commit scanning during an ongoing merge.

- Fixed crash when ggshield received missing tags.

<a id='changelog-1.44.1'></a>

## 1.44.1 — 2025-10-28

### Changed

- Fixed Python version for PDM install in the build release workflow.

<a id='changelog-1.44.0'></a>

## 1.44.0 — 2025-10-27

### Added

- Added `--insecure` CLI option and `insecure` configuration setting as clearer alternatives to `--allow-self-signed` and `allow_self_signed`. The new option explicitly communicates that SSL verification is completely disabled, making the connection vulnerable to man-in-the-middle attacks.
- Added prominent warning messages when SSL verification is disabled (via either `--insecure` or `--allow-self-signed`), explaining the security risks and recommending the secure alternative of using the system certificate trust store (available with Python >= 3.10).

### Changed

- Removed Clear Linux from the OS package testing workflow as the project has been discontinued.

### Deprecated

- The `--allow-self-signed` CLI option and `allow_self_signed` configuration setting are now deprecated in favor of `--insecure` and `insecure`. Deprecation warnings are displayed when these options are used, guiding users to the clearer alternative. Both options remain functional for backward compatibility and will be maintained for an extended deprecation period before removal.

### Fixed

- Fixed crash when API returns scopes not yet recognized by py-gitguardian.

- Skip non-seekable files instead of crashing.

### Security

- Improved clarity around SSL verification settings. The `--allow-self-signed` option name was misleading as it suggests certificate validation is still performed, when in reality all SSL verification is disabled. The new `--insecure` option makes this behavior explicit. Both options remain functional for backward compatibility.

<a id='changelog-1.43.0'></a>

## 1.43.0 — 2025-08-27

### Fixed

- Fixed PyInstaller deprecation warning when running PyInstaller-based ggshield.

- Scanning git repositories can no longer fail with git "dubious ownership" errors.

- Extended the range of API error status codes supported by ggshield so the UI correctly displays them.

<a id='changelog-1.42.0'></a>

## 1.42.0 — 2025-07-29

### Added

- Added an additional section in `ggshield` outputs to return vault related fields if the account setting is enabled.

- `ggshield` Docker image now supports both linux/amd64 and linux/arm64 architectures (#952).

- `ggshield secret scan docker` now scans more files.

### Changed

- `ggshield secret scan` now provides an `--source-uuid` option. When this option is set, it will create the incidents on the GIM
  dashboard on the corresponding source. Note that the token should have the scope `scan:create-incidents`.

<a id='changelog-1.41.0'></a>

## 1.41.0 — 2025-06-24

### Changed

- When scanning a docker image, if no image is found matching the client platform, try to pull the `linux/amd64` image.

<a id='changelog-1.40.0'></a>

## 1.40.0 — 2025-05-27

### Added

- The release assets now contain a NuGet package.

- Added a new section in `ggshield` outputs (text and JSON) to notify if a secret is in one of the accounts' secrets managers.

### Changed

- `ggshield secret scan docker` now scans files in `/usr/src/app`.

### Fixed

- Fixed a bug in the way `ggshield` obfuscated secrets that caused a crash for short secrets (#1086).

- `ggshield` no longer crashes when it can't find git.

<a id='changelog-1.39.0'></a>

## 1.39.0 — 2025-04-29

### Added

- `ggshield` is now available on Chocolatey (#934).

- `ggshield secret scan` output now contains a link to the detector documentation for each secret found.

### Fixed

- Fixed error when scanning `.tar.gz` compressed files inside docker layers.

<a id='changelog-1.38.1'></a>

## 1.38.1 — 2025-04-02

### Added

- ggshield can now scan .jar files using `ggshield secret scan archive`.

<a id='changelog-1.38.0'></a>

## 1.38.0 — 2025-03-27

### Removed

- Removed support for python 3.8.

### Added

- ggshield now uses the system certificates instead of the bundled ones. Note that this only works with Python >= 3.10 (#1067).

### Changed

- Pre-receive hook isn't blocking anymore when GitGuardian server is temporarily unavailable (return 5xx status code).

### Fixed

- Files with emojis in their name are now handled properly.

- Fix ggshield crashing on Windows when doing big merges (#1032).

<a id='changelog-1.37.0'></a>

## 1.37.0 — 2025-03-03

### Fixed

- `ggshield secret scan docker` now correctly handles ignored paths (#548).

<a id='changelog-1.36.0'></a>

## 1.36.0 — 2025-01-27

### Removed

- `ggshield sca` and `ggshield iac` commands have been removed.

### Fixed

- The `--instance` option now accepts both https://api.eu1.gitguardian.com/v1 or https://api.gitguardian.com/v1.

- Fix `ggshield secret scan pre-commit` crashing on big merges (#1032).

<a id='changelog-1.35.0'></a>

## 1.35.0 — 2025-01-08

### Added

- `ggshield secret scan` now provides an `--all-secrets` option. When this option is set, it lists all found secrets and their possible ignore reason.

### Changed

- Files contained in the `.git/` directory are now scanned. Files in subdirectories such as `.git/hooks` are still excluded.

- When scanning commits, ggshield now ignores by default secrets that are removed or contextual to the patch.

### Fixed

- Handle trailing content in multi-parent hunk header.

- Installing ggshield from the release RPM on EL9 failed because of a missing library. This is now fixed (#1036).

- Fix Visual Studio not being able to show error messages from ggshield pre-commit (#170).

<a id='changelog-1.34.0'></a>

## 1.34.0 — 2024-11-27

### Added

- `ggshield config list` command now supports the `--json` option, allowing output in JSON format.

- All `secret scan` commands as well as the `api-status` and `quota` commands now supports the `--instance` option to allow using a different instance.

- The `api-status` command now prints where the API key and instance used come from.

### Changed

- `ggshield api-status --json` output now includes the instance URL.

- `ggshield secret scan repo` now uses `git clone --mirror` to retrieve more git objects.

- `ggshield secret scan ci` now scans all commits of a Pull Request in the following CI environments: Jenkins, Azure, Bitbucket and Drone.

### Deprecated

- ggshield now prints a warning message when it is being run executed by Python 3.8.

### Fixed

- When running `ggshield secret scan ci` in a GitLab CI, new commits from the target branch that are not on the feature branch will no longer be scanned.

- Take into account the `--allow-self-signed` option at all levels in `ggshield secret scan` commands.

- When `ggshield secret scan` is called with `--with-incident-details` and the token does not have the required scopes, the command now fails and an error message is printed.

- ggshield no longer fails to report secrets for patches with content in hunk header lines.

<a id='changelog-1.33.0'></a>

## 1.33.0 — 2024-10-29

### Changed

- The `--debug` option now automatically turns on verbose mode.

- The `--use-gitignore` option now also applies to single files passed as argument.

- RPM packages now depend on `git-core` instead of `git`, reducing the number of dependencies to install (#983).

### Fixed

- When using the `--debug` option, the log output no longer overlaps with the progress bars.

- The ggshield pre-commit hook no longer crashes when merging files with spaces in their names (#991).

- RPM packages now work correctly on RHEL 8.8 (#984).

<a id='changelog-1.32.2'></a>

## 1.32.2 — 2024-10-16

### Fixed

- Fixed a regression introduced in ggshield 1.32.1, which made `ggshield install -m global` crash (#972).

<a id='changelog-1.32.1'></a>

## 1.32.1 — 2024-10-01

### Fixed

- Fixed a case where ggshield commit parser could fail because of the local git configuration.

<a id='changelog-1.32.0'></a>

## 1.32.0 — 2024-09-24

### Added

- When scanning a merge commit, `ggshield secret scan pre-commit` now skips files that merged without conflicts. This makes merging the default branch into a topic branch much faster. You can use the `--scan-all-merge-files` option to go back to the previous behavior.

- `ggshield secret scan` commands now provide the `--with-incident-details` option to output more information about known incidents (JSON and SARIF outputs only).

- It is now possible to ignore a secret manually using `ggshield secret ignore SECRET_SHA --name NAME`.

### Fixed

- The git commit parser has been reworked, fixing cases where commands scanning commits would fail.

<a id='changelog-1.31.0'></a>

## 1.31.0 — 2024-08-27

### Added

- We now provide tar.gz archives for macOS, in addition to pkg files.

### Fixed

- JSON output: fixed incorrect values for line and index when scanning a file and not a patch.

<a id='changelog-1.30.2'></a>

## 1.30.2 — 2024-08-05

### Security

- Fixed a bug where `ggshield secret scan archive` could be passed a maliciously crafted tar archive to overwrite user files.

<a id='changelog-1.30.1'></a>

## 1.30.1 — 2024-07-30

### Added

- `ggshield secret scan` commands can now output results in [SARIF format](https://sarifweb.azurewebsites.net/), using the new `--format sarif` option (#869).

- `ggshield sca scan ci` and `ggshield sca scan all` now support the `MALICIOUS` value for `--minimum-severity`

### Changed

- ggshield now has the ability to display custom remediation messages on pre-commit, pre-push and pre-receive. These messages are defined in the platform and fetched from the `/metadata` endpoint of the API. If no messages are set up on the platform, default remediation messages will be displayed as before.

<a id='changelog-1.30.0'></a>

## 1.30.0 — 2024-07-30

Yanked: release process issue.

<a id='changelog-1.29.0'></a>

## 1.29.0 — 2024-06-25

### Removed

- The `--all` option of the `ggshield sca scan ci` and `ggshield iac scan ci` commands has been removed.

### Added

- `ggshield secret scan path` now provides a `--use-gitignore` option to honor `.gitignore` and related files (#801).

- A new secret scan command, `ggshield secret scan changes`, has been added to scan changes between the current state of a repository checkout and its default branch.

- GGShield is now available as a standalone executable on Windows.

### Changed

- The behavior of the `ggshield sca scan ci` and `ggshield iac scan ci` commands have changed. These commands are now expected to run in merge-request CI pipelines only, and will compute the diff exactly associated with the merge request.

### Deprecated

- Running `ggshield sca scan ci` or `ggshield iac scan ci` outside of a merge request CI pipeline is now deprecated.

### Fixed

- GGShield now consumes less memory when scanning large repositories.

- Errors thrown during `ggshield auth login` flow with an invalid instance URL are handled and the stack trace is no longer displayed on the console.

- Patch symbols at the start of lines are now always displayed, even for single line secrets.

- The `ggshield auth login` command now respects the `--allow-self-signed` flag.

- GGShield now exits with a proper error message instead of crashing when it receives an HTTP response without `Content-Type` header.

<a id='changelog-1.28.0'></a>

## 1.28.0 — 2024-05-29

### Added

- The SCA config `ignored_vulnerabilities` option now supports taking a CVE ID as identifier.

<a id='changelog-1.27.0'></a>

## 1.27.0 — 2024-04-30

### Removed

- The `This feature is still in beta, its behavior may change in future versions` warning is no longer displayed for sca commands.

### Added

- It is now possible to customize the remediation message printed by GGShield pre-receive hook. This can be done by setting the message in the `secret.prereceive_remediation_message` configuration key. Thanks a lot to @Renizmy for this feature.

- We now provide signed .pkg files for macOS.

- Add a `This feature is still in beta, its behavior may change in future versions` warning to `ggshield iac scan all` command.

### Changed

- Linux .deb and .rpm packages now use the binaries produced by pyinstaller. They no longer depend on Python.

### Deprecated

- Dash-separated configuration keys are now deprecated, they should be replaced with underscore-separated keys. For example `show-secrets` should become `show_secrets`. GGShield still supports reading from dash-separate configuration keys, but it prints a warning when it finds one.

### Fixed

- GGShield commands working with commits no longer fail when parsing a commit without any author.

- Configuration keys defined in the global configuration file are no longer ignored if a local configuration file exists.

- The option `--exclude PATTERN` is no longer ignored by the command `ggshield secret scan repo`.

<a id='changelog-1.26.0'></a>

## 1.26.0 — 2024-03-27

### Added

- `ggshield auth login` learned to create tokens with extra scopes using the `--scopes` option. Using `ggshield auth login --scopes honeytokens:write` would create a token suitable for the `ggshield honeytokens` commands.

<a id='changelog-1.25.0'></a>

## 1.25.0 — 2024-02-27

### Added

- It is now possible to create a honeytoken with context using the new `honeytoken create-with-context` command.

### Changed

- SCA incidents ignored on the GitGuardian app will no longer show up in the scan results, in text/JSON format.

<a id='changelog-1.24.0'></a>

## 1.24.0 — 2024-01-30

### Added

- Adds two new flags for `ggshield sca scan` commands, `--ignore-fixable` and `--ignore-not-fixable` so that the user can filter the returned incidents depending on if incidents can be fixed or not. Both flags cannot be used simultaneously.

### Changed

- Number of documents in a chunk is now adapted to the server payload.
- Moved some property from Scannable children classes up to Scannbable itself.

### Fixed

- IAC/SCA scans will scan new commits as intended for CI jobs on newly pushed branches.
- IAC/SCA scans will scan new commits as intended for CI jobs on the first push to a new repository

- In CI jobs, IAC/SCA scans on forced pushs no longer trigger an error but perform a scan on all commits instead.

- Fixes `ggshield sca scan` commands not taking some user parameters into account.

<a id='changelog-1.23.0'></a>

## 1.23.0 — 2024-01-09

### Added

- GGShield output now adapts when the grace period of an IaC incident ignored by a developer has been expired.

- GGShield now shows a warning message if it hits a rate-limit.

### Changed

- IaC incidents ignored on the GitGuardian app no longer show up in the scan results.

### Fixed

- IaC/SCA scans now properly find the parent commit SHA on GitLab push pipelines for new branches.

- Error messages now appear above progress bars instead of overlapping them.

#### IaC

- File content are now displayed as intended when executing `ggshield iac scan all` on a subdirectory of a Git repository.

- Pre-push scans are now diff scans when pushing a new branch, comparing to the last commit of the parent branch.

- Pre-push scans on empty repositories no longer include staged files.

<a id='changelog-1.22.0'></a>

## 1.22.0 — 2023-11-28

### Added

- Secret: GGShield now prints the name of what is being scanned when called with `--verbose` (#212).

- You can now use the `SKIP=ggshield` environment variable without the [pre-commit framework](https://pre-commit.com/) to skip pre-commit and pre-push scans.

### Changed

- GGShield can now scan huge commits without running out of memory.

### Fixed

- IaC and SCA: scans in GitLab merge request pipelines should now be performed on the intended commit ranges, instead of an empty range.

<a id='changelog-1.21.0'></a>

## 1.21.0 — 2023-11-09

### Added

- Support for new options in GitGuardian config file. IaC `ignored-paths` and `ignored_policies` can now be defined as objects with `comment` and `until` properties. If an `until` date is provided, the path/policy is only ignored up until this date. The old format is still supported. Check `.gitguardian.example.yaml` for a sample.

### Changed

- `ggshield iac scan diff --json` output was changed. `added_vulns`, `persisting_vulns` and `removed_vulns` were renamed as `new`, `unchanged` and `deleted`. They also were moved into a `entities_with_incidents` similarly to the scan all JSON output.
  <details>
    <summary>Sample IaC diff JSON output</summary>

      ```json
      {
          "id": "fb0e9a92-de34-43f9-b779-17d25e99ab35",
          "iac_engine_version": "1.15.0",
          "type": "diff_scan",
          "entities_with_incidents": {
              "unchanged": [
                  {
                      "filename": "s3.tf",
                      "incidents": [
                          {
                              "policy": "Allowing public exposure of a S3 bucket can lead to data leakage",
                              "policy_id": "GG_IAC_0055",
                              "line_end": 118,
                              "line_start": 96,
                              "description": "AWS S3 Block Public Access is a feature that allows setting up centralized controls\\nto manage public access to S3 resources.\\n\\nEnforcing the BlockPublicAcls, BlockPublicPolicy and IgnorePublicAcls rule on a bucket\\nallows to make sure that no ACL (Access control list) or policy giving public access\\ncan be associated with the bucket, and that existing ACL giving public access to\\nthe bucket will not be taken into account.",
                              "documentation_url": "<https://docs.gitguardian.com/iac-scanning/policies/GG_IAC_0055>",
                              "component": "aws_s3_bucket.operations",
                              "severity": "HIGH"
                          }
                      ],
                      "total_incidents": 1
                  }
              ],
              "deleted": [
              {
                  "filename": "s3.tf",
                      "incidents": [
                          {
                              "policy": "Allowing public exposure of a S3 bucket can lead to data leakage",
                              "policy_id": "GG_IAC_0055",
                              "line_end": 118,
                              "line_start": 96,
                              "description": "AWS S3 Block Public Access is a feature that allows setting up centralized controls\\nto manage public access to S3 resources.\\n\\nEnforcing the BlockPublicAcls, BlockPublicPolicy and IgnorePublicAcls rule on a bucket\\nallows to make sure that no ACL (Access control list) or policy giving public access\\ncan be associated with the bucket, and that existing ACL giving public access to\\nthe bucket will not be taken into account.",
                              "documentation_url": "<https://docs.gitguardian.com/iac-scanning/policies/GG_IAC_0055>",
                              "component": "aws_s3_bucket.operations",
                              "severity": "HIGH",
                          }
                      ],
                      "total_incidents": 1
                  }
              ],
              "new": [
              {
                  "filename": "s3.tf",
                      "incidents": [
                          {
                              "policy": "Allowing public exposure of a S3 bucket can lead to data leakage",
                              "policy_id": "GG_IAC_0055",
                              "line_end": 118,
                              "line_start": 96,
                              "description": "AWS S3 Block Public Access is a feature that allows setting up centralized controls\\nto manage public access to S3 resources.\\n\\nEnforcing the BlockPublicAcls, BlockPublicPolicy and IgnorePublicAcls rule on a bucket\\nallows to make sure that no ACL (Access control list) or policy giving public access\\ncan be associated with the bucket, and that existing ACL giving public access to\\nthe bucket will not be taken into account.",
                              "documentation_url": "<https://docs.gitguardian.com/iac-scanning/policies/GG_IAC_0055>",
                              "component": "aws_s3_bucket.operations",
                              "severity": "HIGH"
                          }
                      ],
                      "total_incidents": 1
                  }
              ]
          }
      }
      ```

  </details>

### Fixed

- When a git command fails, its output is now always correctly logged.

<a id='changelog-1.20.0'></a>

## 1.20.0 — 2023-10-17

### Changed

#### HMSL

- Adapt message in case we find tons of matches

- command `hmsl check-secret-manager hashicorp-vault` with a "key" naming strategy will display the variable's full path instead of the variable name

- Support no location URL in HMSL response.

- Change wording for HMSL output: do not mention occurrences as it can be misleading.

## 1.19.1 - 2023-09-26

- Internal fixes to unblock release process

<a id='changelog-1.19.0'></a>

## 1.19.0 — 2023-09-26

### Removed

- ggshield now refuses to install on python < 3.8.

### Added

#### HMSL

- Added new `ggshield hmsl check-secret-manager hashicorp-vault` command to scan secrets of an [HashiCorp Vault](https://www.hashicorp.com/products/vault) instance.

### Changed

- Help messages have been improved and are now kept in sync with [ggshield online reference documentation](https://docs.gitguardian.com/ggshield-docs/reference/overview).

### Fixed

- Fixed a typo in the command suggested to tell git a directory is safe.

- The bug on Gitlab CI for IaC and SCA, failing because git does not access the target branch in a merge request is fixed. Now fetches the target branch in the CI env before collecting commit shas.

- Fix IaC and SCA scan commands in Windows

<a id='changelog-1.18.1'></a>

## 1.18.1 — 2023-08-22

### Fixed

- Fixed a bug which caused IaC and SCA scans to fail on GitLab CI because GitLab does not run `git fetch` on the target branch for merge requests. ggshield now runs `git fetch` itself to avoid this problem.

- Fixed a typo in the command suggested to tell git a directory is safe.

<a id='changelog-1.18.0'></a>

## 1.18.0 — 2023-08-16

### Added

#### HMSL

- ggshield gained a new group of commands: `hmsl`, short for "Has My Secret Leaked". These commands make it possible to securely check if secrets have been leaked in a public repository.

#### IaC

- `ggshield iac scan` now provides three new commands for use as Git hooks:
  - `ggshield iac scan pre-commit`
  - `ggshield iac scan pre-push`
  - `ggshield iac scan pre-receive`

  They use the same arguments and options as the other `ggshield iac scan` commands.

- The new `ggshield iac scan ci` command can be used to perform IaC scans in CI environments.
  It supports the same arguments as hook subcommands (in particular, `--all` to scan the whole repository).
  Supported CIs are:
  - Azure
  - Bitbucket
  - CircleCI
  - Drone
  - GitHub
  - GitLab
  - Jenkins
  - Travis

#### SCA

- Introduces new commands to perform SCA scans with ggshield:
  - `ggshield sca scan all <DIRECTORY>` : scans a directory or a repository to find all existing SCA vulnerabilities.
  - `ggshield sca scan diff <DIRECTORY> --ref <GIT_REF>`: runs differential scan compared to a given git ref.
  - `ggshield sca scan pre-commit`
  - `ggshield sca scan pre-push`
  - `ggshield sca scan pre-receive`
  - `ggshield sca scan ci`: Evaluates if a CI event introduces new vulnerabilities, only available on Github and Gitlab for now.

#### Other

- It is now possible to manipulate the default instance using `ggshield config`:
  - `ggshield config set instance <THE_INSTANCE_URL>` defines the default instance.
  - `ggshield config unset instance` removes the previously defined instance.
  - The default instance can be printed with `ggshield config get instance` and `ggshield config list`.

### Changed

- ggshield now requires Python 3.8.

- The IaC Github Action now runs the new `ggshield iac scan ci` command. This means the action only fails if the changes introduce a new vulnerability. To fail if any vulnerability is detected, use the `ggshield iac scan ci --all` command.

### Removed

- The following options have been removed from `ggshield iac scan diff`: `--pre-commit`, `--pre-push` and `--pre-receive`. You can replace them with the new `ggshield iac scan pre-*` commands.

### Fixed

- `ggshield secret scan docker` now runs as many scans in parallel as the other scan commands.

- `ggshield` now provides an easier-to-understand error message for "quota limit reached" errors (#309).

- `ggshield iac scan diff` `--minimum-severity` and `--ignore-policy` options are now correctly processed.

- `ggshield secret scan` no longer tries to scan files longer than the maximum document size (#561).

### Security

- ggshield now depends on cryptography 41.0.3, fixing https://github.com/advisories/GHSA-jm77-qphf-c4w8.

<a id='changelog-1.17.3'></a>

## 1.17.3 — 2023-07-27

### Fixed

- Pin PyYAML>=6.0.1 to fix building (see https://github.com/yaml/pyyaml/pull/702)

<a id='changelog-1.17.2'></a>

## 1.17.2 — 2023-06-28

### Fixed

- Fixed ggshield not installing properly when installing with Brew on macOS.

<a id='changelog-1.17.1'></a>

## 1.17.1 — 2023-06-28

### Added

- New command: `ggshield iac scan all`. This command replaces the now-deprecated `ggshield iac scan`. It scans a directory for IaC vulnerabilities.

- New command: `ggshield iac scan diff`. This command scans a Git repository and inspects changes in IaC vulnerabilities between two points in the history.
  - All options from `ggshield iac scan all` are supported: `--ignore-policy`, `--minimum-severity`, `--ignore-path` etc. Execute `ggshield iac scan diff -h` for more details.
  - Two new options allow to choose which state to select for the difference: `--ref <GIT-REFERENCE>` and `--staged`.
  - The command can be integrated in Git hooks using the `--pre-commit`, `--pre-push`, `--pre-receive` options.
  - The command output list vulnerabilities as `unchanged`, `new` and `deleted`.

- Added a `--log-file FILE` option to redirect all logging output to a file. The option can also be set using the `$GITGUARDIAN_LOG_FILE` environment variable.

### Changed

- Improved `secret scan path` speed by updating charset-normalizer to 3.1.

- Errors are no longer reported twice: first using human-friendly message and then using log output. Log output is now off by default, unless `--debug` or `--log-file` is set (#213).

- The help messages for the `honeytoken` commands have been updated.

- `ggshield honeytoken create` now displays an easier-to-understand error message when the user does not have the necessary permissions to create an honeytoken.

- `ggshield auth login` now displays a warning message if the token expiration date has been adjusted to comply with the personal access token maximum lifetime setting of the user's workspace.

### Deprecated

- `ggshield iac scan` is now replaced by the new `ggshield iac scan all`, which supports the same options and arguments.

<a id='changelog-1.16.0'></a>

## 1.16.0 — 2023-05-30

### Added

- Add a new `ggshield honeytoken create` command to let you create honeytokens if enabled in your workspace.
  Learn more about honeytokens at https://www.gitguardian.com/honeytoken

### Changed

- `ggshield secret scan` commands can now use server-side configuration for the maximum document size and maximum document count per scan.

### Fixed

- Accurately enforce the timeout of the pre-receive secret scan command (#417)

- Correctly compute the secret ignore sha in the json output.

- GitLab WebUI Output Handler now behaves correctly when using the `ignore-known-secrets` flag, it also no longer displays empty messages in the UI.

<a id='changelog-1.15.1'></a>

## 1.15.1 — 2023-05-17

### Changed

- `ggshield secret scan` JSON output has been improved:
  - It now includes an `incident_url` key for incidents. If a matching incident was found in the user's dashboard it contains the URL to the incident. Otherwise, it defaults to an empty string.
  - The `known_secret` key is now always present and defaults to `false` if the incident is unknown to the dashboard.

### Fixed

- Fixed a regression introduced in 1.15.0 which caused the `--ignore-known-secrets` option to be ignored.

<a id='changelog-1.15.0'></a>

## 1.15.0 — 2023-04-25

### Changed

- `ggshield secret scan` output now includes a link to the incident if the secret is already known on the user's GitGuardian dashboard.

- `ggshield secret scan docker` no longer rescans known-clean layers, speeding up subsequent scans. This cache is tied to GitGuardian secrets engine version, so all layers are rescanned when a new version of the secrets engine is deployed.

### Fixed

- Fixed an issue where the progress bar for `ggshield secret scan` commands would sometimes reach 100% too early and then stayed stuck until the end of the scan.

### Removed

- The deprecated commands `ggshield scan` and `ggshield ignore` have been removed. Use `ggshield secret scan` and `ggshield secret ignore` instead.

<a id='changelog-1.14.5'></a>

## 1.14.5 — 2023-03-29

### Changed

- `ggshield iac scan` can now be called without arguments. In this case it scans the current directory.

- GGShield now displays an easier-to-understand error message when no API key has been set.

### Fixed

- Fixed GGShield not correctly reporting misspelled configuration keys if the key name contained `-` characters (#480).

- When called without an image tag, `ggshield secret scan docker` now automatically uses the `:latest` tag instead of scanning all versions of the image (#468).

- `ggshield secret scan` now properly stops with an error message when the GitGuardian API key is not set or invalid (#456).

<a id='changelog-1.14.4'></a>

## 1.14.4 — 2023-02-23

### Fixed

- GGShield Docker image can now be used to scan git repositories even if the repository is mounted outside of the /data directory.

- GGShield commit hook now runs correctly when triggered from Visual Studio (#467).

<a id='changelog-1.14.3'></a>

## 1.14.3 — 2023-02-03

### Fixed

- `ggshield secret scan pre-receive` no longer scans deleted commits when a branch is force-pushed (#437).

- If many GGShield users are behind the same IP address, the daily update check could cause GitHub to rate-limit the IP. If this happens, GGShield honors GitHub rate-limit headers and no longer checks for a new update until the rate-limit is lifted (#449).

- GGShield once again prints a "No secrets have been found" message when a scan does not find any secret (#448).

- Installing GGShield no longer creates a "tests" directory in "site-packages" (#383).

- GGShield now shows a clear error message when it cannot use git in a repository because of dubious ownership issues.

### Deprecated

- The deprecation message when using `ggshield scan` instead of `ggshield secret scan` now states the `ggshield scan` commands are going to be removed in GGShield 1.15.0.

<a id='changelog-1.14.2'></a>

## 1.14.2 — 2022-12-15

### Changed

- It is now possible to use generic command-line options like `--verbose` anywhere on the command line and scan options anywhere after the `scan` word (#197).

- `ggshield iac scan` now shows the severity of the detected vulnerabilities.

### Fixed

- If a file containing secrets has been committed in two different branches, then `ggshield secret scan repo` would show 4 secrets instead of 2. This has been fixed (#428).

- ggshield now uses different error codes when a scan succeeds but finds problems and when a scan does not finish (#404).

- ggshield now correctly handles the case where git is not installed (#329).

<a id='changelog-1.14.1'></a>

## 1.14.1 — 2022-11-16

### Fixed

- Fixed dependency on pygitguardian, which blocked the release on pypi.

<a id='changelog-1.14.0'></a>

## 1.14.0 — 2022-11-15

### Added

- ggshield scan commands now accept the `--ignore-known-secrets` option. This option is useful when working on an existing code-base while secrets are being remediated.

- ggshield learned a new secret scan command: `docset`. This command can scan any content as long as it has been converted into our new docset file format.

### Changed

- `ggshield auth login --method=token` can now read its token from the standard input.

### Fixed

- ggshield now prints clearer error messages if the .gitguardian.yaml file is invalid (#377).

- When used with the [pre-commit](https://pre-commit.com) framework, ggshield would sometimes scan commits with many files more than once. This has been fixed.

<a id='changelog-1.13.6'></a>

## 1.13.6 — 2022-10-19

### Fixed

- `ggshield auth login` no longer fails when called with `--lifetime`.

- pre-receive and pre-push hooks now correctly handle the case where a branch with no new commits is pushed.

- ggshield no longer fails when scanning paths longer than 256 characters (#391).

<a id='changelog-1.13.5'></a>

## 1.13.5 — 2022-10-12

### Fixed

- Fix crash at startup if the home directory is not writable.

<a id='changelog-1.13.4'></a>

## 1.13.4 — 2022-10-12

### Added

- ggshield now checks for update once a day and notifies the user if a new version is available. This check can be disabled with the `--no-check-for-updates` command-line option (#299).

### Changed

- Scanning Git repositories is now faster.

- `ggshield secret scan path` now shows a progress bar.

- When used as a pre-push or pre-receive hook, ggshield no longer scans more commits than necessary when a new branch is pushed (#303, #369).

### Fixed

- ggshield no longer declares two separate instances if the instance URL is set with and without a trailing slash (#357).

- Fixed a regression where ggshield would not load the .env from the current working directory.

- ggshield no longer silently ignores network issues.
