---
name: ggshield
description: >-
  Use when working with ggshield or GitGuardian secret detection.
  Triggers: "ggshield", "scan for secrets", "secret detection", "GitGuardian"
version: 1.0.0
tools: Read, Bash, Glob, Grep
---

# ggshield — GitGuardian Secret Detection CLI

ggshield is the CLI for GitGuardian's secret detection engine. It scans code, files, and git history for leaked credentials and secrets.

## Authentication

Before scanning, authenticate with GitGuardian:

```bash
ggshield auth login
```

This opens a browser for OAuth login. Use `--method token` for headless environments:

```bash
ggshield auth login --method token
```

Check authentication status:

```bash
ggshield api-status
```

## Secret Scanning

### Scan a directory or file

```bash
ggshield secret scan path <path>
```

### Scan git diff (staged changes)

```bash
ggshield secret scan pre-commit
```

### Scan a git range

```bash
ggshield secret scan commit-range HEAD~5..HEAD
```

### Scan a specific commit

```bash
ggshield secret scan commit <sha>
```

### Scan a Docker image

```bash
ggshield secret scan docker <image>
```

## Understanding Output

When secrets are found, ggshield reports:

- **Detector name**: the type of secret (e.g., `github_token`, `aws_access_key`)
- **Severity**: `critical`, `high`, `medium`, `low`, `info`
- **File and line**: location of the secret
- **Match**: the matched value (partially redacted)

Exit codes:

- `0`: no secrets found (or `--exit-zero` is set)
- `1`: secrets found
- `128`: unexpected error

## Remediation

### Ignore a detected secret

To mark a secret as a known false positive:

```bash
ggshield secret ignore --last-found
```

Or add `# ggignore` on the same line as the secret in the source file.

### Rotate credentials

When a real secret is found:

1. Revoke the credential in the relevant service immediately
2. Generate a new credential
3. Update references in the codebase
4. Consider using a secrets manager (Vault, AWS Secrets Manager, etc.)

## Git Hooks

### Install as a pre-commit hook (local)

```bash
ggshield install --mode local
```

### Install as a pre-push hook

```bash
ggshield install --mode local --hook-type pre-push
```

### Install globally (all repos)

```bash
ggshield install --mode global
```

## Common Flags

| Flag                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| `--exit-zero`                | Always return exit code 0 (useful in CI to not block on findings) |
| `--output <file>`            | Write output to a file                                            |
| `--json`                     | Output results as JSON                                            |
| `--minimum-severity <level>` | Only report secrets at or above this severity                     |
| `--ignore-known-secrets`     | Skip secrets already present in the GitGuardian dashboard         |

## Configuration

ggshield reads from `.gitguardian.yaml` in the repo root or `~/.gitguardian.yaml` globally.

Example `.gitguardian.yaml`:

```yaml
exit-zero: false
minimum-severity: medium
ignore-paths:
  - tests/fixtures/
```

## Common Workflows

### Check staged changes before commit

```bash
git add <files>
ggshield secret scan pre-commit
```

### Scan entire repository history

```bash
ggshield secret scan repo .
```

### CI integration (non-blocking)

```bash
ggshield secret scan ci --exit-zero
```

### View scan results as JSON

```bash
ggshield secret scan path . --json
```
