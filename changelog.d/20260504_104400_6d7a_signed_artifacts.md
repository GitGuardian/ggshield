### Added

- Release binaries published to GitHub Releases now ship with [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds), providing signed SLSA build provenance. Users can verify a downloaded asset with `gh attestation verify <file> --repo GitGuardian/ggshield`, and tool managers such as mise (via the aqua backend) will verify automatically at install time.
