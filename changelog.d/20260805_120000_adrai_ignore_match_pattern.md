### Added

- `ggshield secret scan` learned the `--ignore-match-pattern PATTERN` option. Secrets
  whose value matches the given regex are ignored, which is handy to skip values
  encrypted at rest, such as sops values starting with `ENC[AES256_GCM,data:`. The
  option can be repeated, and is also available as the `ignored_match_patterns` setting
  of the `secret` section in `.gitguardian.yaml`.
