### Security

- Harden internal `git` invocations against argument injection: positional refs, remotes, branches and clone URLs are now passed after `--end-of-options` (git 2.24+) so a value starting with `-` (e.g. read from a CI environment variable) cannot be reinterpreted as a `git` option such as `--upload-pack=`.
