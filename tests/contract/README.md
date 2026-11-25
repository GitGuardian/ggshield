# Contract tests

Black-box tests that run ggshield as a user would, against the Python or the
Rust implementation, and compare what comes out with recorded expectations.

## Layout

One folder per test:

```
tests/contract/api_status/json_output/
  test.yaml          # how to run the command (command, env, stdin)
  work/              # input files, copied to {{work}} before the command runs
  home/              # optional starting state, copied to {{home}} (.gitguardian.yaml...)
  config/            # optional, copied to {{config}} (auth_config.yaml: logged-in instances)
  data/              # optional, copied to {{data}} (installed plugins...)
  api_calls.yaml     # API calls replayed by the local mock (absent = none expected)
  expected/
    expected.yaml    # exit code, and how each output is compared
    stdout.json      # recorded stdout (stdout.txt when it is not JSON)
    stderr.txt       # recorded stderr (absent = must be empty)
    files/           # files the command created or changed, per sandbox folder:
      home/.gitguardian.yaml        #   files/<work|home|config|data>/<path>
      config/auth_config.yaml
```

Files the command writes are found by comparing the sandbox before and after
the run (the cache folder is left out). A `.git` folder is stored as `_git` under
`expected/files/`, since git refuses to track a path containing `.git`. Files it deletes are listed in
`expected.yaml` under `deleted_files`. Binary files are compared byte for byte.
For text files, `expected.yaml` lists a compare mode per file under `files:`,
set by `--record`: `data` for `.yaml`, `.yml` and `.json` (parsed and compared
as data, so formatting, key order and comments don't matter), `full` for the
others (exact text, after placeholders). Change a mode by hand when needed (e.g.
`full` to check a rewritten config keeps its comments); re-recording keeps it. The permissions of each written
file are recorded under `file_modes` (`auth_config.yaml` must stay `'0600'`,
it holds tokens); the command runs with umask 022 so modes are the same on
every machine. Modes are not checked on Windows.

`test.yaml`:

```yaml
command: [api-status, --json]
setup: # optional; commands run in {{work}} before it (git only for now)
  - [git, init]
env: # optional; a null value unsets the variable
  GITGUARDIAN_INSTANCE: null
stdin: '...' # optional
```

Placeholders, replaced as plain text in the command, env, stdin and text files
of `work/`, and turned back into placeholders in the outputs: `{{work}}`,
`{{home}}`, `{{config}}`, `{{cache}}`, `{{data}}` (ggshield's folders),
`{{tmp}}` (the test's temporary root, also `TMPDIR`) and `{{mock_url}}`. The
most specific placeholder wins: a file in the cache shows as `{{cache}}/...`,
not `{{tmp}}/cache/...`.

## Running

```
uv run pytest tests/contract --impl=python                          # validate against Python
uv run pytest tests/contract --impl=rust                            # validate against the Rust binary
uv run pytest tests/contract/api_status/json_output --impl=rust     # one test
uv run pytest tests/contract/api_status --impl=python --record      # record expected output
uv run pytest tests/contract --impl=rust --lf --record              # re-record what just failed
uv run pytest tests/contract/quota/json_output --impl=python --record-api   # record the API calls too
```

Without `--impl`, contract tests are skipped.

Record on Linux or macOS only: `--record` and `--record-api` refuse to run on
Windows, which prints other paths and has no POSIX file modes. Validation runs
on all three.

- `--record` saves the output as the expected output. It replays `api_calls.yaml` and
  never calls the real API.
- `--record-api` runs the command twice. First against the real API
  (`GITGUARDIAN_API_URL`, default `https://api.gitguardian.com`) with your key
  from `GITGUARDIAN_API_KEY`, with real values, so chained calls work; the
  recorded calls are then scrubbed with `scrub.yaml` (a replaced value is also replaced
  in later requests that sent it back) and saved. Then a replay against the
  scrubbed calls, whose output is saved as the expected output: it matches
  `api_calls.yaml`, and never contains a real value.

`--impl=rust` runs `rust/target/release/ggshield` (or `--rust-bin`).

## Fixtures

Use fabricated secrets only (or GitGuardian's test tokens). `work/`,
`api_calls.yaml` and `expected/` are ignored by the repo's own secret scan
(`.gitguardian.yaml`), so a real secret committed there would not be caught.
They are also kept byte for byte: pre-commit formatters skip them and
`.gitattributes` turns off line-ending conversion.

## Comparing

Outputs are compared exactly after cleanup (colours, line endings, placeholders).
JSON output is compared as data. For help, usage and error messages, which
differ between Python and Rust, write `expected/expected.yaml` by hand:

```yaml
exit_code: 0
stdout:
  contains: [--json, --instance]
stderr: full
```

`--record` updates the exit code and `full` outputs, and keeps `contains` lists.

API requests must match `api_calls.yaml` (method, path, query, JSON body), in
any order; an unexpected or missing call fails the test. The headers a call
lists are checked too: a value is compared exactly (`Token {{api_key}}`
for the fake key), `'*'` only requires the header to be present, and headers
not listed are ignored. `--record-api` decides which headers to save from the
`request_headers` lists in `scrub.yaml`, and saves calls in a stable order.
