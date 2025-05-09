# Dependencies

## Updating dependencies

To update a dependency:

- Update the dependency version in `pyproject.toml`.
- Make any necessary changes.
- Run `pdm update <dependency>` to update the lock file.
- File a PR.

## Using an unreleased version of py-gitguardian

If you made changes to py-gitguardian and want to use them in GGShield there are a few steps you need to perform.

### Locally

To use your changes locally:

- Activate `ggshield` virtual environment.
- Run `pip install -e path/to/your/py-gitguardian/checkout`.

You only need to do this once. From now on, changes you make in py-gitguardian are immediately available in ggshield.

### In the CI

For the changes to pass on CI, you need to:

1. Update py-gitguardian dependency in `pyproject.toml` to use a git+https URL, like this:

   ```
   dependencies = [
       (...)
       # TODO: replace this with a real version number as soon as a new version of
       # py-gitguardian is out
       "pygitguardian @ git+https://github.com/GitGuardian/py-gitguardian.git@cfa919cff68cc4d3ca40bf2bb8a6f24bc5fca786"
       (...)
   ]
   ```

2. Run `pdm update pygitguardian`.

Remember to do what the `TODO` comment says!
