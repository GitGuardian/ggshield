# Scripts

This directory contains scripts to help with ggshield development.

## build-packages/build-packages

Build .pyz, .deb and .rpm packages.

## action-entrypoint-generator/action-entrypoint-generator

We have two GitHub actions: one to run `secret scan` and another to run `iac scan`. They are defined in `actions/secret` and `actions/iac`. These two actions use the `gitguardian/ggshield:latest` Docker image defined at the root of the repository, which provides a way to run GGShield inside a Docker container.

To test that changes made inside pull requests do not cause problems with our GitHub actions, we have a separate set of actions: `actions-unstable/secret` and `actions-unstable/iac`. The difference between these actions and those defined in `actions` are the following:

- They use the `gitguardian/ggshield:unstable` image instead of `gitguardian/ggshield:latest` as the base image, so that we test more recent code.

- If the `$GITGUARDIAN_GGSHIELD_REF` environment variable is set, then they install GGShield from this ref, so that we test the code from the pull request and not the code currently in the `main` branch.

Since the Dockerfile syntax does not make it easy to reuse code outside of the directory they are defined in, the `action-entrypoint-generator/action-entrypoint-generator` script generates the four possible `entrypoint.sh` files.

## push-to-cloudsmith

Publish the .deb and .rpm built by build-packages to Cloudsmith.

## release

Provide commands to run the steps required for a release.

To list the commands use `scripts/release --help`.

The script aborts if the `VERSION` environment variable is not set. It must be set to the version we want to release.

The script aborts if the working-tree is not clean (can be bypassed with `--allow-dirty`) or is not on the `main` branch (can be bypassed by defining the `RELEASE_BRANCH` environment variable).

## update-pipfile-lock/update-pipfile-lock

Update Pipfile.lock, using the oldest supported version of Python.
