# Scripts

This directory contains scripts to help with ggshield development.

## build-packages/build-packages

Build .pyz, .deb and .rpm packages.

## push-to-cloudsmith

Publish the .deb and .rpm built by build-packages to Cloudsmith.

## release

Provide commands to run the steps required for a release.

To list the commands use `scripts/release --help`.

The script aborts if the `VERSION` environment variable is not set. It must be set to the version we want to release.

The script aborts if the working-tree is not clean (can be bypassed with `--allow-dirty`) or is not on the `main` branch (can be bypassed by defining the `RELEASE_BRANCH` environment variable).

## update-pipfile-lock/update-pipfile-lock

Update Pipfile.lock, using the oldest supported version of Python.
