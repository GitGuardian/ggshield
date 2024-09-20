# Scripts

This directory contains scripts to help with GGShield development and special usage.

## build-packages/build-packages

Build .pyz, .deb and .rpm packages.

## push-to-cloudsmith

Publish the .deb and .rpm built by build-packages to Cloudsmith.

## release

Provide commands to run the steps required for a release.

To list the commands use `scripts/release --help`.

The script aborts if the `VERSION` environment variable is not set. It must be set to the version we want to release.

The script aborts if the working-tree is not clean (can be bypassed with `--allow-dirty`) or is not on the `main` branch (can be bypassed by defining the `RELEASE_BRANCH` environment variable).

## create-ghe-environment

Creates a GitHub Enterprise Server (GHES) [pre-receive hook environment][ghe] containing GGShield.

To run this script you must have Docker installed. The script must be run on the same machine architecture as the GHES server on which the environment will be uploaded.

[ghe]: https://docs.github.com/en/enterprise-server@3.11/admin/policies/enforcing-policy-with-pre-receive-hooks/creating-a-pre-receive-hook-environment
