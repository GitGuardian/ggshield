# Releasing GGShield

## Overview

A release is triggered by pushing a `v*` tag. That tag makes
[`tag.yml`](../../.github/workflows/tag.yml) build every artifact and then publish
to PyPI, Docker Hub, Chocolatey and Cloudsmith, and open version-bump pull
requests on the downstream repositories.

Pushing a tag is a single-person action: GitHub has no mechanism to require a
review for creating a tag. The publishing jobs are therefore gated behind a
protected [environment](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
named `release`, so that **no single person can publish a release**. Building the
artifacts is not gated; only the steps that make them visible to users are.

## Steps

Run the commands in this order, from a release branch (`main` or `X.Y.x`):

1. `scripts/release run-tests`
2. `scripts/release prepare VERSION` — bumps the version, updates the changelog
   and commits
3. `scripts/release tag` — creates and pushes the tag, which starts the release
   workflow
4. **A second person approves the deployment** (see below)
5. `scripts/release publish-gh-release` — removes the "draft" status of the
   GitHub release

Use `scripts/release --help` to list the commands.

## Approving the deployment

After step 3, the build jobs run to completion and the publishing jobs stop with
a "Waiting" status. A reviewer for the `release` environment gets a notification
and can approve or reject the deployment from the workflow run page. See
[Reviewing deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments).

The person who pushed the tag cannot approve their own release: the environment
has "Prevent self-review" enabled. Someone else on the reviewer list must do it.

Before approving, check that:

- the `chore(release): VERSION` commit bumps the version and the changelog as
  expected
- the version number matches the changes being released
- the build and test jobs of the run have succeeded

Rejecting the deployment stops the publication. The tag still exists, so
publishing a corrected version means releasing a new version number rather than
reusing the tag.

## What is _not_ gated

- `scripts/release publish-gh-release` runs from a workstation with your own
  credentials, so removing the draft status of the GitHub release is not covered
  by the environment gate.
- The `chore(release): VERSION` commit is pushed directly to the release branch
  and is not reviewed through a pull request. The deployment approval is the
  point where a second person reviews it.

## GitHub configuration

The gate depends on the `release` environment being configured with:

- **Required reviewers** — the people or teams allowed to approve a release.
  Only one of them needs to approve.
- **Prevent self-review** enabled — without it, whoever pushed the tag can
  approve their own release, and the gate enforces nothing.
- **Allow administrators to bypass configured protection rules** disabled —
  administrators can otherwise force the deployment through.

See [Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).
