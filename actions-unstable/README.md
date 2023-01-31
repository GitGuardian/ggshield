This directory contains GitHub actions used internally by our CI to simulate the "real" GitHub actions (the ones defined in the `actions` directory) using the latest versions of GGShield.

They differ from the real GitHub actions by:

- Using the `gitguardian/ggshield:unstable` Docker image instead of `gitguardian/ggshield:latest`.
- Having the possibility to override the installed GGShield version.

These actions are not meant to be used outside of GGShield CI.
