### Fixed

- `ggshield plugin install --allow-unsigned` and `ggshield plugin update --allow-unsigned` now verify plugin signatures using the embedded / cached sigstore trust root instead of refreshing it over the network, so plugins can still be installed when the sigstore TUF endpoints are unreachable.
