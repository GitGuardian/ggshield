#!/bin/sh
# rpm doesn't own the bundle dirs, so upgrades leave empty *.dist-info behind;
# an empty one crashes the frozen binary at import. Prune them post-transaction.
find /usr/libexec/ggshield/_internal -type d -empty -delete 2>/dev/null || true
