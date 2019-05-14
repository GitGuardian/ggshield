#!/bin/bash

if [ "$(git config --global --get core.hooksPath)" = "" ]; then
    git config --global core.hooksPath ~/.git/hooks
fi

hooks=$(git config --global --get core.hooksPath)
mkdir -p $hooks

if [ -f $hooks/pre-commit ] && [[ "$1" != "--force" ]]; then
    echo "pre-commit already exists in" $hooks/pre-commit
    echo "If you want to override this file, you can add --force."
else
    echo "#!/bin/bash\nsecrets-shield" > $hooks/pre-commit
    chmod a+x $hooks/pre-commit
    echo "pre-commit successfully added in" $hooks/pre-commit
fi
