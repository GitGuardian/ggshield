progress() {
    echo -e "\033[34m$*\033[0m"
}

update_ggshield() {
    local old_pwd="$PWD"

    cd "$HOME"
    local venv_dir=$HOME/venv

    progress "Cloning ggshield $GITGUARDIAN_GGSHIELD_REF"
    git clone --depth 1 https://github.com/gitguardian/ggshield
    cd ggshield
    git fetch origin "$GITGUARDIAN_GGSHIELD_REF"
    git checkout FETCH_HEAD

    progress "Creating venv in $venv_dir"
    python -m venv "$venv_dir"
    . "$venv_dir/bin/activate"

    progress "Installing in venv"
    pip install .

    cd "$old_pwd"

    progress "ggshield=$(which ggshield)"
}

if [ -n "${GITGUARDIAN_GGSHIELD_REF:-}" ] ; then
    update_ggshield
else
    progress "Using ggshield from image"
fi
