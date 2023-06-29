from pathlib import Path

from pygitguardian.models import Detail

from ggshield.core.errors import UnexpectedError
from ggshield.core.git_shell import (
    INDEX_REF,
    get_filepaths_from_ref,
    get_staged_filepaths,
    tar_from_ref_and_filepaths,
)
from ggshield.sca.client import SCAClient


def tar_sca_files_from_git_repo(directory: Path, ref: str, client: SCAClient) -> bytes:
    """Builds a tar containing SCA files from the git repository at
    the given directory, for the given ref. Empty string denotes selection
    from staging area."""
    # TODO: add exclusion patterns
    if ref == INDEX_REF:
        all_files = get_staged_filepaths(wd=str(directory))
    else:
        all_files = get_filepaths_from_ref(ref, wd=str(directory))

    sca_files_result = client.compute_sca_files(
        touched_files=[str(path) for path in all_files]
    )
    if isinstance(sca_files_result, Detail):
        raise UnexpectedError("Failed to select SCA files")

    return tar_from_ref_and_filepaths(
        ref=ref, filepaths=map(Path, sca_files_result.sca_files), wd=str(directory)
    )
