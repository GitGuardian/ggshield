from ggshield.core.text_utils import display_info
from ggshield.hmsl.collection import PreparedSecrets


def write_outputs(result: PreparedSecrets, prefix: str) -> None:
    """
    Write payload and mapping files.
    """
    with open(f"{prefix}payload.txt", "w") as payload_file:
        payload_file.write("\n".join(result.payload) + "\n")

    with open(f"{prefix}mapping.txt", "w") as mapping_file:
        for hash, hint in result.mapping.items():
            line = hash + ":" + hint if hint else hash
            mapping_file.write(line + "\n")
    display_info(
        f"{prefix}payload.txt and {prefix}mapping.txt files have been written."
    )
