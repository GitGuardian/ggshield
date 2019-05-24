import subprocess
from typing import List


def shell(command: str) -> List:
    """ Execute a command in a subprocess. """
    return (
        subprocess.check_output(command.split(" ")).decode("utf-8").rstrip().split("\n")
    )
