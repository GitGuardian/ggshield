from colorama import init, Fore, Style
from typing import Dict, List


def leak_message(scan_result: Dict, nb_lines: int = 3) -> str:
    """
    Build readable message on the found secrets
    :param scan_result: The result from scanning API
    :param nb_lines: The number of line to display before and after a secret in the patch
    :return: The formatted message to display
    """
    message = "\n{} secrets have been found\n".format(
        len(scan_result["scan"]["secrets"])
    )
    content = scan_result["content"]

    for secret in scan_result["scan"]["secrets"]:
        message += "\n💥 💔 💥 A secret of type {} has been found in file {}\n".format(
            Fore.BLUE
            + Style.BRIGHT
            + secret["detector"]["display_name"]
            + Style.RESET_ALL,
            Fore.YELLOW + Style.BRIGHT + scan_result["filename"] + Style.RESET_ALL,
        )

        index = 0

        for i, match in enumerate(secret["matches"]):
            start = match["indice_start"]
            end = match["indice_end"]

            if i == 0:
                message += format_patch(backward_context(content, start, nb_lines))
            else:
                message += format_patch(content[index:start])

            message += format_secret(content[start:end])
            index = end

        message += format_patch(forward_context(content, index, nb_lines))

    return message


def format_patch(patch: str) -> str:
    return Style.DIM + patch + Style.RESET_ALL


def format_secret(secret: str) -> str:
    return Fore.RED + secret + Style.RESET_ALL


def backward_context(content: str, index: int, nb_lines: int) -> str:
    return "\n".join(content[:index].split("\n")[-nb_lines:])


def forward_context(content: str, index: int, nb_lines: int) -> str:
    return "\n".join(content[index:].split("\n")[:nb_lines])


def error_message(response: Dict) -> str:
    """
    Build a message in case of error
    :return: The formatted message to display
    """
    error = ""
    if "msg" in response:
        error = response["msg"]
    elif "message" in response:
        error = response["message"]

    return "{} : {}".format(Fore.RED + "Error" + Fore.RESET, error)


def no_leak_message() -> str:
    """
    Build a message if no secret is found
    :return: The formatted message to display
    """
    return Style.DIM + "No secret has been found"


def process_scan_result(results: List, nb_lines: int = 3) -> int:
    """
    Process a commit scan result
    """
    init(autoreset=True)
    leak = False
    error = False

    for scan_result in results:
        if scan_result["error"]:
            print(error_message(scan_result["scan"]))
            error = True
        elif scan_result["has_leak"]:
            print(leak_message(scan_result, nb_lines))
            leak = True

    if leak or error:
        return 1

    print(no_leak_message())
    return 0
