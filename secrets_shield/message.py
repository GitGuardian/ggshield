from colorama import Fore, Style


def leak_message(scan_result):
    """
    Display readable information on the found secrets
    """
    for secret in scan_result["scan"]["secrets"]:
        for match in scan_result["scan"]["secrets"][0]["matches"]:
            print(
                "A secret of type {} has been found in file {}".format(
                    Fore.BLUE
                    + Style.BRIGHT
                    + secret["detector"]["display_name"]
                    + Style.RESET_ALL,
                    Fore.YELLOW + Style.BRIGHT + scan_result["filename"],
                )
            )

            before, after = scan_result["content"].split(match["string_matched"])

            before = "\n".join(before.split("\n")[-3:])
            after = "\n".join(after.split("\n")[:3])

            print(
                "{}{}{}".format(
                    Style.DIM + before,
                    Style.NORMAL + Fore.RED + match["string_matched"],
                    Style.DIM + Fore.RESET + after,
                )
            )


def error_message(response):
    """
    Display a message in case of error
    """
    error = ""
    if "msg" in response:
        error = response["msg"]
    elif "message" in response:
        error = response["message"]

    print("{} : {}".format(Fore.RED + "Error" + Fore.RESET, error))


def no_leak_message():
    """
    Display a message if no secret is found
    """
    print(Style.DIM + "No secret has been found")
