#!/usr/bin/python3

from commit import Commit
import asyncio


def print_message_leak(secrets, filename: str = None):
    """
    Prompt an alert if a leak is found
    """
    for secret in secrets:
        for match in secret["matches"]:
            print(
                "A secret from provider {} has been found in file {} ({})".format(
                    secret["detector"]["display_name"],
                    filename,
                    match["string_matched"],
                )
            )


def check_scan(commit):
    """
    Checks a commit scan result
    """
    for scan_result in commit.result:
        if not scan_result["error"] and scan_result["has_leak"]:
            print_message_leak(scan_result["scan"]["secrets"], scan_result["filename"])


def main():
    c = Commit()
    asyncio.run(c.scan())
    check_scan(c)


if __name__ == "__main__":
    main()
