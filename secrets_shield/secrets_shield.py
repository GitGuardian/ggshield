#!/usr/bin/python3

from secrets_shield.commit import Commit
from secrets_shield.message import leak_message, error_message, no_leak_message
from colorama import init
import sys
import asyncio


def check_scan(results):
    """
    Checks a commit scan result
    """
    leak = False
    error = False

    for scan_result in results:
        if scan_result["error"]:
            error_message(scan_result["scan"])
            error = True
        elif scan_result["has_leak"]:
            leak_message(scan_result)
            leak = True

    if leak or error:
        sys.exit(1)

    no_leak_message()


def main():
    init(autoreset=True)
    check_scan(asyncio.get_event_loop().run_until_complete(Commit().scan()))


if __name__ == "__main__":
    main()
