#!/usr/bin/python3

from secrets_shield.commit import Commit
from secrets_shield.message import process_scan_result
import sys
import asyncio


def main():
    loop = asyncio.get_event_loop()
    sys.exit(process_scan_result(loop.run_until_complete(Commit().scan())))


if __name__ == "__main__":
    main()
