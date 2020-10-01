from typing import Tuple

import click

from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result, ScanCollection

from .message import leak_message, no_leak_message


class TextHandler(OutputHandler):
    def process_scan(self, scan: ScanCollection, top: bool = True) -> Tuple[str, int]:
        return_code = 0
        if scan.optional_header and (scan.results or self.verbose):
            click.echo(scan.optional_header)

        if scan.results:
            return_code = 1
            for result in scan.results:
                self.process_result(result)
        else:
            if self.verbose:
                no_leak_message()

        if scan.scans:
            for sub_scan in scan.scans:
                inner_scan_str, inner_return_code = self.process_scan(
                    sub_scan, top=False
                )
                return_code = max(return_code, inner_return_code)

        return "", return_code

    def process_result(self, result: Result) -> str:
        leak_message(result, self.show_secrets)
        return ""
