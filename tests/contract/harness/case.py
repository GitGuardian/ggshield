"""One contract test: a folder with a test.yaml, turned into a pytest item."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

from . import api_calls, expected, runner, scrub, spec
from .environment import check_rust_bin, ggshield_command
from .mock_server import MockServer, RecordMockServer, ReplayMockServer


class ContractFailure(Exception):
    def __init__(self, sections: List[str]):
        super().__init__("\n\n".join(sections))
        self.sections = sections


class ContractFile(pytest.File):
    """A test.yaml file: one contract test, named after its folder."""

    def collect(self):
        yield ContractCase.from_parent(self, name=self.path.parent.name)


class ContractCase(pytest.Item):
    # Set once the test's temporary folder exists, shown on failure
    sandbox_root: Optional[Path] = None

    @property
    def folder(self) -> Path:
        return self.path.parent

    @property
    def api_calls_path(self) -> Path:
        return self.folder / "api_calls.yaml"

    def runtest(self) -> None:
        test_spec, ggshield = self._prepare()
        if self.config.getoption("--record-api"):
            self._record_api_calls(test_spec, ggshield)
        outputs = self._replay(test_spec, ggshield)
        if self.config.getoption("--record"):
            expected.record(self.folder / "expected", outputs)
        elif failures := expected.compare(self.folder / "expected", outputs):
            raise ContractFailure(failures)

    def repr_failure(self, excinfo, style=None):
        if isinstance(excinfo.value, ContractFailure):
            header = f"Contract test failed: {self.folder}\n"
            if self.sandbox_root is not None:
                header += f"Sandbox kept at: {self.sandbox_root}\n"
            return header + "\n" + "\n\n".join(excinfo.value.sections)
        return super().repr_failure(excinfo, style=style)

    def reportinfo(self):
        return self.path, None, f"contract: {self.folder.name}"

    def _prepare(self) -> Tuple[spec.Spec, List[str]]:
        """The test's spec and the ggshield command to run, or skip / fail."""
        impl: Optional[str] = self.config.getoption("--impl")
        if impl is None:
            pytest.skip("contract tests need --impl=python or --impl=rust")
        rust_bin: str = self.config.getoption("--rust-bin")
        if impl == "rust" and (error := check_rust_bin(rust_bin)):
            pytest.fail(error, pytrace=False)
        try:
            test_spec = spec.load(self.path)
        except spec.SpecError as error:
            pytest.fail(str(error), pytrace=False)
        return test_spec, ggshield_command(impl, rust_bin)

    def _record_api_calls(self, test_spec: spec.Spec, ggshield: List[str]) -> None:
        """--record-api, pass 1: real API, real values, so chained calls work.
        The calls are scrubbed when saved; the output of this run is not kept."""
        recorder = self._recording_server()
        self._run(test_spec, ggshield, recorder)
        if not recorder.recorded:
            # No API call: no api_calls.yaml
            self.api_calls_path.unlink(missing_ok=True)
            return
        # Requests were already normalized by the mock (placeholders). Scrubbing
        # replaces real values in responses, then in requests that sent them back.
        api_calls.save(self.api_calls_path, scrub.scrub(recorder.recorded))

    def _recording_server(self) -> RecordMockServer:
        api_key = os.environ.get("GITGUARDIAN_API_KEY")
        if not api_key:
            pytest.fail(
                "--record-api needs your API key in GITGUARDIAN_API_KEY",
                pytrace=False,
            )
        return RecordMockServer(
            os.environ.get("GITGUARDIAN_API_URL", "https://api.gitguardian.com"),
            api_key,
        )

    def _replay(self, test_spec: spec.Spec, ggshield: List[str]) -> expected.Outputs:
        """Run against api_calls.yaml. After --record-api this is pass 2, against
        the scrubbed calls: expected/ then matches api_calls.yaml by
        construction and never sees a real value."""
        # Started even without api_calls.yaml: every API URL points at it, so an
        # unexpected call is reported by name instead of hitting a closed port
        # (retried with backoff, then a ggshield connection error). It also
        # gives {{mock_url}} a value for commands that print the instance URL.
        mock = ReplayMockServer(api_calls.load(self.api_calls_path))
        outputs = self._run(test_spec, ggshield, mock)
        api_errors = mock.errors + mock.unused()
        if api_errors:
            # Never record output produced against the wrong API answers
            raise ContractFailure(
                ["API calls do not match api_calls.yaml:"]
                + api_errors
                + [f"Command output:\n{outputs.stdout}{outputs.stderr}"]
            )
        return outputs

    def _run(
        self, test_spec: spec.Spec, ggshield: List[str], server: MockServer
    ) -> expected.Outputs:
        """Run the command once, in a fresh sandbox, against `server`."""
        # Kept after the run (pytest rotates old runs), so a failure can be
        # inspected: see repr_failure.
        self.sandbox_root = self._make_sandbox_root()
        try:
            return runner.run(
                test_spec, self.folder, ggshield, server, self.sandbox_root
            )
        except runner.SetupError as error:
            raise ContractFailure([str(error)])  # shows the sandbox path

    def _make_sandbox_root(self) -> Path:
        # pytest's own temporary folders (what the tmp_path fixture uses): kept
        # after the run, old runs removed by pytest. Custom items get no fixtures,
        # hence the config attribute.
        factory = self.config._tmp_path_factory  # type: ignore[attr-defined]
        return factory.mktemp(f"{self.folder.parent.name}-{self.folder.name}")
