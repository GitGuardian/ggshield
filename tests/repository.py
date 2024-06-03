import subprocess
import sys
from pathlib import Path
from typing import Optional, Union

from ggshield.utils.git_shell import git


class Repository:
    """
    Helper class to create Git repositories, for test purposes
    """

    def __init__(self, path: Path, remote_url: Optional[str] = None):
        self.path = path
        self.remote_url = remote_url
        self._credentials_set = False

    def git(self, *args: Union[str, Path]) -> str:
        try:
            return git(["-C", str(self.path)] + [str(x) for x in args])
        except subprocess.CalledProcessError as exc:
            out = exc.stdout.decode("utf-8", errors="ignore")
            err = exc.stderr.decode("utf-8", errors="ignore")
            print(f"Command failed with return code {exc.returncode}", file=sys.stderr)
            print(f"\n# stdout\n\n{out}", file=sys.stderr)
            print(f"\n# stderr\n\n{err}", file=sys.stderr)
            raise exc

    @classmethod
    def create(cls, path: Path, bare=False, initial_branch="main") -> "Repository":
        cmd = ["init", str(path), "--initial-branch", initial_branch]
        if bare:
            cmd.append("--bare")
        git(cmd)
        return cls(path)

    @classmethod
    def clone(cls, url: Union[str, Path], path: Path) -> "Repository":
        git(["clone", str(url), str(path)])
        return cls(path, remote_url=str(url))

    def add(self, *args: Union[str, Path]):
        self.git("add", *args)

    def push(self, *args: str) -> None:
        self.git("push", *args)

    def create_commit(self, message: str = "Test commit") -> str:
        self._ensure_credentials_are_set()
        self.git("commit", "--allow-empty", "-m", message)
        return self.get_top_sha()

    def checkout(self, name: str) -> None:
        self.git("checkout", name)

    def create_branch(self, name: str, orphan: bool = False) -> None:
        self.git("checkout", "--orphan" if orphan else "-b", name)

    def get_top_sha(self) -> str:
        out = self.git("rev-parse", "HEAD")
        return out.strip()

    def _ensure_credentials_are_set(self):
        if self._credentials_set:
            return
        self.git("config", "user.name", "ggshield-test")
        self.git("config", "user.email", "ggshield-test@example.com")
        self._credentials_set = True

    def remove_unreachable_commits(self):
        # Remove all unreachable commits and their references.
        # It is used to simulate the CI env which cannot access detached history.
        self.git("reflog", "expire", "--expire-unreachable=now", "--all")
        self.git("gc", "--prune=now")


def create_pre_receive_repo(tmp_path) -> Repository:
    repo = Repository.create(tmp_path)
    repo.create_commit("initial commit")

    # Detach from the current branch to simulate what happens when pre-receive
    # is called: the new commits are not in any branch yet.
    repo.git("checkout", "--detach")
    return repo
