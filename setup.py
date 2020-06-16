import re
from os.path import abspath, dirname, join

from setuptools import find_packages, setup


VERSION_RE = re.compile(r"__version__\s*=\s*\"(.*?)\"")


def readme():
    with open(abspath("README.md")) as f:
        return f.read()


current_path = abspath(dirname(__file__))


with open(join(current_path, "ggshield", "__init__.py")) as file:
    content = file.read()
    result = re.search(VERSION_RE, content)
    if result is None:
        raise Exception("could not find package version")
    __version__ = result.group(1)

setup(
    author="GitGuardian",
    author_email="support@gitguardian.com",
    description="Detect policy breaks using GitGuardian's brains",
    entry_points={"console_scripts": ["ggshield=ggshield.cmd:cli"]},
    include_package_data=True,
    install_requires=["requests", "click", "pyyaml"],
    name="ggshield",
    packages=find_packages(exclude=["tests"]),
    url="https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit.git",
    version=__version__,
    zip_safe=True,
)
