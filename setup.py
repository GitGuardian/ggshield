import io
import os
import re
from typing import Any

from setuptools import find_packages, setup


VERSION_RE = re.compile(r"__version__\s*=\s*\"(.*?)\"")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args: Any) -> str:
    """Reads complete file contents."""
    return str(io.open(os.path.join(HERE, *args), encoding="utf-8").read())


def get_version() -> str:
    """Reads the version from this module."""
    init = read("ggshield", "__init__.py")
    return VERSION_RE.search(init).group(1)  # type: ignore


setup(
    name="ggshield",
    version=get_version(),
    packages=find_packages(exclude=["tests"]),
    description="Detect secrets from all sources using GitGuardian's brains",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/GitGuardian/ggshield",
    author="GitGuardian",
    author_email="support@gitguardian.com",
    maintainer="GitGuardian",
    entry_points={"console_scripts": ["ggshield=ggshield.cmd:cli_wrapper"]},
    install_requires=["click", "pygitguardian==1.2.2", "pyyaml", "python-dotenv"],
    include_package_data=True,
    zip_safe=True,
    license="MIT",
    keywords="cli devsecops secrets-detection security-tools gitguardian",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
