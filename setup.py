import os
import re
from typing import Any

from setuptools import find_packages, setup


VERSION_RE = re.compile(r"__version__\s*=\s*\"(.*?)\"")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args: Any) -> str:
    """Reads complete file contents."""
    return str(open(os.path.join(HERE, *args), encoding="utf-8").read())


def get_version() -> str:
    """Reads the version from this module."""
    init = read("ggshield", "__init__.py")
    return VERSION_RE.search(init).group(1)  # type: ignore


setup(
    name="ggshield",
    version=get_version(),
    packages=find_packages(exclude=["tests", "tests.*"]),
    description="Detect secrets from all sources using GitGuardian's brains",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/GitGuardian/ggshield",
    author="GitGuardian",
    author_email="support@gitguardian.com",
    maintainer="GitGuardian",
    entry_points={"console_scripts": ["ggshield=ggshield.cmd.main:main"]},
    install_requires=[
        "appdirs>=1.4.4,<1.5.0",
        "charset-normalizer>=3.1.0,<3.2.0",
        "click>=8.1,<8.2",
        "cryptography>=41.0.3,<42.0.0",
        "marshmallow>=3.18.0,<3.19.0",
        "marshmallow-dataclass>=8.5.8,<8.6.0",
        "oauthlib>=3.2.1,<3.3.0",
        "pygitguardian>=1.9.0,<1.10.0",
        "pyjwt>=2.6.0,<2.7.0",
        "python-dotenv>=0.21.0,<0.22.0",
        "pyyaml>=6.0.1,<6.1",
        "requests>=2.31.0,<2.32.0",
        "rich>=12.5.1,<12.6.0",
    ],
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
