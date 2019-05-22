from setuptools import setup, find_packages

packages = find_packages()

setup(
    name="secrets_shield",
    description="Detect secrets in commit patches",
    url="https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit.git",
    version="0.1.0",
    author="GitGuardian",
    author_email="dev@gitguardian.com",
    install_requires=[
        "requests==2.22.0",
        "pytest==4.5.0",
        "aiohttp==3.5.4",
        "Click==7.0",
        "snapshottest==0.5.0",
        "vcrpy==2.0.1",
    ],
    packages=packages,
    entry_points={
        "console_scripts": ["secrets-shield=secrets_shield.secrets_shield:cli"]
    },
)
