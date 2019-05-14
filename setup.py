from setuptools import setup, find_packages

packages = find_packages()

setup(
    name="secrets_shield",
    description="Detect secrets in commit patches",
    url="https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit.git",
    version="1.0.0",
    author="GitGuardian",
    author_email="dev@gitguardian.com",
    install_requires=["pytest==4.5.0", "aiohttp==3.5.4", "colorama==0.4.1"],
    packages=packages,
    entry_points={
        "console_scripts": ["secrets-shield=secrets_shield.secrets_shield:main"]
    },
)
