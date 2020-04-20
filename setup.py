from setuptools import find_packages, setup


packages = find_packages()

setup(
    name="ggshield",
    description="Detect secrets in commit patches",
    url="https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit.git",
    version="0.1.0",
    author="GitGuardian",
    author_email="dev@gitguardian.com",
    install_requires=["requests==2.22.0", "Click==7.0", "PyYAML==5.1"],
    packages=packages,
    entry_points={"console_scripts": ["ggshield=ggshield.cmd:cli"]},
)
