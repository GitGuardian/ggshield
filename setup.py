from setuptools import setup, find_packages

setup(
    name='secrets_shield',
    description='Detect secrets in commit patches',
    url='https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit.git',
    version='1.0.0',
    author='gitguardian',
    author_email='contact@gitguardian.com',
    install_requires=['requests==2.21.0'],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'secrets-shield = secrets_shield.secrets_shield:main',
        ],
    },
)
