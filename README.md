# Secrets-shield : protect your secrets with GitGuardian pre-commit

## Introduction

**Secrets-shield** is an open-source python package provided by [GitGuardian](https://gitguardian.com/) used as a pre-commit to prevent you from commiting your secrets on public repos.

You can use it via the [pre-commit](https://pre-commit.com/) framework on your repositories, or as a standalone pre-commit either globally or locally.

## The pre-commit framework

In order to use **secrets-shield** with the [pre-commit](https://pre-commit.com/) framework, you need to do the following steps.

Make sure you have pre-commit installed :

```shell
pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your root repository :

```yaml
repos:
  - repo: https://gitlab.gitguardian.ovh/gg-code/prm/pre-commit
    rev: dev
    hooks:
    - id: commit-secrets-shield
      language_version: python3.6
      stages: [commit]
```

Then install the hook with the command :

```shell
> pre-commit install
pre-commit installed at .git/hooks/pre-commit
```

Now you're good to go!

If you want to skip the pre-commit check, you can add `-n` parameter :

```shell
git commit -m "commit message" -n
```

Another way is to add SKIP=hook_id before the command :

```shell
SKIP=commit-secrets-shield git commit -m "commit message"
```

## The global pre-commit hook

First you need to install **secrets-shield** using pip :

```shell
pip install .
```

To install pre-commit globally (for all current and future repo), you just need to execute the installation script :

```shell
sudo source pre-commit-global.sh
```

It will do the following :

* check if a global hook folder is defined in the global git configuration
* create the `~/.git/hooks` folder (if needed)
* create a `pre-commit` file which will be executed before every commit
* give executable access to this file

You can also install the hook locally on desired repositories. You just need to copy the script `pre-commit-local.sh` in the repository and execute :

```shell
sudo source pre-commit-local.sh
```

If you already have a pre-commit executable file and you want to use **secrets-shield**, all you need to do is to add this line in the file :

```shell
secrets-shield
```

## Output

If no secret has been found, you will have a simple message :

```bash
> secrets-shield
No secret has been found
```

If a secret lies in your staged code, you will have an alert giving you the type of secret, the filename where the secret has been found and a patch giving you the secret position in file :

```shell
> secrets-shield

💥 💔 💥 A secret of type AWS Keys has been found in file production.rb
+      :s3_credentials => {
+        :bucket => "XXX",
+        :access_key_id => "XXX",
+        :secret_access_key => "XXX"
+      }
+    }
```

## Contributing

If you have questions you would like to ask the developers, or feedback you would like to provide, feel free to use the mailing list : dev@gitguardian.com

We would love to hear from you. Additionally, if you have a feature you would like to suggest, the mailing list would be the best place for it.

## License

Secrets-shield is MIT licensed.
