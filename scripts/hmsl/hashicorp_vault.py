#!/usr/bin/env python3
"""
Start an Hashicorp Vault server and get the root token associated with it
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import time


CONTAINER_NAME = "hashicorp-vault-ggshield"
ROOT_TOKEN = "my_vault_token"
RESTRICTED_TOKEN = "restricted_token"

READY_TRIES = 20


logger = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.getLevelName(os.environ.get("LOG_LEVEL", "WARN").upper()),
)


def wait_for_server_to_be_ready() -> None:
    """
    Will block (with a timeout) while waiting for the server to be ready.

    If timeout elapsed, a RuntimeError is raised.
    """
    for tries in range(READY_TRIES):
        check_cmd_ret = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                f"name={CONTAINER_NAME}",
                "--format",
                "json",
            ],
            capture_output=True,
        )
        json_status = json.loads(check_cmd_ret.stdout)

        if "(healthy)" in json_status["Status"]:
            logger.debug("Server is healthy")
            return

        logger.debug(
            "Server not healthy yet, waiting... (%d / %d)", tries + 1, READY_TRIES
        )
        time.sleep(0.500)

    raise RuntimeError("Hashicorp Vault server is not ready")


def stop_hashicorp_vault_server():
    """Stop the Hashicorp Vault server instance."""
    stop_cmd_ret = subprocess.run(
        ["docker", "stop", CONTAINER_NAME], capture_output=True
    )
    stop_cmd_ret.check_returncode()


def execute_container_command(cmd: str):
    """
    Execute the given command in the container.
    """
    cmd_ret = subprocess.run(
        ["docker", "exec", CONTAINER_NAME] + cmd.split(" "),
        capture_output=True,
    )
    cmd_ret.check_returncode()


def populate_server():
    """
    Populate the server with a known state.
    """

    # Add a v1 kv at path secret_v1
    execute_container_command("vault secrets enable -version=1 -path=secret_v1 kv")

    # Add same secrets for both paths
    data: dict[str, dict[str, str]] = {
        "b2c/worker/config.env": {
            "WORKER_KEY": "my_secret_key",
            "DB_PASSWORD": "my_password",
        },
        "b2c/web_app/config.env": {
            "SECRET_KEY": "another_secret",
            "DB_PASSWORD": "test_test",
        },
        "b2c/web_app/prod/config.env": {
            "PROD_STUFF": "test",
        },
        "b2b/worker/config.env": {
            "ANOTHER_PASSWORD": "my_secret_key",
            "SECRET": "super_secret",
        },
        "b2b/web_app/config.env": {
            "TESTING": "true",
            "TIMEOUT": "15",
        },
        "b2b/web_app/prod/config.env": {
            "PROD_STUFF": "test",
        },
    }
    for mount in ["secret", "secret_v1"]:
        for secret_path, secrets in data.items():
            execute_container_command(
                f"vault kv put -mount={mount} {secret_path} "
                + " ".join(
                    (
                        f"{secret_name}={secret_value}"
                        for secret_name, secret_value in secrets.items()
                    )
                )
            )

    # Add another token without any rights on the secret and secret_v1 mounts
    execute_container_command(
        f"vault token create -policy=default -id {RESTRICTED_TOKEN}"
    )


def start_hashicorp_vault_server():
    """Start the Hashicorp Vault server"""
    logger.debug("Starting server...")

    docker_run_ret = subprocess.run(
        [
            "docker",
            "run",
            "--cap-add=IPC_LOCK",
            "--rm",
            "-d",
            f"--name={CONTAINER_NAME}",
            "--env",
            f"VAULT_DEV_ROOT_TOKEN_ID={ROOT_TOKEN}",
            "--env",
            "VAULT_ADDR=http://127.0.0.1:8200",
            "-p",
            "8200:8200",
            "--health-cmd=wget -q -O - http://127.0.0.1:8200/v1/sys/health",
            "--health-start-period=1s",
            "--health-interval=2s",
            "hashicorp/vault",
        ],
    )
    if docker_run_ret.returncode == 125:
        logger.error("it seems the server is running already.")
        sys.exit(1)

    docker_run_ret.check_returncode()

    try:
        wait_for_server_to_be_ready()
    except RuntimeError:
        stop_hashicorp_vault_server()
        raise

    execute_container_command(f"vault login {ROOT_TOKEN}")
    populate_server()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dev Hashicorp Vault Server")

    parser.add_argument(
        "command", type=str, help="the command to run", choices=["start", "stop"]
    )
    args = parser.parse_args()

    if args.command == "start":
        start_hashicorp_vault_server()
    elif args.command == "stop":
        stop_hashicorp_vault_server()
    else:
        raise RuntimeError("Unknown command")
