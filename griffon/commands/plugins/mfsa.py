"""
Mozila advisories plugin:

    https://github.com/mozilla/foundation-security-advisories plugin

Run the following to setup the plugin (installs pyyaml and pulls git repo)
> griffon z_mfsa setup

"""
import logging
import os
import subprocess

import click

from griffon import GRIFFON_CONFIG_DIR

logger = logging.getLogger("griffon")

api_url = "https://api.osv.dev/v1/query"


@click.group(help="(UNDER DEV) MFSA plugin")
@click.pass_context
def plugins(ctx):
    """https://github.com/mozilla/foundation-security-advisories plugin"""
    pass


@plugins.command()
@click.pass_context
def update(ctx):
    subprocess.run(
        [
            "git",
            "log",
            "--graph",
            "--pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset'",  # noqa
            "--abbrev-commit",
        ],
        cwd=os.path.expanduser("~/.griffon/repos/foundation-security-advisories"),
    )


@plugins.command(help="Run this first, installs pyyaml amd pulls repo")
@click.pass_context
def setup(ctx):
    subprocess.run(["pip", "install", "pyyaml"])
    if not os.path.exists(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos")):
        os.makedirs(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos"))
    subprocess.run(
        ["git", "clone", "https://github.com/mozilla/foundation-security-advisories.git"],
        cwd=os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos"),
    )


@plugins.command()
@click.pass_context
def advisories(ctx):
    pass


@plugins.command()
@click.pass_context
def get(ctx):
    pass


@plugins.command()
@click.pass_context
def search(ctx):
    pass
