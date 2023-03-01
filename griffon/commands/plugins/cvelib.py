"""
cvelib plugin:

> griffon plugins cvelib setup

"""
import logging
import subprocess

import click

logger = logging.getLogger("griffon")


@click.group(help="cvelib plugin ")
@click.pass_context
def plugins(ctx):
    """cvelib plugin"""
    pass


try:
    from cvelib.cli import cli

    plugins.add_command(cli)
except Exception:
    pass


@plugins.command(help="Run this first, installs cvelib")
@click.pass_context
def setup(ctx):
    subprocess.run(["pip", "install", "cvelib"])
