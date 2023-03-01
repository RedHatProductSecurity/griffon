"""
mangen plugin:


"""
import logging
import os
import subprocess
from configparser import ConfigParser

import click
import requests

from griffon import GRIFFON_CONFIG_DIR
from griffon.output import console

logger = logging.getLogger("griffon")

api_url = "https://vuln.go.dev"


# define autocomplete for service names
@click.group(help="(UNDER DEV) mangen plugin")
@click.pass_context
def plugins(ctx):
    """MANGEN plugin"""
    pass


@plugins.command(help="Run this first")
@click.pass_context
def setup(ctx):
    if not os.path.exists(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos")):
        os.makedirs(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos"))
    subprocess.run(
        ["git", "clone", "https://git.prodsec.redhat.com/prodsec/manifests.git"],
        cwd=os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/repos"),
    )


@plugins.command()
@click.option("--name", "service_name")
@click.pass_context
def get(ctx, service_name):
    """ """
    if not service_name:
        click.echo(ctx.get_help())
        exit(0)

    if service_name:
        config = ConfigParser()
        config.read("/tmp/mangen.ini")

        config_dict = {}
        for section in config.sections():
            config_dict[section] = {}
            for option in config.options(section):
                config_dict[section][option] = config.get(section, option)

        res = requests.get(config_dict[service_name]["url"])
        console.print(res.text)
