"""

"""
import configparser
import io
import logging
import os
import subprocess

import click

from griffon import GRIFFON_CONFIG_DIR, GRIFFON_DEFAULT_LOG_FILE, GRIFFON_RC_FILE

logger = logging.getLogger("griffon")


@click.group(name="configure")
@click.pass_context
def configure_grp(ctx):
    """Configure griffon."""
    pass


@configure_grp.command(help="Update griffon to latest release")
@click.pass_context
def update(ctx):
    subprocess.run(["pip", "install", "--force", "griffon"])


@configure_grp.command(name="setup", help="Create ~/.griffon and .griffonrc config file")
def setup():
    """stub"""
    if not os.path.exists(os.path.expanduser(GRIFFON_CONFIG_DIR)):
        os.makedirs(os.path.expanduser(GRIFFON_CONFIG_DIR))
        logger.warning(f"{GRIFFON_CONFIG_DIR} created")
    else:
        logger.warning(f"{GRIFFON_CONFIG_DIR} already exists")

    with open("griffon/static/default_griffonrc", "r") as file:
        data = file.read()
    config = configparser.ConfigParser(allow_no_value=True)
    config.readfp(io.StringIO(data))
    config.set("default", "history_log", GRIFFON_DEFAULT_LOG_FILE)

    with open(os.path.expanduser(GRIFFON_RC_FILE), "w") as configfile:
        config.write(configfile)
