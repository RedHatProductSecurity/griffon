"""

"""
import configparser
import logging
import os
import subprocess

import click
from pkg_resources import resource_filename  # type: ignore

from griffon import GRIFFON_CONFIG_DIR, GRIFFON_RC_FILE

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
        if not os.path.exists(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/plugins")):
            os.makedirs(os.path.expanduser(f"{GRIFFON_CONFIG_DIR}/plugins"))
            logger.warning(f"{GRIFFON_CONFIG_DIR}/plugins created")
        else:
            logger.warning(f"{GRIFFON_CONFIG_DIR}/plugins already exists")
    else:
        logger.warning(f"{GRIFFON_CONFIG_DIR} already exists")

    logger.warning(__name__)
    default_griffonrc = resource_filename("griffon", "static/default_griffonrc")
    config = configparser.ConfigParser(allow_no_value=True)
    config.read(default_griffonrc)
    with open(os.path.expanduser(GRIFFON_RC_FILE), "w") as configfile:
        config.write(configfile)
