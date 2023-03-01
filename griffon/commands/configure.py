"""

"""
import configparser
import logging
import os

import click

from griffon import GRIFFON_CONFIG_DIR, GRIFFON_DEFAULT_LOG_FILE, GRIFFON_RC_FILE

logger = logging.getLogger("griffon")


@click.group(name="configure")
@click.pass_context
def configure_grp(ctx):
    """Configure griffon."""
    pass


@configure_grp.command(name="setup", help="Create ~/.griffon and .griffonrc config file")
def setup():
    """stub"""
    if not os.path.exists(os.path.expanduser(GRIFFON_CONFIG_DIR)):
        os.makedirs(os.path.expanduser(GRIFFON_CONFIG_DIR))
        logger.warning(f"{GRIFFON_CONFIG_DIR} created")
    else:
        logger.warning(f"{GRIFFON_CONFIG_DIR} already exists")

    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config.add_section("default")
    config["default"]["log_file"] = GRIFFON_DEFAULT_LOG_FILE
    config["default"]["format"] = "text"
    config.add_section("exclude")
    with open(os.path.expanduser(GRIFFON_RC_FILE), "w") as configfile:
        config.write(configfile)
