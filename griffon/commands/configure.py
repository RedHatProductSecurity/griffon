"""

"""
import logging

import click

logger = logging.getLogger("rich")


@click.group(name="configure")
@click.pass_context
def configure_grp(ctx):
    """Configure operations."""
    pass


@configure_grp.command(name="stub")
def stub():
    """stub"""
    click.echo("generate ~/.griffonrc configuration file")
