"""
osidb entity operations

"""
import logging

import click

from .affects import affects
from .flaws import flaws
from .manage import manage_grp
from .trackers import trackers

logger = logging.getLogger("griffon")

default_conditions: dict = {}


@click.group(name="osidb")
@click.pass_context
def osidb_grp(ctx):
    pass


osidb_grp.add_command(flaws)
osidb_grp.add_command(affects)
osidb_grp.add_command(trackers)
osidb_grp.add_command(manage_grp)
