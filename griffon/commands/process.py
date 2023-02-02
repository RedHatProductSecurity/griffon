"""

"""
import logging

import click
from requests import HTTPError

from griffon import progress_bar
from griffon.exceptions import catch_exception
from griffon.output import cprint
from griffon.services import Process, core_process

logger = logging.getLogger("rich")


@click.group(name="process", help="Service operations that perform mutations/write.")
@click.pass_context
def process_grp(ctx):
    """Mutation operations."""
    pass


@process_grp.command(name="generate_affects_for_component", help="Generate affects for component.")
@click.option("--purl")
@click.option("--cve_id")
@catch_exception(handle=(HTTPError))
@click.pass_context
@progress_bar
def generate_affects_for_component_process(ctx, purl, cve_id):
    """List cves of a specific component."""
    if not purl and not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = core_process.generate_affects_for_specific_component_process()
    assert isinstance(q, Process)
    cprint(q.execute({"purl": purl}))
