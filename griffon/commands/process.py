"""

"""
import logging

import click
from requests import HTTPError

from griffon import progress_bar
from griffon.exceptions import catch_exception
from griffon.output import cprint
from griffon.services import ProcessService, core_process

logger = logging.getLogger("griffon")

process_service = ProcessService()


# @click.group(name="process", help="Service operations that perform mutations/write.")
# @click.pass_context
# def process_grp(ctx):
#     """Mutation operations."""
#     pass


@click.command(
    name="generate_affects_for_component", help="(UNDER DEV)Generate affects for component."
)
@click.option("--purl")
@click.option("--cve_id")
@catch_exception(handle=(HTTPError))
@click.pass_context
@progress_bar
def generate_affects_for_component_process(ctx, purl, cve_id):
    """Generate affects for specific component."""
    if not purl and not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    cprint(
        process_service.invoke(
            core_process.generate_affects_for_specific_component_process, ctx.params
        ),
        ctx=ctx,
    )
